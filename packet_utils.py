import zlib
import struct
import io

class PacketBuffer:
    def __init__(self, data=b""):
        self.io = io.BytesIO(data)

    def read_varint(self):
        result = 0
        shift = 0
        while True:
            byte = self.io.read(1)
            if len(byte) == 0:
                raise Exception("Buffer underflow")
            b = byte[0]
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        
        # Handle sign if needed (though often VarInts are treated as unsigned in packet headers)
        if result & (1 << 31):
            result -= 1 << 32
        return result

    def read_bytes(self, length):
        return self.io.read(length)
    
    def read_string(self):
        length = self.read_varint()
        return self.io.read(length).decode('utf-8')
    
    def read_unsigned_short(self):
        return struct.unpack('>H', self.io.read(2))[0]

    def get_remaining(self):
        return self.io.read()

    def read_packet_id(self):
        return self.read_varint()

    # --- Primitives ---
    def read_short(self):
        return struct.unpack('>h', self.io.read(2))[0]

    def read_unsigned_short(self):
        return struct.unpack('>H', self.io.read(2))[0]

    def read_int(self):
        return struct.unpack('>i', self.io.read(4))[0]

    def read_long(self):
        return struct.unpack('>q', self.io.read(8))[0]

    def read_float(self):
        return struct.unpack('>f', self.io.read(4))[0]

    def read_double(self):
        return struct.unpack('>d', self.io.read(8))[0]

    def read_unsigned_byte(self):
        return self.io.read(1)[0]
    
    def read_byte(self): 
        return struct.unpack('>b', self.io.read(1))[0]

def write_varint(val):
    out = b''
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        out += bytes([byte])
        if val == 0:
            break
    return out

def write_string(val):
    data = val.encode('utf-8')
    return write_varint(len(data)) + data

def write_short(val):
    return struct.pack('>h', val)

def write_unsigned_short(val):
    return struct.pack('>H', val)

def write_int(val):
    return struct.pack('>i', val)

def write_long(val):
    return struct.pack('>q', val)

def write_float(val):
    return struct.pack('>f', val)

def write_double(val):
    return struct.pack('>d', val)

def write_packet(packet_id, data, compression_context=None):
    """
    Wraps payload in standard Minecraft format.
    compression_context: Can be an object with .compression_threshold OR a raw int value (for backward compat).
    """
    threshold = None
    if compression_context is not None:
        if hasattr(compression_context, 'compression_threshold'):
            threshold = compression_context.compression_threshold
        elif isinstance(compression_context, int):
            threshold = compression_context
            
    if threshold is not None and threshold >= 0:
        # Compressed Format
        # 1. Construct raw packet [ID][Data]
        raw_packet = write_varint(packet_id) + data
        raw_len = len(raw_packet)
        
        if raw_len < threshold:
            # Send uncompressed: DataLength = 0
            data_len_varint = write_varint(0)
            body = data_len_varint + raw_packet
        else:
            # Send compressed
            data_len_varint = write_varint(raw_len)
            compressed_data = zlib.compress(raw_packet)
            body = data_len_varint + compressed_data
            
        packet_len = write_varint(len(body))
        return packet_len + body
    else:
        # Uncompressed Format
        id_bytes = write_varint(packet_id)
        length = len(id_bytes) + len(data)
        return write_varint(length) + id_bytes + data

def read_next_packet(socket_obj, compression_context=None):
    """
    Reads the next full packet.
    compression_context: Object with .compression_threshold OR int value.
    This allows checking the threshold AFTER blocking read matches.
    """
    # 1. Read Packet Length (VarInt)
    length = 0
    shift = 0
    byte_count = 0
    while True:
        b = socket_obj.recv(1)
        if not b:
            return None, None # Connection closed
        b = b[0]
        length |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        byte_count += 1
        if byte_count > 5:
             raise Exception("VarInt too big")

    # 2. Read Packet Body
    data = b''
    while len(data) < length:
        chunk = socket_obj.recv(length - len(data))
        if not chunk:
            raise Exception("Connection closed during packet body")
        data += chunk
    
    # 3. Parse Body
    buf = PacketBuffer(data)
    
    # Resolve Threshold
    threshold = None
    if compression_context is not None:
        if hasattr(compression_context, 'compression_threshold'):
            threshold = compression_context.compression_threshold
        elif isinstance(compression_context, int):
            threshold = compression_context

    if threshold is not None and threshold >= 0:
        # Compressed Format: [DataLength] [CompressedData]
        data_length = buf.read_varint()
        
        if data_length == 0:
            # Uncompressed: [PacketID] [Data]
            pass 
        else:
            # Compressed: [ZlibBlob]
            compressed_data = buf.get_remaining()
            uncompressed = zlib.decompress(compressed_data)
            buf = PacketBuffer(uncompressed)
            
    # Standard ID parsing
    packet_id = buf.read_varint()
    payload = buf.get_remaining()
    
    return packet_id, payload

