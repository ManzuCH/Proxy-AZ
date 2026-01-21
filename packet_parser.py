import struct
import json
from packet_utils import PacketBuffer

def parse_packet(direction, state, packet_id, payload):
    """
    Parses a packet payload based on ID and State.
    Returns a dict of parsed fields or None if no parser parses this packet.
    """
    if state != 3: return None # Only parse PLAY state for now
    
    buf = PacketBuffer(payload)
    parsed = {}
    
    try:
        if direction == "S->C":
            # --- Entity Velocity (0x3B) ---
            if packet_id == 0x3B:
                parsed['entity_id'] = buf.read_varint()
                parsed['vel_x'] = buf.read_short()
                parsed['vel_y'] = buf.read_short()
                parsed['vel_z'] = buf.read_short()
                # Minecraft Velocity is Steps per 8000 ticks?
                # Actually it is (val / 8000.0) * 20 blocks/sec usually.
                # Raw value is enough.
                parsed['description'] = f"EID={parsed['entity_id']} V=({parsed['vel_x']}, {parsed['vel_y']}, {parsed['vel_z']})"

            # --- Chat Message (0x0F) ---
            elif packet_id == 0x0F:
                json_str = buf.read_string()
                parsed['json'] = json_str
                try:
                    obj = json.loads(json_str)
                    # Extract plain text if possible
                    text = ""
                    if 'text' in obj: text = obj['text']
                    if 'extra' in obj:
                        for extra in obj['extra']:
                            if 'text' in extra: text += extra['text']
                    parsed['text'] = text
                    parsed['description'] = f"Chat: {text[:50]}"
                except:
                    parsed['description'] = "Chat (Complex JSON)"

            # --- Join Game (0x23) ---
            elif packet_id == 0x23:
                parsed['entity_id'] = buf.read_int()
                parsed['gamemode'] = buf.read_unsigned_byte()
                parsed['dimension'] = buf.read_int()
                parsed['difficulty'] = buf.read_unsigned_byte()
                parsed['max_players'] = buf.read_unsigned_byte()
                parsed['level_type'] = buf.read_string()
                parsed['description'] = f"Join: EID={parsed['entity_id']} Mode={parsed['gamemode']} Type={parsed['level_type']}"
                
            # --- Update Health (0x3E) ---
            elif packet_id == 0x3E:
                parsed['health'] = buf.read_float()
                parsed['food'] = buf.read_varint()
                parsed['saturation'] = buf.read_float()
                parsed['description'] = f"Health={parsed['health']:.1f} Food={parsed['food']}"

    except Exception as e:
        parsed['error'] = str(e)
        
    if not parsed: return None
    return parsed
