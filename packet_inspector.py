import time
import datetime
from packet_definitions import PACKET_NAMES

class PacketInspector:
    def __init__(self):
        self.enabled = False
        self.ignored_packets = [
            0x20, # Chunk Data (S->C)
            0x0B, # Keep Alive (C->S)
            0x1F, # Keep Alive (S->C)
            0x0C, # Player Position (C->S)
            0x0D, # Player Pos + Look (C->S)
            0x0E, # Player Look (C->S)
            0x25, # Entity Relative Move (S->C)
            0x26, # Entity Look + Rel Move (S->C)
            0x27, # Entity Look (S->C)
            0x28, # Entity (S->C)
        ]
    
    def enable(self):
        self.enabled = True
        print("[Inspector] Packet Inspector ENABLED. Filtering common spam (ChunkData, KeepAlive, Movement).")

    def inspect(self, direction, state, packet_id, payload):
        if not self.enabled: return

        # 1. Resolve State strings
        # State 0=Handshake, 1=Status, 2=Login, 3=Play
        state_str = "UNKNOWN"
        if state == 0: state_str = "HANDSHAKE"
        elif state == 1: state_str = "STATUS"
        elif state == 2: state_str = "LOGIN"
        elif state == 3: state_str = "PLAY"
        
        # 2. Check Ignore List (Only for PLAY state usually)
        if state == 3 and packet_id in self.ignored_packets:
            return 

        # 3. Resolve Packet Name
        pkt_name = f"Unknown(0x{packet_id:02x})"
        
        try:
            if state_str in PACKET_NAMES:
                if direction in PACKET_NAMES[state_str]:
                    mapping = PACKET_NAMES[state_str][direction]
                    if packet_id in mapping:
                        pkt_name = mapping[packet_id]
        except:
            pass

        # 4. Parse fields (Deep Inspection)
        parsed_data = None
        parsed_desc = ""
        try:
            import packet_parser
            parsed_data = packet_parser.parse_packet(direction, state, packet_id, payload)
            if parsed_data and 'description' in parsed_data:
                parsed_desc = parsed_data['description']
        except Exception as e:
            # print(f"Parser error: {e}")
            pass

        # 5. Format Output & Push
        # [Time] [Dir] [State] PacketName | Len=... | Preview=...
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Helper to push to Web Server
        try:
             import inspector_server
             inspector_server.add_packet(time.time(), direction, state_str, packet_id, pkt_name, len(payload), payload, parsed_desc, parsed_data)
        except:
             pass
