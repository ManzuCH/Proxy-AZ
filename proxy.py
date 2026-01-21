import socket
import threading
import sys
import struct
import time
import random 
import zlib

import packet_utils
import encryption_utils
import auth_utils
from packet_inspector import PacketInspector

# Configuration
LOCAL_HOST = '0.0.0.0'
LOCAL_PORT = 25565
TARGET_HOST = '127.0.0.1' 
TARGET_PORT = 25566 

# Global Auth State
MC_ACCESS_TOKEN = None
MC_PROFILE_NAME = None
MC_PROFILE_ID = None
ENABLE_INSPECTOR = False

# Packet IDs (Protocol 110 / 1.9.4)
PACKET_HANDSHAKE = 0x00
PACKET_LOGIN_START = 0x00
PACKET_ENCRYPTION_REQUEST = 0x01
PACKET_ENCRYPTION_RESPONSE = 0x01
PACKET_LOGIN_SUCCESS = 0x02
PACKET_SET_COMPRESSION = 0x03

class ProxyConnection:
    def __init__(self, client_sock, target_host, target_port):
        self.client_sock = client_sock
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.connect((target_host, target_port))
        
        self.running = True
        self.client_state = 0 # 0=Handshake, 1=Status, 2=Login, 3=Play
        self.compression_threshold = None
        
        # Cheats
        self.player_eid = None
        self.delayed_packets = [] # List of (send_time, packet_data)
        self.last_packet_time = 0 
        
        self.send_lock = threading.Lock() # Protects server_sock writes

        self.inspector = PacketInspector()
        if ENABLE_INSPECTOR:
            self.inspector.enable()

        # Encryption
        self.server_cipher = None 
        
        # Threads
        self.t1 = threading.Thread(target=self.client_to_server)
        self.t2 = threading.Thread(target=self.server_to_client)
        self.t3 = threading.Thread(target=self.process_delay_queue)
        self.t1.start()
        self.t2.start()
        self.t3.start()

    def process_delay_queue(self):
        """ Checks for delayed packets (Cheat) """
        while self.running:
            now = time.time()
            remaining = []
            for send_time, data in self.delayed_packets:
                if now >= send_time:
                    try:
                        with self.send_lock:
                            if self.server_cipher:
                                encrypted = self.server_cipher.encrypt(data)
                                self.server_sock.sendall(encrypted)
                            else:
                                self.server_sock.sendall(data)
                    except: pass
                else:
                    remaining.append((send_time, data))
            self.delayed_packets = remaining
            time.sleep(0.01)

    def close(self):
        self.running = False
        try: self.client_sock.close() 
        except: pass
        try: self.server_sock.close() 
        except: pass

    def client_to_server(self):
        try:
            while self.running:
                # Pass 'self' so read_next_packet checks self.compression_threshold AFTER recv returns
                pid, data = packet_utils.read_next_packet(self.client_sock, self)
                if pid is None:
                    break 

                if self.client_state == 0:
                    buf = packet_utils.PacketBuffer(data)
                    proto_ver = buf.read_varint()
                    addr = buf.read_string()
                    port = buf.read_unsigned_short()
                    next_state = buf.read_varint()
                    self.client_state = next_state
                    print(f"[C->S] Handshake: Ver={proto_ver}, Addr={addr} -> {TARGET_HOST}, State={next_state}")
                    
                    # REWRITE HANDSHAKE with TARGET_HOST
                    new_handshake = b''
                    new_handshake += packet_utils.write_varint(proto_ver)
                    new_handshake += packet_utils.write_string(TARGET_HOST)
                    new_handshake += packet_utils.write_unsigned_short(TARGET_PORT)
                    new_handshake += packet_utils.write_varint(next_state)
                    data = new_handshake
                
                elif self.client_state == 2:
                    if pid == PACKET_LOGIN_START:
                        buf = packet_utils.PacketBuffer(data)
                        username = buf.read_string()
                        print(f"[C->S] Login Start (Real Client wants to be): {username}")
                        
                        if MC_PROFILE_NAME:
                            print(f"[Proxy] Overriding Username with Authenticated: {MC_PROFILE_NAME}")
                            data = packet_utils.write_string(MC_PROFILE_NAME)

                # --- CHEAT: DELAY TRANSACTIONS (e.g. 0x0F) ---
                # Check Cheat Config
                try:
                    import inspector_server
                    fake_lag = inspector_server.CHEAT_CONFIG.get("fake_lag", False)
                except: fake_lag = False

                if self.client_state == 3 and pid == 0x0F and fake_lag:
                    # Delay logic...
                    delay = random.uniform(0.2, 0.4) 
                    send_time = time.time() + delay
                    
                    full_packet = packet_utils.write_packet(pid, data, self)
                    
                    # Ensure monotonic time
                    if send_time < self.last_packet_time:
                        send_time = self.last_packet_time + 0.05
                    self.last_packet_time = send_time
                    
                    self.delayed_packets.append((send_time, full_packet))
                    print(f"[Cheat] Delayed Transaction 0x0F by {delay:.2f}s")
                    continue # Skip immediate send

                # Forward immediately
                try:
                    full_packet = packet_utils.write_packet(pid, data, self)
                    with self.send_lock:
                        if self.server_cipher:
                            encrypted = self.server_cipher.encrypt(full_packet)
                            self.server_sock.sendall(encrypted)
                        else:
                            self.server_sock.sendall(full_packet)
                except Exception as e:
                    print(f"[Proxy] Send Error: {e}")
                    break
        
        except Exception as e:
            pass
        finally:
            self.close()





                
                # INSPECTOR




    def server_to_client(self):
        try:
            while self.running:
                if not self.server_cipher:
                    # Unencrypted Read
                    pid, data = packet_utils.read_next_packet(self.server_sock, self)
                    if pid is None: break

                    if self.client_state == 2: # Login Phase
                        if pid == PACKET_ENCRYPTION_REQUEST:
                            print("[S->C] Intercepted Encryption Request!")
                            self.handle_encryption_request(data)
                            continue 
                        
                        elif pid == PACKET_SET_COMPRESSION:
                             buf = packet_utils.PacketBuffer(data)
                             threshold = buf.read_varint()
                             print(f"[S->C] Set Compression (Unencrypted): {threshold}")
                             self.client_sock.sendall(packet_utils.write_packet(pid, data, self))
                             self.compression_threshold = threshold
                             continue
                        
                        elif pid == PACKET_LOGIN_SUCCESS:
                             print(f"[S->C] Login Success! Switching to PLAY state.")
                             self.client_state = 3
                    
                    # INSPECTOR
                    self.inspector.inspect("S->C", self.client_state, pid, data)

                    self.client_sock.sendall(packet_utils.write_packet(pid, data, self))

                else:
                    # Encrypted Read
                    length = self.read_varint_encrypted()
                    if length is None: 
                        print("[Proxy] Server disconnected cleanly (EOF).")
                        break
                    
                    body = self.read_bytes_encrypted(length)
                    if len(body) < length: 
                        print(f"[Proxy] Server disconnected during body (Expected {length}, got {len(body)}).")
                        break

                    # Decompression Logic
                    if self.compression_threshold is not None and self.compression_threshold >= 0:
                        # print(f"DEBUG: Body Hex: {body.hex()}")
                        buf = packet_utils.PacketBuffer(body)
                        data_len = buf.read_varint()
                        
                        if data_len == 0:
                            # Uncompressed body: Remaining is [ID] [Payload]
                            pass
                        else:
                            compressed = buf.get_remaining()
                            try:
                                uncompressed = zlib.decompress(compressed)
                            except Exception as e:
                                print(f"[Proxy] Decompression Error: {e} | Body: {body.hex()}")
                                raise e
                            buf = packet_utils.PacketBuffer(uncompressed)
                        
                        try:
                            pid = buf.read_varint()
                        except Exception as e:
                             print(f"[Proxy] ID Read Error: {e} | Body: {body.hex()} | DataLen: {data_len}")
                             raise e
                             
                        payload = buf.get_remaining()
                    else:
                        buf = packet_utils.PacketBuffer(body)
                        pid = buf.read_varint()
                        payload = buf.get_remaining()
                    
                    # State Checks
                    if self.client_state == 2:
                        if pid == PACKET_LOGIN_SUCCESS:
                             print(f"[S->C] Login Success (Encrypted)! Switching to PLAY state.")
                             self.client_state = 3
                        elif pid == PACKET_SET_COMPRESSION:
                             p_buf = packet_utils.PacketBuffer(payload)
                             threshold = p_buf.read_varint()
                             print(f"[S->C] Set Compression (Encrypted): {threshold}")
                             self.client_sock.sendall(packet_utils.write_packet(pid, payload, self))
                             self.compression_threshold = threshold
                             continue

                    # --- CHEAT LOGIC START ---
                    
                    if self.client_state == 3:
                        if pid == 0x23: # Join Game
                            try: 
                                buf = packet_utils.PacketBuffer(payload)
                                eid = buf.read_int()
                                self.player_eid = eid
                                print(f"[Cheat] Captured Player EID: {eid}")
                            except: pass

                        elif pid == 0x3B: # Entity Velocity
                            # Check EID
                            try:
                                import inspector_server
                                anti_kb = inspector_server.CHEAT_CONFIG.get("anti_kb", True)
                                kb_h = inspector_server.CHEAT_CONFIG.get("kb_h", 0)   # Horizontal
                                kb_v = inspector_server.CHEAT_CONFIG.get("kb_v", 100) # Vertical
                                smart_mode = inspector_server.CHEAT_CONFIG.get("smart_mode", True)
                                
                                buf = packet_utils.PacketBuffer(payload)
                                eid = buf.read_varint()
                                
                                if eid == self.player_eid and anti_kb:
                                    # Read Original
                                    vel_x = buf.read_short()
                                    vel_y = buf.read_short()
                                    vel_z = buf.read_short()
                                    
                                    # Calculate Target Vel
                                    t_x = int(vel_x * (kb_h / 100.0))
                                    t_y = int(vel_y * (kb_v / 100.0))
                                    t_z = int(vel_z * (kb_h / 100.0))
                                    
                                    # Logic for "Safe" Anti-Cheat Bypass
                                    if smart_mode:
                                        # 1. Jitter Horizontal if Near Zero
                                        # If request is 0% but original was large, result is 0.
                                        # AC checks for Friction/Momentum. Absolute 0 is weird if hit hard.
                                        # Use +/- random jitter to simulate friction.
                                        if t_x == 0 and vel_x != 0: t_x = random.randint(-15, 15) # Increased jitter range
                                        if t_z == 0 and vel_z != 0: t_z = random.randint(-15, 15)
                                        
                                        # 2. Safety Clamp for Vertical
                                        # If user sets Vertical to < 50%, it looks suspicious (no jump).
                                        # Warn or Clamp? For now, we trust the slider, but maybe add minimum jitter?
                                        # If t_y is 0 (no vertical KB), ensure it's not a "grounded bit" spoof fail.
                                        if t_y == 0 and vel_y > 400: # 400 ~ small jump
                                             # t_y = random.randint(100, 200) # Mini hop
                                             pass
                                    
                                    # Reconstruct
                                    new_payload = b''
                                    new_payload += packet_utils.write_varint(eid)
                                    new_payload += packet_utils.write_short(t_x)
                                    new_payload += packet_utils.write_short(t_y)
                                    new_payload += packet_utils.write_short(t_z)
                                    
                                    payload = new_payload
                                    print(f"[Cheat] KB Modified: H={kb_h}% V={kb_v}% | {vel_x},{vel_y},{vel_z} -> {t_x},{t_y},{t_z}")
                                
                                else:
                                    # Debug: Show velocity packets for other entities to debug EID issues
                                    # buf.read_short() ... just purely for logging
                                    # print(f"[Debug] Velocity for EID {eid} (MyPID: {self.player_eid})")
                                    pass

                            except Exception as e:
                                print(f"[Cheat Error] KB Logic Failed: {e}")

                        elif pid == 0x1C: # Explosion
                            try:
                                import inspector_server
                                anti_kb = inspector_server.CHEAT_CONFIG.get("anti_kb", True)
                                kb_h = inspector_server.CHEAT_CONFIG.get("kb_h", 0)
                                if anti_kb:
                                    buf = packet_utils.PacketBuffer(payload)
                                    x = buf.read_float()
                                    y = buf.read_float()
                                    z = buf.read_float()
                                    strength = buf.read_float()
                                    count = buf.read_varint() # Protocol 1.9+ uses VarInt for record count!
                                    # Skip records (count * 3 bytes)
                                    records = buf.read_bytes(count * 3)
                                    
                                    # Player Motion
                                    p_x = buf.read_float()
                                    p_y = buf.read_float()
                                    p_z = buf.read_float()
                                    
                                    # Apply KB Reduction
                                    t_x = p_x * (kb_h / 100.0)
                                    t_y = p_y * (kb_h / 100.0) # Explosions affect Y heavily
                                    t_z = p_z * (kb_h / 100.0)
                                    
                                    # Reconstruct
                                    new_payload = b''
                                    new_payload += packet_utils.write_float(x)
                                    new_payload += packet_utils.write_float(y)
                                    new_payload += packet_utils.write_float(z)
                                    new_payload += packet_utils.write_float(strength)
                                    new_payload += packet_utils.write_varint(count) # Write back as VarInt
                                    new_payload += records
                                    new_payload += packet_utils.write_float(t_x)
                                    new_payload += packet_utils.write_float(t_y)
                                    new_payload += packet_utils.write_float(t_z)
                                    
                                    payload = new_payload
                                    print(f"[Cheat] Explosion KB Modified: {p_x:.2f},{p_y:.2f},{p_z:.2f} -> {t_x:.2f},{t_y:.2f},{t_z:.2f}")
                            except Exception as e:
                                print(f"[Cheat Error] Explosion Logic Failed: {e}")

                    # --- CHEAT LOGIC END ---

                    # INSPECTOR
                    self.inspector.inspect("S->C", self.client_state, pid, payload)
                    
                    self.client_sock.sendall(packet_utils.write_packet(pid, payload, self))

        except Exception as e:
            if isinstance(e, OSError) and e.errno == 9:
                pass
            else:
                print(f"[S->C Error] {e}")
                import traceback
                traceback.print_exc()
        finally:
            self.close()

    def handle_encryption_request(self, data):
        buf = packet_utils.PacketBuffer(data)
        server_id = buf.read_string()
        pubkey_len = buf.read_varint()
        pubkey = buf.read_bytes(pubkey_len)
        token_len = buf.read_varint()
        token = buf.read_bytes(token_len)
        
        print(f"ServerID: {server_id} | PubKey Len: {len(pubkey)} | VerifyToken Len: {len(token)}")
        
        # 1. Generate Shared Secret
        shared_secret = encryption_utils.generate_shared_secret()
        
        # 2. Online Mode Authentication
        if MC_ACCESS_TOKEN and MC_PROFILE_ID:
            print("[Proxy] Performing Online Auth with Mojang...")
            server_hash = encryption_utils.make_digest(server_id, shared_secret, pubkey)
            hash_str = encryption_utils.java_hex_digest(server_hash)
            
            success = auth_utils.join_server(MC_ACCESS_TOKEN, MC_PROFILE_ID, hash_str, shared_secret, pubkey)
            if not success:
               print("[!] Auth Failed! Server might reject connection.")
        else:
            print("[Proxy] Skipping Auth (Offline Mode)")

        # 3. Send Encryption Response to Server
        enc_secret = encryption_utils.encrypt_secret(pubkey, shared_secret)
        enc_token = encryption_utils.encrypt_secret(pubkey, token)
        
        resp_data = b''
        resp_data += packet_utils.write_varint(len(enc_secret))
        resp_data += enc_secret
        resp_data += packet_utils.write_varint(len(enc_token))
        resp_data += enc_token
        
        with self.send_lock:
            self.server_sock.sendall(packet_utils.write_packet(PACKET_ENCRYPTION_RESPONSE, resp_data))
        print("[P->S] Sent Encryption Response")
        
        # 4. Enable Encryption locally
        self.server_cipher = encryption_utils.AESCipher(shared_secret)
        print("[*] Encryption enabled with Real Server")

    def read_varint_encrypted(self):
        value = 0
        shift = 0
        while True:
            # print("DEBUG: Reading encrypted byte...")
            byte = self.server_sock.recv(1)
            if not byte: 
                print("DEBUG: Connection closed while reading varint.")
                return None
            try:
                byte = self.server_cipher.decrypt(byte)
            except Exception as e:
                print(f"DEBUG: Decryption error: {e}")
                return None
                
            val = byte[0]
            value |= (val & 0x7F) << shift
            if (val & 0x80) == 0:
                break
            shift += 7
        # print(f"DEBUG: Read VarInt Encrypted: {value}")
        return value

    def read_bytes_encrypted(self, n):
        data = b''
        while len(data) < n:
            chunk = self.server_sock.recv(n - len(data))
            if not chunk: 
                print("DEBUG: Connection closed while reading bytes.")
                break
            data += self.server_cipher.decrypt(chunk)
        return data

def start_proxy():
    global MC_ACCESS_TOKEN, MC_PROFILE_NAME, MC_PROFILE_ID, ENABLE_INSPECTOR
    
    # Check for Auth request
    print("[*] Starting Minecraft Proxy...")
    print("[*] Authentication Mode:")
    print("    1. Automatic (Microsoft Device Code Flow)")
    print("    2. Manual (Paste Access Token)")
    print("    3. Offline (Skipping Auth)")
    choice = input("Choice (1/2/3) [Default: 1]: ").strip()
    
    try:
        if choice == '2':
            token = input("Paste your Minecraft Access Token: ").strip()
            if token:
                MC_ACCESS_TOKEN, MC_PROFILE_NAME, MC_PROFILE_ID = auth_utils.get_profile(token)
        elif choice == '3':
            print("[*] Skipping Authentication (Offline Mode)")
        else:
            MC_ACCESS_TOKEN, MC_PROFILE_NAME, MC_PROFILE_ID = auth_utils.device_flow_login()
    except Exception as e:
        print(f"[!] Login Failed/Skipped: {e}")
        # Proceed as Offline?
        
    # Inspector Prompt
    insp = input("Enable Packet Inspector (Wireshark-like view)? (y/n) [n]: ").strip().lower()
    if insp == 'y':
        ENABLE_INSPECTOR = True
        
        # Start Web Server
        import inspector_server
        server_thread = inspector_server.InspectorServer()
        server_thread.start()
        print(f"[*] Access the Inspector Dashboard at: http://localhost:8080")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LOCAL_HOST, LOCAL_PORT))
    server.listen(5)
    print(f"[*] Proxy acting as Client on {LOCAL_HOST}:{LOCAL_PORT}")
    print(f"[*] Forwarding to {TARGET_HOST}:{TARGET_PORT}")
    
    while True:
        client, addr = server.accept()
        print(f"[*] New connection from {addr}")
        ProxyConnection(client, TARGET_HOST, TARGET_PORT)

if __name__ == '__main__':
    # Usage: python proxy.py [TARGET_HOST] [TARGET_PORT] [LOCAL_PORT]
    if len(sys.argv) > 1:
        TARGET_HOST = sys.argv[1]
    if len(sys.argv) > 2:
        TARGET_PORT = int(sys.argv[2])
    if len(sys.argv) > 3:
        LOCAL_PORT = int(sys.argv[3])
    
    start_proxy()
