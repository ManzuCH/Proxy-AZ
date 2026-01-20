import socket
import threading
import sys
import struct
import packet_utils
import encryption_utils
import auth_utils
import zlib
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

# Packet IDs
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
        
        self.inspector = PacketInspector()
        if ENABLE_INSPECTOR:
            self.inspector.enable()

        # Encryption
        self.server_cipher = None 
        
        # Threads
        self.t1 = threading.Thread(target=self.client_to_server)
        self.t2 = threading.Thread(target=self.server_to_client)
        self.t1.start()
        self.t2.start()

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
                    print(f"[C->S] Handshake: Ver={proto_ver}, Addr={addr}, State={next_state}")

                elif self.client_state == 2:
                    if pid == PACKET_LOGIN_START:
                        buf = packet_utils.PacketBuffer(data)
                        username = buf.read_string()
                        print(f"[C->S] Login Start (Real Client wants to be): {username}")
                        
                        if MC_PROFILE_NAME:
                            print(f"[Proxy] Overriding Username with Authenticated: {MC_PROFILE_NAME}")
                            data = packet_utils.write_string(MC_PROFILE_NAME)
                # VERBOSE LOG C->S
                if self.client_state == 3:
                     # print(f"[C->S] Packet ID=0x{pid:02x} Len={len(data)} Payload={data.hex()}")
                     pass
                
                # INSPECTOR
                self.inspector.inspect("C->S", self.client_state, pid, data)

                raw_packet = packet_utils.write_packet(pid, data, self)
                
                if self.server_cipher:
                    encrypted = self.server_cipher.encrypt(raw_packet)
                    self.server_sock.sendall(encrypted)
                else:
                    self.server_sock.sendall(raw_packet)

        except Exception as e:
            if isinstance(e, OSError) and e.errno == 9:
                pass
            else:
                print(f"[C->S Error] {e}")
                # import traceback
                # traceback.print_exc()
        finally:
            self.close()

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
                        import zlib
                        buf = packet_utils.PacketBuffer(body)
                        data_len = buf.read_varint()
                        if data_len == 0:
                            # Uncompressed body
                            pass 
                        else:
                            compressed = buf.get_remaining()
                            uncompressed = zlib.decompress(compressed)
                            buf = packet_utils.PacketBuffer(uncompressed)
                        
                        pid = buf.read_varint()
                        payload = buf.get_remaining()
                    else:
                        buf = packet_utils.PacketBuffer(body)
                        pid = buf.read_varint()
                        payload = buf.get_remaining()
                    
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

                    # VERBOSE LOG
                    # print(f"[S->C] Packet ID=0x{pid:02x} Len={len(payload)}")
                    
                    self.client_sock.sendall(packet_utils.write_packet(pid, payload, self))
                    
                    # INSPECTOR
                    self.inspector.inspect("S->C", self.client_state, pid, payload)

        except Exception as e:
            if isinstance(e, OSError) and e.errno == 9:
                # Socket closed (Bad file descriptor) - expected on shutdown
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
            
            # Use specific UUID format handling? (Usually straightforward)
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
        
        self.server_sock.sendall(packet_utils.write_packet(PACKET_ENCRYPTION_RESPONSE, resp_data))
        print("[P->S] Sent Encryption Response")
        
        # 4. Enable Encryption locally
        self.server_cipher = encryption_utils.AESCipher(shared_secret)
        print("[*] Encryption enabled with Real Server")

    def read_varint_encrypted(self):
        value = 0
        shift = 0
        while True:
            byte = self.server_sock.recv(1)
            if not byte: return None
            byte = self.server_cipher.decrypt(byte)
            val = byte[0]
            value |= (val & 0x7F) << shift
            if (val & 0x80) == 0:
                break
            shift += 7
        return value

    def read_bytes_encrypted(self, n):
        data = b''
        while len(data) < n:
            chunk = self.server_sock.recv(n - len(data))
            if not chunk: break
            data += self.server_cipher.decrypt(chunk)
        return data

def start_proxy():
    global MC_ACCESS_TOKEN, MC_PROFILE_NAME, MC_PROFILE_ID
    
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
        global ENABLE_INSPECTOR
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
        
    # Safety check
    if (TARGET_HOST in ['127.0.0.1', 'localhost', '0.0.0.0'] and TARGET_PORT == LOCAL_PORT):
        print(f"[!] ERROR: Target {TARGET_HOST}:{TARGET_PORT} is the same as Listen Port {LOCAL_PORT}!")
        sys.exit(1)

    start_proxy()
