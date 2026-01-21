import http.server
import socketserver
import json
import threading
import os
import urllib.parse
from packet_inspector import PacketInspector

# Global Packet History shared with Proxy
PACKET_HISTORY = []
MAX_HISTORY = 5000

# Cheat Configuration (Shared State)
CHEAT_CONFIG = {
    "fake_lag": False,  # Default OFF
    "anti_kb": True,    # Default ON
    "kb_h": 0,          # Horizontal % (X/Z)
    "kb_v": 100,        # Vertical % (Y) - Default 100 for Legit pop
    "smart_mode": True  # Micro-Jitter on near-zero values
}

class InspectorHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open("inspector_ui.html", "rb") as f:
                self.wfile.write(f.read())
        
        # ... (packets) ...

        elif path == "/api/status":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(CHEAT_CONFIG).encode('utf-8'))
            
        elif path == "/api/toggle":
            # ?cheat=fake_lag&state=true OR ?cheat=kb_h&value=20
            query = urllib.parse.parse_qs(parsed_path.query)
            cheat = query.get('cheat', [None])[0]
            
            if cheat in CHEAT_CONFIG:
                state = query.get('state', [None])[0]
                value = query.get('value', [None])[0]
                
                if state:
                    CHEAT_CONFIG[cheat] = (state.lower() == 'true')
                elif value:
                    try:
                        CHEAT_CONFIG[cheat] = int(value)
                    except: pass
                    
                print(f"[Inspector] Updated {cheat} to {CHEAT_CONFIG[cheat]}")
                
            self.send_response(200)
            self.end_headers()
            
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        return # Silence logging

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class InspectorServer(threading.Thread):
    def __init__(self, port=8080):
        super().__init__()
        self.port = port
        self.daemon = True
        
    def run(self):
        print(f"[Inspector] Web Server started at http://localhost:{self.port}")
        # Change directory to where script is? Assumed CWD.
        try:
            with ReusableTCPServer(("", self.port), InspectorHandler) as httpd:
                httpd.serve_forever()
        except OSError as e:
            if e.errno == 98:
                print(f"[Inspector] Port {self.port} is busy. Trying {self.port+1}...")
                with ReusableTCPServer(("", self.port+1), InspectorHandler) as httpd:
                    print(f"[Inspector] Web Server started at http://localhost:{self.port+1}")
                    httpd.serve_forever()
            else:
                raise e

# Helper to add packets from Proxy
def add_packet(start_time, direction, state, packet_id, name, length, payload_bytes, description="", parsed_data=None):
    # Format for JSON
    import datetime
    pkt = {
        "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "direction": direction,
        "state": state, # String
        "id": packet_id,
        "name": name,
        "length": length,
        "payload": payload_bytes.hex(),
        "description": description,
        "parsed": parsed_data
    }
    
    PACKET_HISTORY.append(pkt)
    if len(PACKET_HISTORY) > MAX_HISTORY:
        PACKET_HISTORY.pop(0)
