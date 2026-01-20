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
                
        elif path == "/api/packets":
            # Parse Query: ?since=Index
            query = urllib.parse.parse_qs(parsed_path.query)
            since_idx = int(query.get('since', [0])[0])
            
            # Get new packets
            new_packets = []
            if since_idx < len(PACKET_HISTORY):
                new_packets = PACKET_HISTORY[since_idx:]
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(new_packets).encode('utf-8'))
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        return # Silence logging

class InspectorServer(threading.Thread):
    def __init__(self, port=8080):
        super().__init__()
        self.port = port
        self.daemon = True
        
    def run(self):
        print(f"[Inspector] Web Server started at http://localhost:{self.port}")
        # Change directory to where script is? Assumed CWD.
        with socketserver.TCPServer(("", self.port), InspectorHandler) as httpd:
            httpd.serve_forever()

# Helper to add packets from Proxy
def add_packet(start_time, direction, state, packet_id, name, length, payload_bytes):
    # Format for JSON
    import datetime
    pkt = {
        "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "direction": direction,
        "state": state, # String
        "id": packet_id,
        "name": name,
        "length": length,
        "payload": payload_bytes.hex()
    }
    
    PACKET_HISTORY.append(pkt)
    if len(PACKET_HISTORY) > MAX_HISTORY:
        PACKET_HISTORY.pop(0)
