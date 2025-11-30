import socketserver
import http.server
import time
import os
import json
import uuid

PORT = 8000
WIN_FILE_PATH = "./setups/win_setup.ps1"
setupwin_cmd: bytes = (
    b"Start-Process powershell -Verb runAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command \"irm http://localhost:8000/win | iex\"'"
)
srv_ip = "192.168.222.1"
session = uuid.uuid4()
is_session_active = False
is_alive = False
last_keepalive = 0
ZIP_PATH = "db/current.zip"
stop_trigger = False


class WebServer(http.server.SimpleHTTPRequestHandler):
    def do_keepalive(self):
        global is_alive, last_keepalive
        is_alive = True
        last_keepalive = time.time()

    def do_GET(self):
        if self.path == "/win":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            with open(WIN_FILE_PATH, "rb") as f:
                self.wfile.write(f.read().replace(b"IP_ADDR", srv_ip.encode()))
        elif self.path == "/inst_win_cmd":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(setupwin_cmd)
        elif self.path.startswith("/currentsession"):
            self.do_keepalive()
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            print(f"Current session: {is_session_active}")
            if is_session_active:
                print(f"Current session: {session}")
                self.wfile.write(str(session).encode())
            else:
                self.wfile.write(b"no")
        elif self.path.startswith("/download"):
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            with open(ZIP_PATH, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "File not found.")

    def do_POST(self):
        global is_alive, last_keepalive, session
        if self.path.startswith("/api/post/"):
            self.do_keepalive()
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)
            if os.path.exists(f"./db/sessions/{session}.json"):
                with open(f"./db/sessions/{session}.json", "r") as f:
                    existing_data = json.load(f)
                existing_data[round(time.time())] = {
                    "data": data,
                    "type": self.path.split("/")[-1],
                }
                data = existing_data
            else:
                data = {
                    round(time.time()): {"data": data, "type": self.path.split("/")[-1]}
                }
            with open(f"./db/sessions/{session}.json", "w") as f:
                json.dump(data, f, indent=4)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Data received")
        else:
            self.send_error(404, "API endpoint not found.")


def run_server():
    with socketserver.ThreadingTCPServer(("", PORT), WebServer) as httpd:
        print(f"Serving...")
        while not stop_trigger:
            print("Waiting for requests...", stop_trigger)
            httpd.handle_request()
        print("Server stopped due to stop_trigger.")
