import mitmproxy
import urllib.request
import json
import threading

class MitmproxySender:
    def __init__(self):
        self._pending_requests = []
        # Config
        self.url = "http://IP_ADDR:8000/api/post/httpdump"
        # self.url = "http://localhost:8000/t.php"
        self.update_interval = 2
        self._timer = threading.Timer(self.update_interval, self.update_requ)
        self._timer.start()

    def update_requ(self):
        self._timer = threading.Timer(self.update_interval, self.update_requ)
        self._timer.start()
        if self._pending_requests:
            data = json.dumps(self._pending_requests)
            try:
                req = urllib.request.Request(self.url, data.encode("utf-8"), {"Content-Type": "application/json"})
                response = urllib.request.urlopen(req)
                print(f"Response from server: {response.read()}")
            except Exception as e:
                print(f"Error sending data to {self.url}: {e}")
            self._pending_requests = []
        

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://") and not "IP_ADDR" in flow.request.pretty_url:
            try:
                self._pending_requests.append({
                    "Url": flow.request.pretty_url,
                    "Method": flow.request.method,
                    "Headers": dict(flow.request.headers),
                    "Body": flow.request.content.decode("utf-8", errors="ignore"),
                })
            except Exception as e:
                print(f"Error fetching URL {flow.request.url}: {e}")

addons = [MitmproxySender()]