"""Two loopback-only HTTP origins used by the local acceptance tests."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.parse import urlsplit


class _LabHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        lab = self.server.lab
        label = self.server.label
        path = urlsplit(self.path).path
        lab.record(
            label,
            self.path,
            self.headers.get("Authorization"),
            self.headers.get("Cookie"),
            self.headers.get("Referer"),
            self.headers.get("Proxy-Authorization"),
        )

        if label == "A" and path == "/cross":
            self._redirect(f"http://127.0.0.1:{lab.b_port}/capture")
        elif label == "A" and path == "/cross-return":
            self._redirect(f"http://127.0.0.1:{lab.b_port}/return")
        elif label == "B" and path == "/return":
            self._redirect(f"http://127.0.0.1:{lab.a_port}/capture")
        elif label == "A" and path == "/relative":
            self._redirect("capture?case=relative")
        elif label == "A" and path == "/mixed":
            self._redirect(f"http://LOCALHOST:{lab.a_port}/capture")
        elif label == "A" and path == "/loop":
            self._redirect("/loop")
        elif label == "A" and path.startswith("/count/"):
            count = int(path.rsplit("/", 1)[-1])
            self._redirect(f"/count/{count + 1}")
        elif label == "A" and path == "/unsafe":
            self._redirect("file:///etc/passwd")
        elif label == "A" and path == "/unsafe-space":
            self._redirect(f"http://127.0.0.1:{lab.b_port}/a b?token=SYNTHETIC_LAB_TOKEN")
        elif label == "A" and path == "/large":
            self._respond(200, b"X" * 128)
        else:
            body = json.dumps({"origin": label, "path": self.path}).encode("utf-8")
            self._respond(200, body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class LoopbackLab:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[dict[str, str | None]] = []
        self.a = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
        self.b = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
        self.a.lab = self.b.lab = self
        self.a.label = "A"
        self.b.label = "B"
        self.a_port = self.a.server_port
        self.b_port = self.b.server_port
        self._threads = [
            threading.Thread(target=self.a.serve_forever, daemon=True),
            threading.Thread(target=self.b.serve_forever, daemon=True),
        ]

    @property
    def a_url(self) -> str:
        return f"http://127.0.0.1:{self.a_port}"

    @property
    def b_url(self) -> str:
        return f"http://127.0.0.1:{self.b_port}"

    def record(
        self,
        label: str,
        path: str,
        authorization: str | None,
        cookie: str | None,
        referer: str | None,
        proxy_authorization: str | None,
    ) -> None:
        with self._lock:
            self._records.append(
                {
                    "origin": label,
                    "path": path,
                    "authorization": authorization,
                    "cookie": cookie,
                    "referer": referer,
                    "proxy_authorization": proxy_authorization,
                }
            )

    def snapshot(self) -> list[dict[str, str | None]]:
        with self._lock:
            return [dict(record) for record in self._records]

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def __enter__(self) -> "LoopbackLab":
        for thread in self._threads:
            thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.a.shutdown()
        self.b.shutdown()
        self.a.server_close()
        self.b.server_close()
        for thread in self._threads:
            thread.join(timeout=2)
