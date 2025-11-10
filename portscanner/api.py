"""
Minimal REST API server exposing scan summaries.
"""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional


class _State:
    summary: Dict = {}
    diff: Dict = {}
    trend: str = ""


class APIServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.state = _State()

    def update(self, summary: Dict, diff: Optional[Dict], trend: str) -> None:
        self.state.summary = summary or {}
        self.state.diff = diff or {}
        self.state.trend = trend or ""


class RequestHandler(BaseHTTPRequestHandler):
    def _write_json(self, payload, status=200):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 (standard library naming)
        if self.path == "/health":
            self._write_json({"status": "ok"})
            return
        if self.path == "/summary":
            self._write_json(self.server.state.summary)
            return
        if self.path == "/diff":
            self._write_json(self.server.state.diff)
            return
        if self.path == "/trend":
            self._write_json({"trend": self.server.state.trend})
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A003 (inherit interface)
        return  # silence default logging


def start_api_server(listen: str, summary: Dict, diff: Optional[Dict], trend: str) -> APIServer:
    host, _, port_str = listen.partition(":")
    host = host or "127.0.0.1"
    port = int(port_str or 8000)
    server = APIServer((host, port), RequestHandler)
    server.update(summary, diff, trend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] API server listening on http://{host}:{port}")
    return server
