from __future__ import annotations

import socketserver
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest


@contextmanager
def _http_target(config: dict):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            body = config.get("body", "<html><body>ordinary site</body></html>")
            if parsed.path == "/version" and config.get("dashboard"):
                body = '{"major":"1","gitVersion":"v1.30.0"}'
            elif parsed.path == "/.well-known/openid-configuration" and config.get("openid"):
                body = config["openid"]
            elif parsed.path == "/openapi.json" and config.get("openapi"):
                body = config["openapi"]
            if config.get("reflect"):
                marker = query.get("cygnus_probe", [""])[0]
                body += marker
            # Verbose error disclosure simulation
            if config.get("error_disclosure"):
                body += "\nTraceback (most recent call last):\n  File \"/var/www/app/views.py\", line 42, in get\n    raise Exception('database error')\nException: database error\n"
            # Open redirect simulation
            redirect_target = None
            if config.get("open_redirect"):
                for param in ("next", "redirect", "url", "return", "returnUrl", "redirect_uri", "continue", "dest", "destination"):
                    vals = query.get(param)
                    if vals:
                        redirect_target = vals[0]
                        break
            status_code = 302 if redirect_target else 200
            self.send_response(status_code)
            for key, value in config.get("headers", {}).items():
                self.send_header(key, value)
            if config.get("cors") and self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
            # Session cookie simulation
            if config.get("session_cookie"):
                # Vulnerable cookie missing Secure/HttpOnly/SameSite by default, unless "secure_cookie" is set
                if config.get("secure_cookie"):
                    self.send_header("Set-Cookie", "sessionid=secure123; Path=/; Secure; HttpOnly; SameSite=Strict")
                else:
                    self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
            if redirect_target:
                self.send_header("Location", redirect_target)
                body = f"<html><body>Redirecting to {redirect_target}</body></html>" + body
            self.send_header("Content-Type", "application/json" if parsed.path == "/version" else "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        def do_POST(self):
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}' if config.get("graphql") and parsed.path == "/graphql" else '{"errors":[{"message":"not found"}]}'
            self.send_response(200 if config.get("graphql") else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join()


@contextmanager
def _ftp_target(anonymous: bool):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            message = "220 MockFTP ready; anonymous login allowed\r\n" if anonymous else "220 MockFTP authenticated users only\r\n"
            self.request.sendall(message.encode())
            self.request.settimeout(0.25)
            try:
                data = self.request.recv(1024)
                if data:
                    self.request.sendall(("211 anonymous login allowed\r\n" if anonymous else "211 no anonymous feature\r\n").encode())
            except OSError:
                pass

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"ftp://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.fixture
def http_target():
    return _http_target


@pytest.fixture
def ftp_target():
    return _ftp_target
