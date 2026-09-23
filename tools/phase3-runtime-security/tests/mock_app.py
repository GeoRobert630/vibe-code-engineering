"""Tiny local mock application used only to test the scanner.

Modes:
  safe      correct headers, secure cookies, restrictive CORS, generic errors
  unsafe    missing headers, insecure cookies, reflected CORS with credentials,
            stack-trace / DB-error / path / secret leakage in error responses
Roles:
  app       the application
  redirect  a plain-HTTP listener: safe -> 301 to https on the same host, unsafe -> 200

Run standalone (binds to 127.0.0.1 only):
  python tests/mock_app.py --mode safe --port 3000
  python tests/mock_app.py --mode unsafe --port 3001
  python tests/mock_app.py --mode safe --role redirect --port 3080 --https-port 3443
"""

from __future__ import annotations

import argparse
import json
import secrets
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TRUSTED_ORIGIN = "https://app.example.test"
# Obviously fake values; tests assert they never appear in reports.
UNSAFE_COOKIE_VALUE = "abc123FAKESESSIONVALUE"
UNSAFE_DB_PASSWORD = "FakeLeakedPassw0rd"

UNSAFE_TRACE = (
    "Traceback (most recent call last):\n"
    '  File "/home/app/src/server.py", line 42, in handle\n'
    "    cur.execute(query)\n"
    'psycopg2.errors.SyntaxError: syntax error at or near "WHERE"\n'
    f"DATABASE_URL=postgres://app:{UNSAFE_DB_PASSWORD}@db.internal/appdb\n"
)

SAFE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def make_handler(mode: str, role: str = "app", https_port: int | None = None):
    safe = mode == "safe"

    class Handler(BaseHTTPRequestHandler):
        server_version = "app" if safe else "BaseHTTP/0.6"
        sys_version = "" if safe else "Python/3.12"
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:  # keep test output quiet
            pass

        def _send(self, status: int, body: str, ctype: str = "application/json", extra: dict[str, str] | None = None, cookies: list[str] | None = None) -> None:
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            if safe:
                for k, v in SAFE_HEADERS.items():
                    self.send_header(k, v)
            else:
                self.send_header("X-Powered-By", "Express 4.17.1")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            for c in cookies or []:
                self.send_header("Set-Cookie", c)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _cors(self) -> dict[str, str]:
            origin = self.headers.get("Origin")
            if origin is None:
                return {}
            if safe:
                if origin == TRUSTED_ORIGIN:
                    return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Vary": "Origin"}
                return {"Vary": "Origin"}
            return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}

        def _redirect_role(self) -> bool:
            if role != "redirect":
                return False
            if safe:
                host = self.headers.get("Host", "127.0.0.1").split(":")[0]
                self.send_response(301)
                self.send_header("Location", f"https://{host}:{https_port or 443}{self.path}")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(200, "<html><body>plain http</body></html>", "text/html")
            return True

        def do_GET(self) -> None:
            if self._redirect_role():
                return
            path = self.path.split("?")[0]
            if path == "/":
                cookies = (
                    [f"session={secrets.token_hex(16)}; Path=/; Secure; HttpOnly; SameSite=Lax",
                     "theme=dark; Path=/; Secure; SameSite=Lax; Max-Age=86400"]
                    if safe else
                    [f"session={UNSAFE_COOKIE_VALUE}; Path=/", "tracking=t123; SameSite=None"]
                )
                self._send(200, "<!doctype html><html><body>mock</body></html>", "text/html", self._cors(), cookies)
            elif path.startswith("/api/items/"):
                item = path.rsplit("/", 1)[-1]
                if item.isdigit():
                    self._send(200, json.dumps({"id": int(item)}), extra=self._cors())
                elif safe:
                    self._send(400, '{"error": "invalid id"}', extra=self._cors())
                else:
                    self._send(500, UNSAFE_TRACE, "text/plain", self._cors())
            elif path == "/api/search":
                if safe:
                    self._send(400, '{"error": "missing parameter"}', extra=self._cors())
                else:
                    self._send(500, "KeyError: 'q'\n  at Object.<anonymous> (/usr/src/app/routes/search.js:12:7)", "text/plain")
            elif safe:
                self._send(404, '{"error": "not found"}', extra=self._cors())
            else:
                self._send(500, UNSAFE_TRACE, "text/plain", self._cors())

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_OPTIONS(self) -> None:
            origin = self.headers.get("Origin")
            if safe:
                if origin == TRUSTED_ORIGIN:
                    self._send(204, "", extra={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "GET, POST", "Vary": "Origin"})
                else:
                    self._send(403, '{"error": "origin not allowed"}')
            else:
                self._send(204, "", extra={"Access-Control-Allow-Origin": origin or "*", "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
                                           "Access-Control-Allow-Headers": "*", "Access-Control-Allow-Credentials": "true"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(min(length, 65536))
            try:
                json.loads(raw or b"")
            except ValueError:
                if safe:
                    self._send(400, '{"error": "invalid request"}')
                else:
                    self._send(500, "Traceback (most recent call last):\n  File \"/home/app/src/api.py\", line 9\njson.decoder.JSONDecodeError: Expecting value", "text/plain")
                return
            # The mock never stores anything; valid JSON is simply acknowledged.
            self._send(200, '{"ok": true}')

    return Handler


class MockServer:
    """Run a mock server on 127.0.0.1 in a background thread."""

    def __init__(self, mode: str, role: str = "app", https_port: int | None = None, certfile: str | None = None, keyfile: str | None = None, port: int = 0) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(mode, role, https_port))
        self.scheme = "http"
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}"

    def __enter__(self) -> "MockServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Local mock app for phase3 scanner tests (binds 127.0.0.1 only).")
    ap.add_argument("--mode", choices=["safe", "unsafe"], required=True)
    ap.add_argument("--role", choices=["app", "redirect"], default="app")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--https-port", type=int, default=None)
    args = ap.parse_args()
    server = MockServer(args.mode, args.role, args.https_port, port=args.port)
    print(f"mock {args.mode}/{args.role} listening on {server.url}", flush=True)
    try:
        server.httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
