"""Local deterministic HTTP server for performance tests (127.0.0.1, random port). Records request method/path.

Serves tools/quality-ci/fixtures/performance plus test-only pages:
  /autopost.html      tries POST/DELETE fetches and a form submit on load (must be blocked)
  /redirect.html      302 to /good.html (not followed)
  /offsite.html       loads a script from another origin (blocked)
  /slow-load.html     responds after a delay (timeout)
  /big.html           larger than the configured byte cap (oversize)
  /many.html          requests more sub-resources than the request cap
  /secret.html?...    token-like values in URL, image src, LCP element id and page text (redaction)
  /oversized.html     one image displayed far smaller than its natural size
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "performance"
# Fake token-shaped values for redaction tests, built at runtime so no complete token literal is committed
# (same convention as the Phase 2 tests; avoids tripping push protection / secret scanners).
FAKE_GH = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789AB"
FAKE_SK = "sk_" + "live_" + "abcdefghijklmnop"
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".png": "image/png"}

AUTOPOST = """<!DOCTYPE html><html lang="en"><head><title>Autopost</title></head><body><main><h1>Autopost</h1>
<form id="f" action="/submit" method="post"><input name="q"></form>
<script>
fetch('/api/delete', {method: 'POST', body: 'x'}).catch(() => {});
fetch('/api/item', {method: 'DELETE'}).catch(() => {});
setTimeout(() => document.getElementById('f').submit(), 50);
</script></main></body></html>"""
OFFSITE = """<!DOCTYPE html><html lang="en"><head><title>Offsite</title>
<script src="http://203.0.113.10/tracker.js" async></script></head><body><main><h1>Offsite</h1></main></body></html>"""
MANY = "<!DOCTYPE html><html lang='en'><head><title>Many</title></head><body><main><h1>Many</h1>" + \
    "".join(f"<img src='img/good.png?n={i}' width='4' height='4' alt=''>" for i in range(40)) + "</main></body></html>"
SECRET = f"""<!DOCTYPE html><html lang="en"><head><title>Secret text {FAKE_SK}</title></head><body><main>
<h1 id="tok_{FAKE_GH}">Private words {FAKE_GH}</h1>
<img src="img/shift.png?token=abcdef123456">
</main></body></html>"""
OVERSIZED = """<!DOCTYPE html><html lang="en"><head><title>Oversized</title></head><body><main><h1>Oversized</h1>
<img src="img/shift.png" width="20" height="20" alt="">
</main></body></html>"""


class Recorder:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.lock = threading.Lock()

    def add(self, method: str, path: str) -> None:
        with self.lock:
            self.requests.append((method, path))


def _handler(rec: Recorder, slow_seconds: float, big_bytes: int):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body: bytes, ctype="text/html; charset=utf-8", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def do_GET(self):
            rec.add("GET", self.path)
            path = self.path.split("?", 1)[0]
            pages = {"/autopost.html": AUTOPOST, "/offsite.html": OFFSITE, "/many.html": MANY, "/secret.html": SECRET,
                     "/oversized.html": OVERSIZED}
            if path in pages:
                return self._send(200, pages[path].encode())
            if path == "/redirect.html":
                return self._send(302, b"", extra={"Location": "/good.html"})
            if path == "/slow-load.html":
                time.sleep(slow_seconds)
                return self._send(200, (FIXTURES / "good.html").read_bytes())
            if path == "/big.html":
                return self._send(200, b"<!DOCTYPE html><html lang='en'><title>Big</title><p>" + b"a" * big_bytes + b"</p></html>")
            f = (FIXTURES / path.lstrip("/")).resolve()
            if FIXTURES in f.parents and f.is_file():
                return self._send(200, f.read_bytes(), TYPES.get(f.suffix, "application/octet-stream"))
            return self._send(404, b"not found", "text/plain")

        def do_HEAD(self):
            return self.do_GET()

        def _unsafe(self):
            rec.add(self.command, self.path)
            return self._send(405, b"", "text/plain")

        do_POST = do_PUT = do_DELETE = do_PATCH = _unsafe

    return H


class PerfServer:
    def __init__(self, slow_seconds: float = 5.0, big_bytes: int = 300_000):
        self.rec = Recorder()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self.rec, slow_seconds, big_bytes))
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self) -> "PerfServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
