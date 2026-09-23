"""Minimal, bounded HTTP client for read-only probes.

Guarantees:
* requests go only to the configured target host (scheme/port from base_url or http_url)
* redirects are never followed (they are inspected instead)
* methods are allowlisted; POST is only allowed with a body that is *not* valid JSON
  (the invalid-JSON probe), so no request can create or modify data through a JSON API
* a hard request budget, a timeout, a delay between requests and a response-size cap
* TLS verification is always on for HTTPS (optionally with a configured CA file)
"""

from __future__ import annotations

import http.client
import json
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..config import Config

MAX_BODY = 256 * 1024
USER_AGENT = "phase3-runtime-security/0.1 (read-only defensive checks)"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
PROBE_METHOD = "PHASE3PROBE"  # deliberately unsupported method token for the error probe


class RequestNotAllowed(ValueError):
    pass


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: str
    truncated: bool = False

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()


@dataclass
class Client:
    cfg: Config
    sent: int = 0
    log: list[str] = field(default_factory=list)

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.cfg.ca_file) if self.cfg.ca_file else ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        base: str | None = None,
    ) -> Response:
        base = base or self.cfg.base_url
        parts = urlsplit(base)
        if parts.hostname != self.cfg.host:
            raise RequestNotAllowed("request host differs from the configured target")
        if not path.startswith("/") or path.startswith("//") or "://" in path:
            raise RequestNotAllowed("only relative paths are allowed")
        if method not in SAFE_METHODS | {PROBE_METHOD, "POST"}:
            raise RequestNotAllowed(f"method {method} not allowed")
        if method == "POST":
            try:
                json.loads(body or b"")
            except ValueError:
                pass
            else:
                raise RequestNotAllowed("POST is only allowed with a malformed (non-JSON) body")
        if self.sent >= self.cfg.max_requests:
            raise BudgetExceeded(f"request budget of {self.cfg.max_requests} exhausted")
        if self.sent and self.cfg.delay_seconds:
            time.sleep(self.cfg.delay_seconds)
        self.sent += 1

        port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                parts.hostname, port, timeout=self.cfg.timeout, context=self._ssl_context()
            )
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=self.cfg.timeout)
        full_path = (parts.path.rstrip("/") + path) or "/"
        send_headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
        send_headers.update(headers or {})
        try:
            conn.request(method, full_path, body=body, headers=send_headers)
            resp = conn.getresponse()
            raw = resp.read(MAX_BODY + 1)
            result = Response(
                url=f"{parts.scheme}://{parts.netloc}{full_path}",
                status=resp.status,
                reason=resp.reason,
                headers=list(resp.getheaders()),
                body=raw[:MAX_BODY].decode("utf-8", "replace"),
                truncated=len(raw) > MAX_BODY,
            )
        finally:
            conn.close()
        self.log.append(f"{method} {result.url} -> {result.status}")
        return result
