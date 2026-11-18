"""
Networking helpers shared by inputs and outputs (stdlib only):

* ``HttpClient``   persistent HTTP/1.1 connection(s) with TLS and failover
* ``sigv4_headers`` AWS Signature Version 4 (S3, SQS)
* ``GoogleToken``  OAuth2 access token from a service-account key (JWT bearer, RS256)
* ``EntraToken``   OAuth2 client-credentials token from Microsoft Entra ID
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import http.client
import json
import ssl
import threading
import time
import urllib.parse

from ulpf.runtime.retry import RetriableError, classify_http


class HttpResponse:
    def __init__(self, status: int, body: bytes, headers: dict):
        self.status = status
        self.body = body
        self.headers = headers

    def json(self):
        return json.loads(self.body or b"null")

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


class HttpClient:
    """Keeps one connection per base URL per thread; fails over across ``urls``."""

    def __init__(self, urls: list[str] | str, ssl_context: ssl.SSLContext | None = None,
                 timeout: float = 30.0, headers: dict | None = None):
        self.urls = [urls] if isinstance(urls, str) else list(urls)
        self.ssl = ssl_context
        self.timeout = timeout
        self.headers = headers or {}
        self._local = threading.local()
        self._all: list = []          # every thread's connections, so close() reaches them all
        self._all_lock = threading.Lock()
        self._next = 0

    def _conn(self, url: str):
        conns = getattr(self._local, "conns", None)
        if conns is None:
            conns = self._local.conns = {}
        c = conns.get(url)
        if c is None:
            u = urllib.parse.urlsplit(url)
            if u.scheme == "https":
                c = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=self.timeout,
                                                context=self.ssl or ssl.create_default_context())
            else:
                c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=self.timeout)
            conns[url] = c
            with self._all_lock:
                self._all.append(c)
        return c

    def _drop(self, url: str) -> None:
        conns = getattr(self._local, "conns", {})
        c = conns.pop(url, None)
        if c is not None:
            with self._all_lock:
                if c in self._all:
                    self._all.remove(c)
            try:
                c.close()
            except Exception:
                pass

    def request(self, method: str, path: str, body=None, headers: dict | None = None,
                base: str | None = None, sink=None) -> HttpResponse:
        """Send to the next healthy base URL. Network errors raise RetriableError.

        ``body`` may be a seekable file (send ``Content-Length``); ``sink``: a file the body of a
        2xx response is streamed into."""
        bases = [base] if base else self.urls[self._next:] + self.urls[:self._next]
        last: Exception | None = None
        for url in bases:
            u = urllib.parse.urlsplit(url)
            if path.startswith("/"):
                full = u.path.rstrip("/") + path
            else:   # "" = the base URL itself (e.g. a token endpoint)
                full = path or ((u.path or "/") + (f"?{u.query}" if u.query else ""))
            h = {**self.headers, **(headers or {})}
            if body is not None and not any(k.lower() == "content-length" for k in h):
                h["Content-Length"] = str(len(body))     # a file-like body must come with its length
            for attempt in (1, 2):   # a kept-alive connection may have been closed by the peer
                c = self._conn(url)
                try:
                    if hasattr(body, "seek"):
                        body.seek(0)
                    c.request(method, full, body=body, headers=h)
                    r = c.getresponse()
                    if sink is not None and 200 <= r.status < 300:
                        while chunk := r.read(1 << 20):     # stream large objects (bounded memory)
                            sink.write(chunk)
                        data = b""
                    else:
                        data = r.read()
                    return HttpResponse(r.status, data, {k.lower(): v for k, v in r.getheaders()})
                except (OSError, http.client.HTTPException) as e:
                    self._drop(url)
                    last = e
                    if attempt == 2:
                        break
            self._next = (self.urls.index(url) + 1) % len(self.urls) if url in self.urls else 0
        raise RetriableError(f"{method} {path}: {type(last).__name__}: {last}")

    def checked(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None,
                base: str | None = None) -> HttpResponse:
        r = self.request(method, path, body, headers, base)
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err
        return r

    def close(self) -> None:
        getattr(self._local, "conns", {}).clear()
        with self._all_lock:
            conns, self._all = self._all, []
        for c in conns:
            try:
                c.close()
            except Exception:
                pass
        self._local = threading.local()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ---------------------------------------------------------------------------
# AWS Signature Version 4
# ---------------------------------------------------------------------------

def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sigv4_headers(method: str, url: str, region: str, service: str, access_key: str, secret_key: str,
                  body: bytes = b"", session_token: str | None = None, headers: dict | None = None,
                  now: _dt.datetime | None = None, content_sha_header: bool = True,
                  payload_hash: str | None = None) -> dict:
    """Return headers (incl. Authorization) for a SigV4-signed request.

    ``content_sha_header`` adds ``x-amz-content-sha256`` (required by S3,
    optional elsewhere).
    """
    u = urllib.parse.urlsplit(url)
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    payload_hash = payload_hash or hashlib.sha256(body).hexdigest()     # given for streamed bodies
    h = {k.lower(): str(v).strip() for k, v in (headers or {}).items()}
    h["host"] = u.netloc
    h["x-amz-date"] = amz_date
    if content_sha_header:
        h["x-amz-content-sha256"] = payload_hash
    if session_token:
        h["x-amz-security-token"] = session_token
    signed = ";".join(sorted(h))
    canonical_headers = "".join(f"{k}:{h[k]}\n" for k in sorted(h))
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    canonical_query = "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
                               for k, v in sorted(q))
    canonical_path = urllib.parse.quote(u.path or "/", safe="/-_.~%")
    creq = "\n".join([method, canonical_path, canonical_query, canonical_headers, signed, payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = _sign(_sign(_sign(_sign(("AWS4" + secret_key).encode(), date), region), service), "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    h["authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                          f"SignedHeaders={signed}, Signature={sig}")
    h.pop("host")
    return h


# ---------------------------------------------------------------------------
# OAuth tokens
# ---------------------------------------------------------------------------

class _CachedToken:
    def __init__(self):
        self._token: str | None = None
        self._expires = 0.0
        self._lock = threading.Lock()

    def get(self) -> str:
        with self._lock:
            if self._token is None or time.time() > self._expires - 120:
                self._token, ttl = self._fetch()
                self._expires = time.time() + ttl
            return self._token

    def _fetch(self) -> tuple[str, float]:
        raise NotImplementedError


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class GoogleToken(_CachedToken):
    """Service-account JWT bearer flow (RFC 7523), signed RS256 with the account's private key."""

    def __init__(self, credentials_file: str, scope: str, token_url: str | None = None):
        super().__init__()
        with open(credentials_file, "r", encoding="utf-8") as f:
            self.info = json.load(f)
        self.scope = scope
        self.token_url = token_url or self.info.get("token_uri") or "https://oauth2.googleapis.com/token"

    def _fetch(self) -> tuple[str, float]:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        now = int(time.time())
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = _b64url(json.dumps({"iss": self.info["client_email"], "scope": self.scope,
                                     "aud": self.token_url, "iat": now, "exp": now + 3600}).encode())
        key = serialization.load_pem_private_key(self.info["private_key"].encode(), password=None)
        sig = key.sign(f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
        assertion = f"{header}.{claims}.{_b64url(sig)}"
        body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                       "assertion": assertion}).encode()
        with HttpClient(self.token_url) as c:
            r = c.checked("POST", "", body, {"Content-Type": "application/x-www-form-urlencoded"})
        d = r.json()
        return d["access_token"], float(d.get("expires_in", 3600))


class EntraToken(_CachedToken):
    """Microsoft Entra ID client-credentials token."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, scope: str,
                 login_endpoint: str | None = None):
        super().__init__()
        self.url = f"{(login_endpoint or 'https://login.microsoftonline.com').rstrip('/')}/{tenant_id}/oauth2/v2.0/token"
        self.client_id, self.client_secret, self.scope = client_id, client_secret, scope

    def _fetch(self) -> tuple[str, float]:
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                       "client_secret": self.client_secret, "scope": self.scope}).encode()
        with HttpClient(self.url) as c:
            r = c.checked("POST", "", body, {"Content-Type": "application/x-www-form-urlencoded"})
        d = r.json()
        return d["access_token"], float(d.get("expires_in", 3600))
