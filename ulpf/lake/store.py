"""
Object storage for the lakehouse cold tier: local disk, S3-compatible (AWS S3, MinIO, Ceph RGW)
and Azure Blob Storage.

Every backend offers the same small interface over ``/``-separated keys relative to the table
root. ``put_if_absent`` is the atomic "create only if missing" that Delta Lake commits rely on:
a hard link on local disk, ``If-None-Match: *`` on S3 (AWS since 2024, MinIO, Ceph RGW Reef+)
and Azure. Large objects are streamed from and to files, so memory stays bounded.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET

from ulpf.runtime.net import HttpClient, sigv4_headers
from ulpf.runtime.retry import PermanentError, RetriableError, classify_http


class Exists(Exception):
    """put_if_absent: the key already exists (another writer committed first)."""


def _check_key(key: str) -> str:
    parts = key.split("/")
    if not key or key.startswith("/") or any(p in ("", ".", "..") for p in parts) or "\\" in key:
        raise ValueError(f"invalid object key {key!r}")
    return key


class Store:
    def put(self, key: str, data: bytes) -> None: ...
    def put_file(self, key: str, path: str) -> None: ...
    def put_if_absent(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def get_file(self, key: str, path: str) -> None: ...
    def exists(self, key: str) -> bool: ...
    def list(self, prefix: str) -> list[tuple[str, int]]: ...
    def delete(self, key: str) -> None: ...

    @property
    def local_root(self) -> str | None:
        """A directory DuckDB can read the objects from directly (local stores only)."""
        return None


class LocalStore(Store):
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    @property
    def local_root(self) -> str:
        return self.root

    def _p(self, key: str) -> str:
        return os.path.join(self.root, *_check_key(key).split("/"))

    def _tmp(self, key: str) -> str:
        path = self._p(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
        os.close(fd)
        return tmp

    def put(self, key: str, data: bytes) -> None:
        tmp = self._tmp(key)
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._p(key))

    def put_file(self, key: str, path: str) -> None:
        tmp = self._tmp(key)
        shutil.copyfile(path, tmp)
        with open(tmp, "rb+") as f:
            os.fsync(f.fileno())
        os.replace(tmp, self._p(key))

    def put_if_absent(self, key: str, data: bytes) -> None:
        tmp = self._tmp(key)
        try:
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(tmp, self._p(key))           # atomic, fails if the name exists
            except FileExistsError:
                raise Exists(key) from None
        finally:
            os.unlink(tmp)

    def get(self, key: str) -> bytes:
        try:
            with open(self._p(key), "rb") as f:
                return f.read()
        except FileNotFoundError:
            raise KeyError(key) from None

    def get_file(self, key: str, path: str) -> None:
        shutil.copyfile(self._p(key), path)

    def exists(self, key: str) -> bool:
        return os.path.exists(self._p(key))

    def list(self, prefix: str) -> list[tuple[str, int]]:
        base = os.path.join(self.root, *prefix.rstrip("/").split("/")) if prefix else self.root
        out = []
        for d, _dirs, files in os.walk(base):
            for f in files:
                if f.startswith(".tmp-"):
                    continue
                full = os.path.join(d, f)
                out.append((os.path.relpath(full, self.root).replace(os.sep, "/"), os.path.getsize(full)))
        return sorted(out)

    def delete(self, key: str) -> None:
        try:
            os.unlink(self._p(key))
        except FileNotFoundError:
            pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


class S3Store(Store):
    """S3 / MinIO / Ceph RGW with SigV4. ``endpoint`` + ``path_style`` for MinIO and Ceph."""

    def __init__(self, bucket: str, prefix: str, region: str, access_key: str, secret_key: str,
                 session_token: str | None = None, endpoint: str | None = None, path_style: bool = False,
                 ssl_context=None):
        self.bucket, self.region = bucket, region
        self.prefix = prefix.strip("/")
        self.access, self.secret, self.token = access_key, secret_key, session_token
        if endpoint:
            ep = endpoint.rstrip("/")
            self.base = f"{ep}/{bucket}" if path_style else ep.replace("://", f"://{bucket}.", 1)
        else:
            self.base = f"https://{bucket}.s3.{region}.amazonaws.com"
        self.http = HttpClient(self.base, ssl_context, timeout=300)

    def _key(self, key: str) -> str:
        k = _check_key(key)
        return f"{self.prefix}/{k}" if self.prefix else k

    def _url(self, key: str, query: str = "") -> tuple[str, str]:
        path = "/" + urllib.parse.quote(self._key(key), safe="/-_.~")
        return path + (f"?{query}" if query else ""), self.base + path + (f"?{query}" if query else "")

    def _send(self, method: str, key: str, body=None, headers=None, query: str = "", sink=None,
              payload_hash: str | None = None, ok404: bool = False):
        path, url = self._url(key, query) if key else ("/?" + query, self.base + "/?" + query)
        data = body if isinstance(body, (bytes, type(None))) else b""
        h = sigv4_headers(method, url, self.region, "s3", self.access, self.secret, data or b"",
                          self.token, headers, payload_hash=payload_hash)
        r = self.http.request(method, path, body, h, sink=sink)     # path-style: base path is /bucket
        if ok404 and r.status == 404:
            return r
        if r.status == 412:
            raise Exists(key)
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err
        return r

    def put(self, key: str, data: bytes) -> None:
        self._send("PUT", key, data)

    def put_file(self, key: str, path: str) -> None:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            self._send("PUT", key, f, {"Content-Length": str(size)}, payload_hash=_sha256_file(path))

    def put_if_absent(self, key: str, data: bytes) -> None:
        self._send("PUT", key, data, {"If-None-Match": "*"})

    def get(self, key: str) -> bytes:
        r = self._send("GET", key, ok404=True)
        if r.status == 404:
            raise KeyError(key)
        return r.body

    def get_file(self, key: str, path: str) -> None:
        with open(path, "wb") as f:
            self._send("GET", key, sink=f)

    def exists(self, key: str) -> bool:
        return self._send("HEAD", key, ok404=True).status != 404

    def list(self, prefix: str) -> list[tuple[str, int]]:
        out, token = [], None
        full = self._key(prefix.rstrip("/")) + "/" if prefix else (self.prefix + "/" if self.prefix else "")
        strip = len(self.prefix) + 1 if self.prefix else 0
        while True:
            q = {"list-type": "2", "prefix": full}
            if token:
                q["continuation-token"] = token
            query = urllib.parse.urlencode(sorted(q.items()), quote_via=urllib.parse.quote)
            r = self._send("GET", "", query=query)
            root = ET.fromstring(r.body)
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            for c in root.iter(f"{ns}Contents"):
                out.append((c.find(f"{ns}Key").text[strip:], int(c.find(f"{ns}Size").text)))
            if (root.findtext(f"{ns}IsTruncated") or "false") != "true":
                return sorted(out)
            token = root.findtext(f"{ns}NextContinuationToken")

    def delete(self, key: str) -> None:
        self._send("DELETE", key, ok404=True)


class AzureBlobStore(Store):
    """Azure Blob Storage: Entra ID bearer token (``token``: object with ``get()``) or a SAS."""

    API = "2023-11-03"

    def __init__(self, account_url: str, container: str, prefix: str, token=None, sas: str | None = None,
                 ssl_context=None):
        if token is None and not sas:
            raise ValueError("azure store needs a token or a SAS")
        self.base = account_url.rstrip("/")
        self.container, self.prefix = container, prefix.strip("/")
        self.token, self.sas = token, (sas or "").lstrip("?")
        self.http = HttpClient(self.base, ssl_context, timeout=300)

    def _path(self, key: str = "", query: str = "") -> str:
        k = _check_key(key) if key else ""
        name = "/".join(x for x in (self.prefix, k) if x)
        q = "&".join(x for x in (query, self.sas) if x)
        return f"/{self.container}" + (f"/{urllib.parse.quote(name, safe='/-_.~')}" if name else "") + (f"?{q}" if q else "")

    def _send(self, method: str, key: str, body=None, headers=None, query: str = "", sink=None, ok404=False):
        h = {"x-ms-version": self.API, **(headers or {})}
        if self.token is not None:
            h["Authorization"] = f"Bearer {self.token.get()}"
        r = self.http.request(method, self._path(key, query), body, h, sink=sink)
        if ok404 and r.status == 404:
            return r
        if r.status in (409, 412) and headers and headers.get("If-None-Match") == "*":
            raise Exists(key)
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err
        return r

    def put(self, key: str, data: bytes) -> None:
        self._send("PUT", key, data, {"x-ms-blob-type": "BlockBlob"})

    def put_file(self, key: str, path: str) -> None:
        size = os.path.getsize(path)
        if size > 5000 * 2**20:
            raise PermanentError(f"{path}: {size} bytes is above the single-put limit")
        with open(path, "rb") as f:
            self._send("PUT", key, f, {"x-ms-blob-type": "BlockBlob", "Content-Length": str(size)})

    def put_if_absent(self, key: str, data: bytes) -> None:
        self._send("PUT", key, data, {"x-ms-blob-type": "BlockBlob", "If-None-Match": "*"})

    def get(self, key: str) -> bytes:
        r = self._send("GET", key, ok404=True)
        if r.status == 404:
            raise KeyError(key)
        return r.body

    def get_file(self, key: str, path: str) -> None:
        with open(path, "wb") as f:
            self._send("GET", key, sink=f)

    def exists(self, key: str) -> bool:
        return self._send("HEAD", key, ok404=True).status != 404

    def list(self, prefix: str) -> list[tuple[str, int]]:
        out, marker = [], ""
        full = "/".join(x for x in (self.prefix, prefix.rstrip("/")) if x)
        full = full + "/" if full else ""
        strip = len(self.prefix) + 1 if self.prefix else 0
        while True:
            q = f"restype=container&comp=list&prefix={urllib.parse.quote(full, safe='')}"
            if marker:
                q += f"&marker={urllib.parse.quote(marker, safe='')}"
            r = self._send("GET", "", query=q)
            root = ET.fromstring(r.body)
            for b in root.iter("Blob"):
                out.append((b.findtext("Name")[strip:], int(b.find("Properties").findtext("Content-Length"))))
            marker = root.findtext("NextMarker") or ""
            if not marker:
                return sorted(out)

    def delete(self, key: str) -> None:
        self._send("DELETE", key, ok404=True)


def open_store(opts: dict) -> Store:
    """The store a lakehouse output's ``storage`` options name (secrets come from env vars)."""
    from ulpf.runtime.sinks.base import client_ssl_context, env_secret
    kind = opts.get("type", "local")
    if kind == "local":
        return LocalStore(opts["path"])
    if kind in ("s3", "minio", "ceph"):
        return S3Store(opts["bucket"], opts.get("prefix", ""), opts.get("region", "us-east-1"),
                       env_secret(opts.get("access_key_env"), "access key"),
                       env_secret(opts.get("secret_key_env"), "secret key"),
                       env_secret(opts.get("session_token_env"), "session token") if opts.get("session_token_env") else None,
                       opts.get("endpoint"), opts.get("path_style", kind != "s3"),
                       client_ssl_context(opts.get("tls")))
    if kind == "azure":
        token = None
        if opts.get("client_secret_env"):
            from ulpf.runtime.net import EntraToken
            token = EntraToken(opts["tenant_id"], opts["client_id"], env_secret(opts["client_secret_env"]),
                               "https://storage.azure.com/.default", opts.get("login_endpoint"))
        return AzureBlobStore(opts["account_url"], opts["container"], opts.get("prefix", ""), token,
                              env_secret(opts.get("sas_env"), "SAS token") if opts.get("sas_env") else None,
                              client_ssl_context(opts.get("tls")))
    raise PermanentError(f"unknown lakehouse storage type {kind!r}")


__all__ = ["Store", "LocalStore", "S3Store", "AzureBlobStore", "Exists", "open_store",
           "RetriableError", "PermanentError"]
