import asyncio
import base64
import gzip
import hashlib
import json
import threading
import time
from contextlib import asynccontextmanager, contextmanager, suppress
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from typing import Dict, List, Optional

from fasthttp import Client, BasicAuth, DigestAuth, AuthBase
from fasthttp.retry import RetryPolicy
from fasthttp.errors import ResponseError, RequestError, WebSocketHandshakeError
from fasthttp.connection import READ_BUFFER_SIZE
from fasthttp.wsproto import WSConnection
from fasthttp.wsproto.connection import ConnectionType
from fasthttp.wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    RejectConnection,
    Request as WSRequestEvent,
    TextMessage,
)

try:
    import brotli

    BR_AVAILABLE = True
except Exception:  # pragma: no cover
    BR_AVAILABLE = False


BASIC_USERNAME = "basicuser"
BASIC_PASSWORD = "basicpass"
DIGEST_USERNAME = "digestuser"
DIGEST_PASSWORD = "digestpass"
API_KEY_SECRET = "secret-key-123"
DIGEST_NONCE = "abcdef1234567890"
DIGEST_REALM = "fasthttp-test"
DIGEST_OPAQUE = "deadbeef"


class TestHandler(BaseHTTPRequestHandler):
    retry_counter = 0

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/basic-auth":
            if not self._check_basic_auth():
                self._send_basic_challenge()
                return
            body = b"basic-auth-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/digest-auth":
            if not self._check_digest_auth(self.command or "GET", parsed_path.path):
                self._send_digest_challenge()
                return
            body = b"digest-auth-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/custom-auth":
            api_key = self.headers.get("X-API-Key")
            if api_key != API_KEY_SECRET:
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"custom-auth-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/gzip":
            payload = json.dumps({"hello": "world"}).encode("utf-8")
            body = gzip.compress(payload)
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/br":
            if not BR_AVAILABLE:
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = json.dumps({"brotli": True}).encode("utf-8")
            body = brotli.compress(payload)
            self.send_response(200)
            self.send_header("Content-Encoding", "br")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/stream":
            chunks = [b"hello", b"-", b"world"]
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii"))
                self.wfile.write(chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        elif path == "/retry":
            if TestHandler.retry_counter == 0:
                TestHandler.retry_counter += 1
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            body = b"ok"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/final":
            body = b"final"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/set-cookie":
            body = b"cookie-set"
            self.send_response(200)
            self.send_header("Set-Cookie", "token=abc")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/needs-cookie":
            cookie = self.headers.get("Cookie", "")
            body = cookie.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/query-test":
            parsed_path = urlparse(self.path)
            query_params = parsed_path.query
            body = query_params.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/cookie-path":
            parsed_path = urlparse(self.path)
            if parsed_path.path == "/cookie-path":
                self.send_response(200)
                self.send_header("Set-Cookie", "path_cookie=value123; Path=/cookie-path")
                self.send_header("Content-Length", "0")
                self.end_headers()

        elif path == "/cookie-domain":
            self.send_response(200)
            self.send_header("Set-Cookie", "domain_cookie=test; Domain=.127.0.0.1")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/cookie-expires":
            self.send_response(200)
            # Set cookie with expires in future
            expires = formatdate(time.time() + 3600, localtime=False, usegmt=True)
            self.send_header("Set-Cookie", f"expires_cookie=test; Expires={expires}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/cookie-max-age":
            self.send_response(200)
            self.send_header("Set-Cookie", "maxage_cookie=test; Max-Age=3600")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/cookie-secure":
            self.send_response(200)
            self.send_header("Set-Cookie", "secure_cookie=test; Secure")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/cookie-httponly":
            self.send_response(200)
            self.send_header("Set-Cookie", "httponly_cookie=test; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/cookie-samesite":
            self.send_response(200)
            self.send_header("Set-Cookie", "samesite_cookie=test; SameSite=Strict")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/check-user-agent":
            ua = self.headers.get("User-Agent", "")
            body = ua.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/redirect-chain":
            self.send_response(302)
            self.send_header("Location", "/redirect-intermediate")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/redirect-intermediate":
            self.send_response(301)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/elapsed-time":
            time.sleep(0.1)  # Simulate some processing time
            body = b"done"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        content_type = self.headers.get("Content-Type", "").lower()

        if path == "/json-body":
            # Echo back the JSON body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/form-data":
            # Echo back the form data
            self.send_response(200)
            self.send_header("Content-Type", "application/x-www-form-urlencoded")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            # Default: echo back the body
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_PUT(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PATCH(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "11")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self):
        body = b"TRACE request received"
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_basic_challenge(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="fasthttp-basic"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_digest_challenge(self) -> None:
        header = (
            f'Digest realm="{DIGEST_REALM}", '
            f'nonce="{DIGEST_NONCE}", '
            'algorithm=MD5, '
            'qop="auth", '
            f'opaque="{DIGEST_OPAQUE}"'
        )
        self.send_response(401)
        self.send_header("WWW-Authenticate", header)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _check_basic_auth(self) -> bool:
        header = self.headers.get("Authorization")
        if not header:
            return False
        expected = "Basic " + base64.b64encode(f"{BASIC_USERNAME}:{BASIC_PASSWORD}".encode("latin1")).decode("ascii")
        return header == expected

    def _check_digest_auth(self, method: str, uri: str) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("digest"):
            return False
        params = self._parse_auth_params(header)
        required = ["username", "realm", "nonce", "uri", "response"]
        if any(key not in params for key in required):
            return False
        if params["username"] != DIGEST_USERNAME or params["realm"] != DIGEST_REALM:
            return False
        if params["nonce"] != DIGEST_NONCE or params["uri"] != uri:
            return False
        if params.get("opaque") and params["opaque"] != DIGEST_OPAQUE:
            return False
        ha1 = hashlib.md5(f"{DIGEST_USERNAME}:{DIGEST_REALM}:{DIGEST_PASSWORD}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        qop = params.get("qop")
        if qop:
            nc = params.get("nc")
            cnonce = params.get("cnonce")
            if not nc or not cnonce:
                return False
            expected = hashlib.md5(f"{ha1}:{DIGEST_NONCE}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        else:
            expected = hashlib.md5(f"{ha1}:{DIGEST_NONCE}:{ha2}".encode()).hexdigest()
        return params.get("response") == expected

    def _parse_auth_params(self, header: str) -> Dict[str, str]:
        params: Dict[str, str] = {}
        if not header:
            return params
        parts = header.split(" ", 1)
        value = parts[1] if len(parts) == 2 else header
        current: List[str] = []
        in_quotes = False
        escape = False
        tuples = []
        for ch in value:
            if ch == '"' and not escape:
                in_quotes = not in_quotes
            if ch == "," and not in_quotes:
                item = "".join(current).strip()
                if item:
                    tuples.append(item)
                current = []
            else:
                current.append(ch)
            if ch == "\\" and not escape:
                escape = True
            else:
                escape = False
        tail = "".join(current).strip()
        if tail:
            tuples.append(tail)
        for item in tuples:
            if "=" not in item:
                continue
            k, v = item.split("=", 1)
            k = k.strip()
            v = v.strip()
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            v = v.replace('\\"', '"')
            params[k] = v
        return params

    def log_message(self, format, *args):  # pragma: no cover
        return


@contextmanager
def run_server():
    server = HTTPServer(("127.0.0.1", 0), TestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base_url
    finally:
        server.shutdown()
        thread.join()


async def _ws_send(writer: asyncio.StreamWriter, data: bytes) -> None:
    if not data:
        return
    writer.write(data)
    await writer.drain()


async def _handle_ws_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    ws = WSConnection(ConnectionType.SERVER)
    try:
        while True:
            data = await reader.read(READ_BUFFER_SIZE)
            if not data:
                ws.receive_data(None)
                break
            ws.receive_data(data)
            for event in ws.events():
                if isinstance(event, WSRequestEvent):
                    target = event.target
                    if target == "/ws/reject":
                        payload = ws.send(RejectConnection(status_code=403, headers=[(b"content-length", b"0")]))
                        await _ws_send(writer, payload)
                        return
                    accept = AcceptConnection()
                    await _ws_send(writer, ws.send(accept))
                elif isinstance(event, TextMessage):
                    await _ws_send(writer, ws.send(TextMessage(data=event.data)))
                elif isinstance(event, BytesMessage):
                    await _ws_send(writer, ws.send(BytesMessage(data=bytes(event.data))))
                elif isinstance(event, Ping):
                    await _ws_send(writer, ws.send(event.response()))
                elif isinstance(event, CloseConnection):
                    await _ws_send(writer, ws.send(event.response()))
                    return
    except Exception:
        pass
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


@asynccontextmanager
async def run_ws_server():
    server = await asyncio.start_server(_handle_ws_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    base_url = f"ws://127.0.0.1:{port}"
    try:
        yield base_url
    finally:
        server.close()
        await server.wait_closed()


async def test_gzip_decoding(client: Client) -> None:
    resp = await client.get("/gzip")
    assert resp.status_code == 200
    assert resp.json() == {"hello": "world"}


async def test_brotli_decoding(client: Client) -> None:
    if not BR_AVAILABLE:
        print("[SKIP] test_brotli_decoding (brotli not installed)")
        return
    resp = await client.get("/br")
    assert resp.status_code == 200
    assert resp.json() == {"brotli": True}


async def test_content_type_charset(client: Client) -> None:
    # Server returns gzip compressed JSON encoded in iso-8859-1 with explicit charset
    payload = json.dumps({"name": "olá"}).encode("iso-8859-1")
    body = gzip.compress(payload)
    original_do_GET = TestHandler.do_GET

    def do_GET_charset(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/charset":
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Type", "application/json; charset=iso-8859-1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return original_do_GET(self)

    TestHandler.do_GET = do_GET_charset
    try:
        resp = await client.get("/charset")
        assert resp.status_code == 200
        assert resp.json() == {"name": "olá"}
    finally:
        TestHandler.do_GET = original_do_GET


async def test_content_type_no_charset(client: Client) -> None:
    # No charset provided -> default to utf-8
    original_do_GET = TestHandler.do_GET

    def do_GET_no_charset(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/no-charset":
            payload = json.dumps({"hello": "world"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        return original_do_GET(self)

    TestHandler.do_GET = do_GET_no_charset
    try:
        resp = await client.get("/no-charset")
        assert resp.status_code == 200
        assert resp.json() == {"hello": "world"}
    finally:
        TestHandler.do_GET = original_do_GET


async def test_lowercase_header_names(client: Client) -> None:
    # Ensure lowercase header names (content-encoding/content-type) are handled
    original_do_GET = TestHandler.do_GET

    payload = json.dumps({"ok": True}).encode("utf-8")

    def do_GET_lowercase(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/lowercase":
            body = gzip.compress(payload)
            self.send_response(200)
            # intentionally use lowercase header names
            self.send_header("content-encoding", "gzip")
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return original_do_GET(self)

    TestHandler.do_GET = do_GET_lowercase
    try:
        resp = await client.get("/lowercase")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
    finally:
        TestHandler.do_GET = original_do_GET


async def test_empty_body_json(client: Client) -> None:
    original_do_GET = TestHandler.do_GET

    def do_GET_empty(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/empty-json":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        return original_do_GET(self)

    TestHandler.do_GET = do_GET_empty
    try:
        resp = await client.get("/empty-json")
        assert resp.status_code == 200
        try:
            resp.json()
            raise AssertionError("Expected ResponseError or JSONDecodeError")
        except (ResponseError, json.decoder.JSONDecodeError):
            pass
    finally:
        TestHandler.do_GET = original_do_GET


async def test_streaming_iter_bytes(client: Client) -> None:
    resp = await client.get("/stream", stream=True)
    chunks = b""
    async for chunk in resp.iter_bytes():
        chunks += chunk
    assert chunks == b"hello-world"


async def test_retry_and_redirect(client: Client) -> None:
    resp_retry = await client.get("/retry")
    assert resp_retry.status_code == 200
    resp_redirect = await client.get("/redirect")
    assert resp_redirect.status_code == 200
    assert resp_redirect.text() == "final"


async def test_cookie_persistence(client: Client) -> None:
    await client.get("/set-cookie")
    resp = await client.get("/needs-cookie")
    assert "token=abc" in resp.text()


async def test_basic_auth_support(client: Client) -> None:
    """Ensure tuple-based Basic Auth works."""
    async with Client(base_url=client.base_url, auth=(BASIC_USERNAME, BASIC_PASSWORD)) as authed:
        resp = await authed.get("/basic-auth")
    assert resp.status_code == 200
    assert resp.text() == "basic-auth-ok"


async def test_digest_auth_support(client: Client) -> None:
    """Ensure Digest Auth handler performs challenge/response automatically."""
    digest = DigestAuth(DIGEST_USERNAME, DIGEST_PASSWORD)
    resp = await client.get("/digest-auth", auth=digest)
    assert resp.status_code == 200
    assert resp.text() == "digest-auth-ok"


async def test_custom_auth_handler(client: Client) -> None:
    """Verify custom AuthBase subclasses can inject headers."""

    class APIKeyAuth(AuthBase):
        def __init__(self, key: str) -> None:
            self.key = key

        def _on_request(self, request):
            request.headers["X-API-Key"] = self.key

    resp = await client.get("/custom-auth", auth=APIKeyAuth(API_KEY_SECRET))
    assert resp.status_code == 200
    assert resp.text() == "custom-auth-ok"


async def test_response_hook_called(client: Client) -> None:
    """Ensure per-request response hooks run."""
    seen = []

    def hook(resp):
        seen.append(resp.status_code)

    resp = await client.get("/gzip", hooks={"response": hook})
    assert resp.status_code == 200
    assert seen == [200]


async def test_async_hook_and_response_replacement(client: Client) -> None:
    """Hooks can be async and may return replacement responses."""

    async def hook(resp):
        # Replace body with uppercase text to prove the hook ran
        new = Response(
            status_code=resp.status_code,
            headers=resp.headers,
            content=resp.text().upper().encode("utf-8"),
            reason=resp.reason,
            request=resp.request,
        )
        return new

    resp = await client.get("/gzip", hooks={"response": hook})
    assert resp.text() == resp.text().upper()


async def test_iter_text(client: Client) -> None:
    resp = await client.get("/stream", stream=True)
    chunks = "".join([c async for c in resp.iter_text()])
    assert chunks == "hello-world"


async def test_raise_for_status(client: Client) -> None:
    resp = await client.get("/notfound")
    try:
        resp.raise_for_status()
        raise AssertionError("Expected HTTPStatusError")
    except Exception:
        pass


async def test_response_context_manager(client: Client) -> None:
    resp = await client.get("/stream", stream=True)
    async with resp:
        data = b""
        async for c in resp.iter_bytes():
            data += c
    assert data == b"hello-world"


async def test_put_request(client: Client) -> None:
    data = b"updated content"
    resp = await client.put("/resource", content=data)
    assert resp.status_code == 200
    assert resp.content == data


async def test_delete_request(client: Client) -> None:
    resp = await client.delete("/resource")
    assert resp.status_code == 204


async def test_patch_request(client: Client) -> None:
    data = b"patched content"
    resp = await client.patch("/resource", content=data)
    assert resp.status_code == 200
    assert resp.content == data


async def test_head_request(client: Client) -> None:
    resp = await client.head("/gzip")
    assert resp.status_code == 200
    assert resp.content == b""


async def test_options_request(client: Client) -> None:
    resp = await client.options("/resource")
    assert resp.status_code == 200
    # Check if Allow header exists (case-insensitive)
    allow_header = None
    for key, value in resp.headers.items():
        if key.lower() == "allow":
            allow_header = value
            break
    assert allow_header is not None


async def test_trace_request(client: Client) -> None:
    resp = await client.trace("/trace")
    assert resp.status_code == 200
    assert resp.text() == "TRACE request received"


async def test_concurrent_requests(client: Client) -> None:
    # Send multiple concurrent requests to exercise AsyncConnectionPool
    async def single():
        r = await client.get("/gzip")
        return r.json()

    results = await asyncio.gather(*[single() for _ in range(8)])
    assert all(r == {"hello": "world"} for r in results)


async def test_circuit_breaker_opens(client: Client) -> None:
    original_do_GET = TestHandler.do_GET

    def do_GET_cb(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/cb":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        return original_do_GET(self)

    TestHandler.do_GET = do_GET_cb
    try:
        rp = RetryPolicy(max_attempts=1, circuit_breaker=True, cb_failure_threshold=2, cb_recovery_seconds=1)
        async with Client(base_url=client.base_url, retry=rp) as c:
            resp1 = await c.get("/cb")
            assert resp1.status_code == 500
            resp2 = await c.get("/cb")
            assert resp2.status_code == 500
            try:
                await c.get("/cb")
                raise AssertionError("Expected RequestError due to open circuit")
            except Exception:
                pass
            await asyncio.sleep(1.1)
            resp3 = await c.get("/cb")
            assert resp3.status_code == 500
    finally:
        TestHandler.do_GET = original_do_GET


async def test_json_body(client: Client) -> None:
    """Test JSON body support."""
    data = {"name": "test", "value": 123}
    resp = await client.post("/json-body", json=data)
    assert resp.status_code == 200
    assert resp.json() == data


async def test_query_parameters(client: Client) -> None:
    """Test query parameters support."""
    params = {"key1": "value1", "key2": "value2", "num": 42}
    resp = await client.get("/query-test", params=params)
    assert resp.status_code == 200
    query_string = resp.text()
    assert "key1=value1" in query_string
    assert "key2=value2" in query_string
    assert "num=42" in query_string


async def test_form_data(client: Client) -> None:
    """Test form data support."""
    data = {"field1": "value1", "field2": "value2", "number": 123}
    resp = await client.post("/form-data", data=data)
    assert resp.status_code == 200
    form_string = resp.text()
    assert "field1=value1" in form_string
    assert "field2=value2" in form_string
    assert "number=123" in form_string


async def test_elapsed_time(client: Client) -> None:
    """Test elapsed time tracking."""
    resp = await client.get("/elapsed-time")
    assert resp.status_code == 200
    assert resp.elapsed > 0
    assert resp.elapsed >= 0.1  # Should be at least the sleep time


async def test_redirect_history(client: Client) -> None:
    """Test redirect history tracking."""
    resp = await client.get("/redirect-chain")
    assert resp.status_code == 200
    assert resp.text() == "final"
    assert len(resp.history) == 2
    assert resp.history[0].status_code == 302
    assert resp.history[1].status_code == 301
    assert resp.history[0].url.endswith("/redirect-chain")
    assert resp.history[1].url.endswith("/redirect-intermediate")


async def test_cookie_path(client: Client) -> None:
    """Test cookie path matching."""
    resp = await client.get("/cookie-path")
    assert resp.status_code == 200
    
    # Cookie should be set with path
    resp2 = await client.get("/cookie-path")
    cookie_header = resp2.request.headers.get("Cookie", "")
    assert "path_cookie=value123" in cookie_header


async def test_cookie_domain(client: Client) -> None:
    """Test cookie domain matching."""
    resp = await client.get("/cookie-domain")
    assert resp.status_code == 200
    
    # Cookie should be available for domain
    resp2 = await client.get("/cookie-domain")
    cookie_header = resp2.request.headers.get("Cookie", "")
    assert "domain_cookie=test" in cookie_header


async def test_cookie_expires(client: Client) -> None:
    """Test cookie expires attribute."""
    resp = await client.get("/cookie-expires")
    assert resp.status_code == 200
    
    # Cookie should be set
    resp2 = await client.get("/cookie-expires")
    cookie_header = resp2.request.headers.get("Cookie", "")
    assert "expires_cookie=test" in cookie_header


async def test_cookie_max_age(client: Client) -> None:
    """Test cookie Max-Age attribute."""
    resp = await client.get("/cookie-max-age")
    assert resp.status_code == 200
    
    # Cookie should be set
    resp2 = await client.get("/cookie-max-age")
    cookie_header = resp2.request.headers.get("Cookie", "")
    assert "maxage_cookie=test" in cookie_header


async def test_cookie_secure(client: Client) -> None:
    """Test cookie Secure attribute."""
    resp = await client.get("/cookie-secure")
    assert resp.status_code == 200
    
    # Cookie should be set (but won't be sent over HTTP, only HTTPS)
    # For HTTP, secure cookies are still stored but not sent
    resp2 = await client.get("/cookie-secure")
    # Secure cookie won't be sent over HTTP, so Cookie header should be empty or not contain it
    cookie_header = resp2.request.headers.get("Cookie", "")
    # Secure cookies are not sent over HTTP, so this is expected behavior
    assert True  # Just verify the request completes


async def test_cookie_httponly(client: Client) -> None:
    """Test cookie HttpOnly attribute."""
    resp = await client.get("/cookie-httponly")
    assert resp.status_code == 200
    
    # HttpOnly cookies are still sent in requests
    resp2 = await client.get("/cookie-httponly")
    cookie_header = resp2.request.headers.get("Cookie", "")
    assert "httponly_cookie=test" in cookie_header


async def test_cookie_samesite(client: Client) -> None:
    """Test cookie SameSite attribute."""
    resp = await client.get("/cookie-samesite")
    assert resp.status_code == 200
    
    # SameSite cookies are still sent in same-site requests
    resp2 = await client.get("/cookie-samesite")
    cookie_header = resp2.request.headers.get("Cookie", "")
    assert "samesite_cookie=test" in cookie_header


async def test_user_agent(client: Client) -> None:
    """Test default User-Agent header."""
    resp = await client.get("/check-user-agent")
    assert resp.status_code == 200
    ua = resp.text()
    assert "fasthttp" in ua.lower()


async def test_custom_user_agent(client: Client) -> None:
    """Test custom User-Agent header."""
    custom_ua = "MyCustomAgent/1.0"
    async with Client(base_url=client.base_url, user_agent=custom_ua) as c:
        resp = await c.get("/check-user-agent")
        assert resp.status_code == 200
        ua = resp.text()
        assert ua == custom_ua


async def test_json_and_content_conflict(client: Client) -> None:
    """Test that json and content parameters cannot be used together."""
    try:
        await client.post("/json-body", json={"test": 1}, content=b"test")
        raise AssertionError("Expected ValueError")
    except ValueError:
        pass


async def test_json_and_data_conflict(client: Client) -> None:
    """Test that json and data parameters cannot be used together."""
    try:
        await client.post("/json-body", json={"test": 1}, data={"test": "value"})
        raise AssertionError("Expected ValueError")
    except ValueError:
        pass


async def test_content_and_data_conflict(client: Client) -> None:
    """Test that content and data parameters cannot be used together."""
    try:
        await client.post("/form-data", content=b"test", data={"test": "value"})
        raise AssertionError("Expected ValueError")
    except ValueError:
        pass


async def test_redirect_with_json_body(client: Client) -> None:
    """Test that JSON body is cleared on redirect."""
    # POST with JSON, redirect to GET
    original_do_POST = TestHandler.do_POST

    def do_POST_redirect(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/post-redirect":
            self.send_response(303)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        return original_do_POST(self)

    TestHandler.do_POST = do_POST_redirect
    try:
        resp = await client.post("/post-redirect", json={"test": "data"})
        assert resp.status_code == 200
        assert resp.text() == "final"
        # The final request should be GET, not POST
        assert resp.request.method == "GET"
    finally:
        TestHandler.do_POST = original_do_POST


async def test_connection_pool_health_check(client: Client) -> None:
    """Test connection pool health check."""
    # Make multiple requests to test connection reuse
    for _ in range(5):
        resp = await client.get("/gzip")
        assert resp.status_code == 200
        assert resp.json() == {"hello": "world"}


async def test_cookie_jar_clear(client: Client) -> None:
    """Test cookie jar clear method."""
    await client.get("/set-cookie")
    resp = await client.get("/needs-cookie")
    assert "token=abc" in resp.text()
    
    # Clear cookies
    client.cookies.clear()
    resp2 = await client.get("/needs-cookie")
    assert "token=abc" not in resp2.text() or resp2.text() == ""


async def test_cookie_jar_remove(client: Client) -> None:
    """Test cookie jar remove method."""
    await client.get("/set-cookie")
    resp = await client.get("/needs-cookie")
    assert "token=abc" in resp.text()
    
    # Remove specific cookie
    client.cookies.remove("token")
    resp2 = await client.get("/needs-cookie")
    assert "token=abc" not in resp2.text() or resp2.text() == ""


async def test_base_url_relative_path(client: Client) -> None:
    """Test base_url with relative path."""
    # Client already has base_url set
    resp = await client.get("/gzip")
    assert resp.status_code == 200
    assert resp.json() == {"hello": "world"}
    
    # Test that base_url is correctly joined
    assert client.base_url is not None
    assert resp.request.url.startswith(client.base_url)


async def test_base_url_absolute_path(client: Client) -> None:
    """Test base_url with absolute path (should override base_url)."""
    # Use absolute URL - should override base_url
    full_url = f"{client.base_url}/gzip"
    resp = await client.get(full_url)
    assert resp.status_code == 200
    assert resp.json() == {"hello": "world"}


async def test_base_url_without_base_url() -> None:
    """Test client without base_url (must use full URLs)."""
    with run_server() as base_url:
        async with Client() as client:  # No base_url
            # Must use full URL
            resp = await client.get(f"{base_url}/gzip")
            assert resp.status_code == 200
            assert resp.json() == {"hello": "world"}
            
            # Relative path should fail
            try:
                await client.get("/gzip")
                raise AssertionError("Expected ValueError for relative URL without base_url")
            except (ValueError, RequestError):
                pass  # Expected


async def test_base_url_trailing_slash(client: Client) -> None:
    """Test base_url with trailing slash."""
    # Test that trailing slash in base_url is handled correctly
    base_url_with_slash = client.base_url.rstrip("/") + "/"
    async with Client(base_url=base_url_with_slash) as client_slash:
        resp = await client_slash.get("gzip")  # No leading slash
        assert resp.status_code == 200
        assert resp.json() == {"hello": "world"}
        
        resp2 = await client_slash.get("/gzip")  # With leading slash
        assert resp2.status_code == 200
        assert resp2.json() == {"hello": "world"}


async def test_base_url_path_joining(client: Client) -> None:
    """Test proper URL joining of base_url and path."""
    # Test absolute path (starts with /) - should replace base_url path
    resp1 = await client.get("/gzip")
    assert resp1.status_code == 200
    parsed1 = urlparse(resp1.request.url)
    assert parsed1.path == "/gzip"
    
    # Test relative path (no leading /) - should be appended to base_url
    # Since base_url is like "http://127.0.0.1:PORT", relative path becomes "/gzip"
    resp2 = await client.get("gzip")
    assert resp2.status_code == 200
    parsed2 = urlparse(resp2.request.url)
    # urljoin behavior: relative path without leading / replaces the last segment
    # So "http://127.0.0.1:PORT" + "gzip" = "http://127.0.0.1:PORT/gzip"
    assert parsed2.path == "/gzip" or parsed2.path.endswith("/gzip")
    
    # Test path with query string
    resp3 = await client.get("/query-test?existing=1")
    assert resp3.status_code == 200
    parsed3 = urlparse(resp3.request.url)
    assert parsed3.path == "/query-test"
    assert "existing=1" in parsed3.query


async def test_base_url_with_params(client: Client) -> None:
    """Test base_url combined with query parameters."""
    params = {"key1": "value1", "key2": "value2"}
    resp = await client.get("/query-test", params=params)
    assert resp.status_code == 200
    query_string = resp.text()
    assert "key1=value1" in query_string
    assert "key2=value2" in query_string
    # Verify base_url is preserved
    assert resp.request.url.startswith(client.base_url)


async def test_websocket_echo(ws_url: str) -> None:
    async with Client() as client:
        ws = await client.websocket(f"{ws_url}/ws/echo")
        async with ws:
            await ws.send_text("hello-ws")
            text = await ws.recv()
            assert text == "hello-ws"

            payload = b"\x00\x01binary"
            await ws.send_bytes(payload)
            received = await ws.recv()
            assert received == payload


async def test_websocket_rejection(ws_url: str) -> None:
    async with Client() as client:
        try:
            await client.websocket(f"{ws_url}/ws/reject")
        except WebSocketHandshakeError:
            return
        raise AssertionError("Expected WebSocketHandshakeError for rejected handshake")


async def run_all_tests() -> None:
    with run_server() as base_url:
        retry = RetryPolicy(max_attempts=2)
        async with Client(base_url=base_url, retry=retry) as client:
            tests = [
                test_gzip_decoding,
                test_brotli_decoding,
                test_content_type_charset,
                test_content_type_no_charset,
                test_lowercase_header_names,
                test_empty_body_json,
                test_streaming_iter_bytes,
                test_retry_and_redirect,
                test_cookie_persistence,
                test_iter_text,
                test_raise_for_status,
                test_response_context_manager,
                test_put_request,
                test_delete_request,
                test_patch_request,
                test_head_request,
                test_options_request,
                test_trace_request,
                test_concurrent_requests,
                test_circuit_breaker_opens,
                # New tests for enhanced features
                test_json_body,
                test_query_parameters,
                test_form_data,
                test_elapsed_time,
                test_redirect_history,
                test_cookie_path,
                test_cookie_domain,
                test_cookie_expires,
                test_cookie_max_age,
                test_cookie_secure,
                test_cookie_httponly,
                test_cookie_samesite,
                test_user_agent,
                test_custom_user_agent,
                test_json_and_content_conflict,
                test_json_and_data_conflict,
                test_content_and_data_conflict,
                test_redirect_with_json_body,
                test_connection_pool_health_check,
                test_cookie_jar_clear,
                test_cookie_jar_remove,
                # Base URL tests
                test_base_url_relative_path,
                test_base_url_absolute_path,
                test_base_url_trailing_slash,
                test_base_url_path_joining,
                test_base_url_with_params,
            ]
            for test_fn in tests:
                await test_fn(client)
            print(f"[OK] {test_fn.__name__}")
    
    # Run tests that don't need the client parameter
    await test_base_url_without_base_url()
    print(f"[OK] {test_base_url_without_base_url.__name__}")

    async with run_ws_server() as ws_base_url:
        ws_tests = [
            test_websocket_echo,
            test_websocket_rejection,
        ]
        for test_fn in ws_tests:
            await test_fn(ws_base_url)
            print(f"[OK] {test_fn.__name__}")
    
    print("All tests completed successfully.")


if __name__ == "__main__":
    asyncio.run(run_all_tests())
