import gzip
import json
import threading
import pytest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from fasthttp import Client, AsyncClient
from fasthttp.retry import RetryPolicy


class TestHandler(BaseHTTPRequestHandler):
    retry_counter = 0

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/gzip":
            payload = json.dumps({"hello": "world"}).encode("utf-8")
            body = gzip.compress(payload)
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/br":
            try:
                import brotli  # type: ignore
                BR_AVAILABLE = True
            except Exception:  # pragma: no cover
                BR_AVAILABLE = False
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

        elif path == "/notfound":
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/cb":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

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


@pytest.fixture
def base_url():
    with run_server() as b:
        yield b


# Sync tests

def test_gzip_decoding(base_url):
    retry = RetryPolicy(max_attempts=2)
    with Client(base_url=base_url, retry=retry) as client:
        resp = client.get("/gzip")
        assert resp.status_code == 200
        assert resp.json() == {"hello": "world"}


def test_brotli_decoding(base_url):
    retry = RetryPolicy(max_attempts=2)
    with Client(base_url=base_url, retry=retry) as client:
        try:
            import brotli  # type: ignore
            BR = True
        except Exception:
            BR = False
        if not BR:
            pytest.skip("brotli not installed")
        resp = client.get("/br")
        assert resp.status_code == 200
        assert resp.json() == {"brotli": True}


def test_iter_text_and_encoding(base_url):
    retry = RetryPolicy(max_attempts=2)
    with Client(base_url=base_url, retry=retry) as client:
        resp = client.get("/stream", stream=True)
        text = "".join(resp.iter_text())
        resp.close()
        assert text == "hello-world"

        # encoding property and raise_for_status tests
        resp2 = client.get("/charset")
        assert resp2.encoding.lower() == "iso-8859-1"

        resp3 = client.get("/notfound")
        with pytest.raises(Exception):
            resp3.raise_for_status()


# Async tests

import asyncio


@pytest.mark.asyncio
async def test_async_gzip_and_stream(base_url):
    retry = RetryPolicy(max_attempts=2)
    async with AsyncClient(base_url=base_url, retry=retry) as client:
        resp = await client.get("/gzip")
        assert resp.status_code == 200
        assert resp.json() == {"hello": "world"}

        resp_s = await client.get("/stream", stream=True)
        txt = "".join([c async for c in resp_s.aiter_text()])
        assert txt == "hello-world"


@pytest.mark.asyncio
async def test_async_circuit_breaker(base_url):
    rp = RetryPolicy(max_attempts=1, circuit_breaker=True, cb_failure_threshold=2, cb_recovery_seconds=1)
    async with AsyncClient(base_url=base_url, retry=rp) as client:
        r1 = await client.get("/cb")
        assert r1.status_code == 500
        r2 = await client.get("/cb")
        assert r2.status_code == 500
        with pytest.raises(Exception):
            await client.get("/cb")
        await asyncio.sleep(1.1)
        r3 = await client.get("/cb")
        assert r3.status_code == 500
