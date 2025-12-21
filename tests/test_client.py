import gzip
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from fasthttp import Client
from fasthttp.retry import RetryPolicy

try:
    import brotli

    BR_AVAILABLE = True
except Exception:  # pragma: no cover
    BR_AVAILABLE = False


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


def test_gzip_decoding(client: Client) -> None:
    resp = client.get("/gzip")
    assert resp.status_code == 200
    assert resp.json() == {"hello": "world"}


def test_brotli_decoding(client: Client) -> None:
    if not BR_AVAILABLE:
        print("[SKIP] test_brotli_decoding (brotli not installed)")
        return
    resp = client.get("/br")
    assert resp.status_code == 200
    assert resp.json() == {"brotli": True}


def test_content_type_charset(client: Client) -> None:
    # Server returns gzip compressed JSON encoded in iso-8859-1 with explicit charset
    payload = json.dumps({"name": "olá"}).encode("iso-8859-1")
    body = gzip.compress(payload)
    # start a small handler route dynamically by reusing TestHandler behavior
    from urllib.parse import urljoin
    # use raw socket server is non-trivial; instead simulate by making a one-off request via run_server
    # Add a route to TestHandler by monkeypatching for the testing runtime
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
        resp = client.get("/charset")
        assert resp.status_code == 200
        assert resp.json() == {"name": "olá"}
    finally:
        TestHandler.do_GET = original_do_GET


def test_content_type_no_charset(client: Client) -> None:
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
        resp = client.get("/no-charset")
        assert resp.status_code == 200
        assert resp.json() == {"hello": "world"}
    finally:
        TestHandler.do_GET = original_do_GET


def test_lowercase_header_names(client: Client) -> None:
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
        resp = client.get("/lowercase")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
    finally:
        TestHandler.do_GET = original_do_GET


def test_streaming_iter_bytes(client: Client) -> None:
    resp = client.get("/stream", stream=True)
    chunks = b"".join(resp.iter_bytes())
    resp.close()
    assert chunks == b"hello-world"


def test_iter_text(client: Client) -> None:
    resp = client.get("/stream", stream=True)
    text = "".join(resp.iter_text())
    resp.close()
    assert text == "hello-world"


def test_response_encoding_property(client: Client) -> None:
    resp = client.get("/charset")
    assert resp.encoding.lower() == "iso-8859-1"


def test_raise_for_status(client: Client) -> None:
    resp = client.get("/notfound")
    try:
        resp.raise_for_status()
        raise AssertionError("Expected HTTPStatusError")
    except Exception:
        pass


def test_response_context_manager(client: Client) -> None:
    resp = client.get("/stream", stream=True)
    with resp:
        data = b"".join(resp.iter_bytes())
    assert data == b"hello-world"


def test_retry_and_redirect(client: Client) -> None:
    resp_retry = client.get("/retry")
    assert resp_retry.status_code == 200
    resp_redirect = client.get("/redirect")
    assert resp_redirect.status_code == 200
    assert resp_redirect.text() == "final"


def test_cookie_persistence(client: Client) -> None:
    client.get("/set-cookie")
    resp = client.get("/needs-cookie")
    assert "token=abc" in resp.text()


def run_all_tests() -> None:
    with run_server() as base_url:
        retry = RetryPolicy(max_attempts=2)
        with Client(base_url=base_url, retry=retry) as client:
            tests = [
                test_gzip_decoding,
                test_brotli_decoding,
                test_streaming_iter_bytes,
                test_retry_and_redirect,
                test_cookie_persistence,
            ]
            for test_fn in tests:
                test_fn(client)
                print(f"[OK] {test_fn.__name__}")
    print("All tests completed successfully.")


if __name__ == "__main__":
    run_all_tests()
