# fasthttp

A small, fast, and extensible HTTP/1.1 client library with both synchronous and asynchronous APIs, connection pooling, streaming support, retry/backoff, and automatic decoding of compressed responses.

[![PyPI version](https://badge.fury.io/py/pyfasthttp.svg)](https://badge.fury.io/py/pyfasthttp)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python Version](https://img.shields.io/pypi/pyversions/pyfasthttp.svg)](https://pypi.org/project/pyfasthttp/)

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Client](#client)
  - [Request](#request)
  - [Response](#response)
  - [Timeouts](#timeouts)
  - [Retry Policy](#retry-policy)
  - [Cookies](#cookies)
- [WebSocket Client](#websocket-client)
- [Advanced Usage](#advanced-usage)
- [File Uploads](#file-uploads)
- [Synchronous Wrapper](#synchronous-wrapper)
- [Error Handling](#error-handling)
- [Benchmarks](#benchmarks)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Sync & Async Support**: Single API that can work synchronously or asynchronously
- **Connection Pooling**: Efficient connection reuse to improve throughput
- **Automatic Compression**: Built-in support for gzip and optional brotli (`br`) compression
- **Multipart Uploads**: Stream-friendly file upload helper with automatic boundary/content-type handling
- **Streaming Support**: Stream large responses without loading everything into memory
- **JSON Handling**: Automatic JSON decoding with charset and compression support
- **Timeout Management**: Flexible timeout configuration for connections and reads
- **Retry & Backoff**: Configurable retry policies with exponential backoff
- **Circuit Breaker**: Optional circuit breaker pattern to prevent cascading failures
- **Cookie Management**: Full cookie jar support
- **HTTP/1.1 Compliant**: Properly implements the HTTP/1.1 specification
- **Optional HTTP/2**: Seamlessly upgrade HTTPS requests to HTTP/2 when the server supports ALPN, with automatic fallback to HTTP/1.1
- **Lightweight**: Minimal dependencies, built on the `h11pro` library

## Installation

Install using pip:

```bash
pip install pyfasthttp
```

For development with all optional dependencies:

```bash
pip install -e .[dev]
```

Note: Brotli (`br`) support is optional and available via the `brotli` package (included in the `dev` extras). Install with `pip install brotli` for brotli compression support.

## Quick Start

### Synchronous Usage

```python
from fasthttp import Client
from fasthttp.timeouts import Timeout

# Basic GET request
with Client() as client:
    resp = client.get("https://httpbin.org/get")
    print(f"Status: {resp.status_code}")
    print(f"Response: {resp.json()}")

# With custom timeout
with Client(timeout=Timeout(connect=5, read=10)) as client:
    resp = client.get("https://httpbin.org/get")
    print(resp.json())
```

### Asynchronous Usage

```python
import asyncio
from fasthttp import Client
from fasthttp.timeouts import Timeout

async def main():
    # Basic async request
    async with Client() as client:
        resp = await client.get("https://httpbin.org/get")
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.json()}")
    
    # With custom timeout
    async with Client(timeout=Timeout(connect=5, read=10)) as client:
        resp = await client.get("https://httpbin.org/get")
        print(resp.json())

asyncio.run(main())
```

## API Reference

### Client

The `Client` class provides an asynchronous HTTP client with connection pooling that can be used either synchronously or asynchronously. When used directly, it requires async/await syntax.

```python
from fasthttp import Client

# Basic client
with Client() as client:
    response = client.get("https://api.example.com/users")

# Client with base URL
with Client(base_url="https://api.example.com") as client:
    response = client.get("/users")  # Will make request to https://api.example.com/users

# Client with custom timeout
from fasthttp.timeouts import Timeout
with Client(timeout=Timeout(connect=5, read=10, total=30)) as client:
    response = client.get("https://api.example.com/users")
```

#### Client Methods:
- `get(url, **kwargs)` - Send a GET request (async by default)
- `post(url, **kwargs)` - Send a POST request (async by default)
- `put(url, **kwargs)` - Send a PUT request (async by default)
- `patch(url, **kwargs)` - Send a PATCH request (async by default)
- `delete(url, **kwargs)` - Send a DELETE request (async by default)
- `head(url, **kwargs)` - Send a HEAD request (async by default)
- `options(url, **kwargs)` - Send an OPTIONS request (async by default)
- `request(method, url, **kwargs)` - Send a custom method request (async by default)


### Request

The `Request` class represents an HTTP request.

```python
from fasthttp import Request

# Create a request object
request = Request(
    method="GET",
    url="https://api.example.com/users",
    headers={"Authorization": "Bearer token"},
    params={"page": 1, "limit": 10},
    data={"key": "value"}
)
```

### Response

The `Response` class represents an HTTP response.

```python
from fasthttp import Client

with Client() as client:
    resp = client.get("https://httpbin.org/json")
    
    # Access response properties
    print(f"Status: {resp.status_code}")
    print(f"Headers: {resp.headers}")
    print(f"Text: {resp.text()}")
    print(f"JSON: {resp.json()}")
    
    # Check status
    resp.raise_for_status()  # Raises an exception for 4xx/5xx responses
```

#### Response Properties:
- `status_code` - HTTP status code
- `headers` - Response headers
- `content` - Raw response content as bytes
- `encoding` - Response encoding

#### Response Methods:
- `text()` - Get response as text string
- `json()` - Parse response as JSON
- `raise_for_status()` - Raise an exception for error status codes
- `iter_bytes()` - Iterate over response content in chunks (sync)
- `aiter_bytes()` - Asynchronously iterate over response content in chunks
- `iter_text()` - Iterate over response content as text chunks (sync)
- `aiter_text()` - Asynchronously iterate over response content as text chunks

### Timeouts

Configure connection, read, and total timeouts.

```python
from fasthttp.timeouts import Timeout

# Different timeout configurations
no_timeout = Timeout()  # No timeouts
connect_timeout = Timeout(connect=5)  # 5 seconds to connect
read_timeout = Timeout(read=10)  # 10 seconds to read
full_timeout = Timeout(connect=5, read=10, total=30)  # Full configuration
```

### Retry Policy

Configure retry behavior with optional circuit breaker.

```python
from fasthttp import Client
from fasthttp.retry import RetryPolicy

# Basic retry policy
retry_policy = RetryPolicy(max_attempts=3)

# Advanced retry policy with circuit breaker
retry_policy = RetryPolicy(
    max_attempts=5,
    backoff_factor=0.5,
    status_codes=[500, 502, 503, 504],
    circuit_breaker=True,
    cb_failure_threshold=3,
    cb_recovery_seconds=60
)

with Client(retry=retry_policy) as client:
    resp = client.get("https://api.example.com/resource")
```

#### Retry Policy Parameters:
- `max_attempts` - Maximum number of attempts (including the initial request)
- `backoff_factor` - Factor for exponential backoff between retries
- `status_codes` - List of HTTP status codes that should trigger a retry
- `circuit_breaker` - Whether to enable the circuit breaker
- `cb_failure_threshold` - Number of failures before opening the circuit
- `cb_recovery_seconds` - Seconds to wait before attempting to close the circuit

### Cookies

Manage cookies with the `CookieJar`.

```python
from fasthttp import Client
from fasthttp.cookies import CookieJar

# Create a cookie jar
jar = CookieJar()
jar.set("session_id", "abc123", domain="example.com", path="/", secure=True)

with Client(cookies=jar) as client:
    resp = client.get("https://example.com/protected")
```

## WebSocket Client

fasthttp ships with a lightweight WebSocket client powered by [wsproto](https://github.com/python-hyper/wsproto). It integrates with the HTTP client's timeout settings, supports the async context-manager pattern, and offers helpers for text, binary, and JSON payloads.

### Quick example

```python
import asyncio
from fasthttp import WebSocket

async def main():
    async with WebSocket.connect("wss://echo.websocket.org") as ws:
        await ws.send_text("hello")
        print("Text echo:", await ws.recv_text())

        await ws.send_bytes(b"\x00\x01")
        print("Binary echo:", await ws.recv_bytes())

        await ws.send_json({"ping": True})
        try:
            print("JSON echo:", await ws.recv_json())
        except WebSocketDecodeError:
            print("Peer did not return JSON.")

asyncio.run(main())
```

### API overview

| Method | Description |
| ------ | ----------- |
| `WebSocket.connect(url, *, headers=None, subprotocols=None, extensions=None, timeout=None, verify=True, ssl_context=None)` | Returns an awaitable/context-manager connector that establishes the WebSocket handshake. |
| `send_text(str, *, final=True)` / `send_bytes(bytes, *, final=True)` / `send_json(obj, *, dumps=None)` | Send text, binary, or JSON frames. |
| `recv()` | Receive the next complete message (returns `str` for text, `bytes` for binary). |
| `recv_text()` / `recv_bytes()` / `recv_json(*, loads=None)` | Typed helpers that validate the payload and raise `WebSocketMessageTypeError` or `WebSocketDecodeError` when the data does not match expectations. |
| `ping(payload=b"")` / `close(code=1000, reason=None)` | Control frames and graceful shutdown. |
| `async for message in ws:` | Iterate over messages until the connection closes. |

### Using through `Client`

The HTTP client exposes a convenience helper that reuses shared timeout defaults and base URLs:

```python
async with Client(base_url="wss://example.org") as client:
    async with await client.websocket("/chat") as ws:
        await ws.send_text("hi!")
        async for message in ws:
            print("Incoming:", message)
```

### Error handling

WebSocket-specific exceptions live in `fasthttp.errors`:

- `WebSocketHandshakeError`: Upgrade/handshake failures.
- `WebSocketClosed`: Connection is already closed (contains `code` and `reason`).
- `WebSocketProtocolError`: Invalid URLs or protocol violations.
- `WebSocketMessageTypeError`: Payload type mismatch (e.g., expected text but received binary).
- `WebSocketDecodeError`: JSON or UTF-8 decoding failures for binary/text frames.
- `WebSocketError`: Base class for all WebSocket-related issues.

Wrap interactions with `try/except` to surface meaningful errors to your users:

```python
try:
    async with WebSocket.connect("wss://example.org/socket") as ws:
        ...
except WebSocketHandshakeError as exc:
    print("Server rejected upgrade:", exc)
except WebSocketDecodeError as exc:
    print("Bad payload:", exc)
```

## Advanced Usage

### Authentication

fasthttp ships with pluggable authentication handlers that mirror the HTTP exchanges performed by web servers.

```python
from fasthttp import Client, BasicAuth, DigestAuth, AuthBase

# 1) Basic authentication (tuple shorthand)
with Client(base_url="https://api.example.com", auth=("user", "pass")) as client:
    resp = client.get("/basic-auth")
    resp.raise_for_status()

# 2) Digest authentication
digest = DigestAuth("digest-user", "digest-pass")
with Client(base_url="https://api.example.com") as client:
    resp = client.get("/digest-endpoint", auth=digest)
    resp.raise_for_status()

# 3) Custom authentication by subclassing AuthBase
class APIKeyAuth(AuthBase):
    def __init__(self, key: str) -> None:
        self.key = key

    def _on_request(self, request):
        request.headers["X-API-Key"] = self.key

with Client(base_url="https://api.example.com") as client:
    resp = client.get("/custom-auth", auth=APIKeyAuth("my-secret"))
    resp.raise_for_status()
```

Authentication handlers receive every outgoing request (`on_request`) and can optionally inspect responses (`on_response`) to perform challenge/response flows (Digest auth does this automatically). You can pass the handler globally via `Client(..., auth=...)` or per-call via `client.get(..., auth=...)`.

#### HTTP/2 Preference & Per-Request Overrides

fasthttp can opportunistically negotiate HTTP/2 on HTTPS connections via [hyper-h2](https://python-hyper.org/projects/h2/en/stable/). Install `h2` (e.g. `pip install h2`) and set `http2=True` on the client to opt-in globally:

```python
async with Client(http2=True) as client:
    resp = await client.get("https://http2.golang.org/reqinfo")
```

You can also override the preference per request:

```python
resp = await client.get("https://example.com/data", http2=False)   # force HTTP/1.1
resp = await client.get("https://example.com/data", http2=True)    # force HTTP/2 attempt
```

If the server declines HTTP/2 during ALPN, fasthttp transparently falls back to HTTP/1.1 and retries the request.

### Response Hooks

fasthttp exposes a `hooks` argument mirroring the Requests API so you can register callbacks that observe (or replace) responses. Hooks can be provided globally when instantiating `Client` or passed for individual requests:

```python
from fasthttp import Client

def log_status(resp):
    print("Got status:", resp.status_code)

async def uppercase_hook(resp):
    # Hooks may be async and may return a replacement Response
    from fasthttp import Response
    return Response(
        status_code=resp.status_code,
        headers=resp.headers,
        content=resp.text().upper().encode("utf-8"),
        reason=resp.reason,
        request=resp.request,
    )

with Client(base_url="https://api.example.com", hooks={"response": log_status}) as client:
    resp = client.get("/resource", hooks={"response": [log_status, uppercase_hook]})
    resp.raise_for_status()
```

Hook callbacks receive the `Response` object, may be sync or async, and can return either `None` (no change) or a new `Response` instance which replaces the current one. Multiple hooks can be registered per event; `response` is currently the supported event.

### Streaming Large Responses

```python
from fasthttp import Client

with Client() as client:
    resp = client.get("https://httpbin.org/stream/20", stream=True)
    
    # Process response in chunks
    for chunk in resp.iter_bytes():
        print(f"Received chunk: {len(chunk)} bytes")
```

### Async Streaming

```python
import asyncio
from fasthttp import Client

async def stream_example():
    async with Client() as client:
        resp = await client.get("https://httpbin.org/stream/20", stream=True)
        
        # Process response in chunks
        async for chunk in resp.aiter_bytes():
            print(f"Received chunk: {len(chunk)} bytes")

asyncio.run(stream_example())
```

### Custom Headers and Parameters

```python
from fasthttp import Client

with Client() as client:
    # With custom headers and query parameters
    resp = client.get(
        "https://httpbin.org/headers",
        headers={"User-Agent": "MyApp/1.0"},
        params={"key": "value"}
    )
    print(resp.json())
```

### POST Request with Data

```python
from fasthttp import Client

with Client() as client:
    # Send JSON data
    resp = client.post(
        "https://httpbin.org/post",
        json={"key": "value"}
    )
    print(resp.json())
    
    # Send form data
    resp = client.post(
        "https://httpbin.org/post",
        data={"field": "value"}
    )
    print(resp.json())
```

### Circuit Breaker

Enable the circuit breaker to prevent cascading failures:

```python
from fasthttp import Client
from fasthttp.retry import RetryPolicy

# Configure circuit breaker
retry_policy = RetryPolicy(
    max_attempts=1,  # Only try once before circuit breaker takes over
    circuit_breaker=True,
    cb_failure_threshold=3,      # Open circuit after 3 failures
    cb_recovery_seconds=60       # Wait 60 seconds before trying again
)

with Client(base_url="https://api.example.com", retry=retry_policy) as client:
    resp = client.get("/resource")
```

## File Uploads

fasthttp natively handles multipart file uploads via the `files` argument or the standalone `MultipartEncoder`.

```python
from fasthttp import Client

async with Client(base_url="https://api.example.com") as client:
    files = {
        "avatar": ("photo.jpg", open("photo.jpg", "rb")),
        "metadata": ("meta.json", b'{"public": true}', "application/json"),
    }
    data = {"user_id": "123"}
    resp = await client.post("/upload", data=data, files=files)
    resp.raise_for_status()
```

Key details:

1. `files` accepts dictionaries or lists of `(filename, content[, content_type])` tuples. Content can be bytes, strings, paths, sync/async streams, or async iterators.
2. When `files` is provided, bodies are streamed and `Content-Length` is automatically managed (chunked transfer).
3. Use `fasthttp.formdata.MultipartEncoder` directly for custom pipelines:

```python
from fasthttp.formdata import MultipartEncoder

encoder = MultipartEncoder(
    fields={"description": "Sample upload"},
    files={"file": ("large.bin", open("large.bin", "rb"), "application/octet-stream")},
)

resp = await client.post("/upload", content=encoder.iter_bytes(), headers={
    "Content-Type": encoder.content_type,
})
```

This integration ensures efficient uploads for multi-gigabyte files without loading them entirely into memory.

## Synchronous Wrapper

The library provides a synchronous wrapper for async classes:

```python
from fasthttp import Client

# Now you can use async classes synchronously
with Client(base_url="https://api.example.com") as client:
    resp = client.get("/users")  # No await needed
    data = resp.json()
```

## Error Handling

The library provides specific exception types for different error conditions:

```python
from fasthttp import Client
from fasthttp.errors import (
    FastHTTPError,
    RequestError,
    ResponseError,
    HTTPStatusError,
    PoolError
)

with Client() as client:
    try:
        resp = client.get("https://httpbin.org/status/500")
        resp.raise_for_status()  # Raises HTTPStatusError for 5xx responses
    except HTTPStatusError as e:
        print(f"HTTP error occurred: {e}")
    except RequestError as e:
        print(f"Request error occurred: {e}")
    except FastHTTPError as e:
        print(f"General FastHTTP error occurred: {e}")
```

### Available Exceptions:
- `FastHTTPError` - Base exception class
- `RequestError` - Errors during request processing
- `ResponseError` - Errors during response processing
- `HTTPStatusError` - HTTP error status codes (4xx, 5xx)
- `PoolError` - Connection pool errors

## Benchmarks

The repository ships with a heavy-load benchmarking harness that compares fasthttp against popular Python HTTP clients under identical settings.

### How to run

```bash
python benchmark.py \
  --url https://httpbin.org/get \
  --duration 15 \
  --concurrency 64 \
  --body-size 1024 \
  --warmup 10
```

Use `--help` to discover additional flags (custom headers, TLS toggle, payload sizes, latency sampling controls, etc.). Ensure `fasthttp`, `aiohttp`, `httpx`, and `requests` are installed in the active environment.

### Latest results

_Hardware/Network_: User laptop, residential network. Results may vary with different environments, servers, or payloads.

| Library   | Requests | Success | Req/s | Avg Lat (ms) | P95 Lat (ms) | P99 Lat (ms) | Mbps |
|-----------|----------|---------|------:|-------------:|-------------:|-------------:|-----:|
| fasthttp  | 1.5K     | 1.5K    |    92 |        649.7 |       1635.6 |       2380.5 | 0.22 |
| requests  | 1.2K     | 1.2K    |    64 |        812.7 |       2653.1 |       4668.8 | 0.17 |
| aiohttp   | 1.1K     | 1.1K    |    63 |        937.2 |       2123.0 |       3039.7 | 0.16 |
| httpx     | 0.5K     | 0.5K    |    23 |       1930.9 |       3438.8 |       5803.9 | 0.06 |

Configuration: GET https://httpbin.org/get, 15s per client, concurrency=64, 1KB payload, TLS verification enabled, 10 warmup hits per client.

> **Note:** fasthttp is under active development; rerun the benchmark after significant changes or on infrastructure that matches your production constraints for more representative numbers.

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/shayanheidari01/fasthttp.git
cd fasthttp

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .[dev]
```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run tests with verbose output
python -m pytest -v

# Run specific test file
python -m pytest test.py
```

### Code Quality

The project uses `ruff` for linting and `mypy` for type checking:

```bash
# Run linter
ruff check .

# Run type checker
mypy fasthttp/
```

## Contributing

Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for detailed contribution guidelines.

## License

This project is licensed under the GNU General Public License v3 (GPLv3). See the [LICENSE](LICENSE) file for details.
