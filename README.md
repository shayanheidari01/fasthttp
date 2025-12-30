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
- [Advanced Usage](#advanced-usage)
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
- **Streaming Support**: Stream large responses without loading everything into memory
- **JSON Handling**: Automatic JSON decoding with charset and compression support
- **Timeout Management**: Flexible timeout configuration for connections and reads
- **Retry & Backoff**: Configurable retry policies with exponential backoff
- **Circuit Breaker**: Optional circuit breaker pattern to prevent cascading failures
- **Cookie Management**: Full cookie jar support
- **HTTP/1.1 Compliant**: Properly implements the HTTP/1.1 specification
- **Lightweight**: Minimal dependencies, built on the `h11` library

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

## Advanced Usage

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
