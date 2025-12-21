# fasthttp

A small, fast, and extensible HTTP/1.1 client library with both synchronous and asynchronous APIs, connection pooling, streaming support, retry/backoff, and automatic decoding of compressed responses.

---

## Installation 🚀

```bash
# For development
pip install -e .[dev]

# Normal install (when published):
# pip install pyfasthttp
```

Note: Brotli (`br`) support is optional and available via the `brotli` package (included in the `dev` extras). Install with `pip install -e .[dev]` or `pip install brotli`.

---

## Quick Examples

### Synchronous usage

```python
from fasthttp import Client
from fasthttp.timeouts import Timeout

with Client(timeout=Timeout(connect=5, read=5)) as client:
    resp = client.get("https://httpbin.org/get")
    print(resp.status_code)
    print(resp.json())  # Decodes according to Content-Encoding and charset
```

### Asynchronous usage

```python
import asyncio
from fasthttp import AsyncClient
from fasthttp.timeouts import Timeout

async def main():
    async with AsyncClient(timeout=Timeout(connect=5, read=5)) as client:
        resp = await client.get("https://httpbin.org/get")
        print(resp.status_code)
        async for chunk in resp.aiter_bytes():
            print(chunk)

asyncio.run(main())
```

---

## Key Features ✨
- **Sync & Async**: Parallel APIs for synchronous and asynchronous usage.
- **Connection pooling** to improve throughput and reduce connection churn.
- **Streaming** support for reading chunked responses.
- **Automatic compression support**: gzip always, optional brotli (`br`) when installed.
- **Reliable JSON decoding** via `Response.json()` which handles decompression and charset decoding.
- **Retry & Backoff** policies for transient failures.
- **Circuit Breaker** (optional) to fail fast for hosts exhibiting repeated failures.

---

## Circuit Breaker 🔧
Enable the circuit breaker by configuring `RetryPolicy`:

```python
from fasthttp import Client
from fasthttp.retry import RetryPolicy

rp = RetryPolicy(max_attempts=1, circuit_breaker=True, cb_failure_threshold=3, cb_recovery_seconds=60)
with Client(base_url="https://api.example.com", retry=rp) as client:
    resp = client.get("/resource")
```

Parameters:
- `cb_failure_threshold`: number of consecutive failures required to open the circuit.
- `cb_recovery_seconds`: seconds to wait before attempting requests again after the circuit is open.

---

## JSON decoding & charset behavior 🧾
`Response.json()` does the following:
- First, it decodes the response body according to `Content-Encoding` (gzip, br).
- Then it decodes text according to the `charset` from the `Content-Type` header (default: `utf-8`).
- If the body is empty or not valid JSON, a `json.decoder.JSONDecodeError` is raised.

---

## Development & Testing 🧪

```bash
# Install development dependencies
pip install -e .[dev]

# Run tests
python -m pytest -q
```

The repository includes a GitHub Actions workflow that runs tests on multiple Python versions and also runs `ruff` and `mypy` checks.

---

## Contributing 🤝
Please open an issue for bugs or feature requests, or send a pull request with tests and documentation updates. See `CONTRIBUTING.md` for guidelines.

---

## License
This project is suitable for release under the **MIT License** (add a `LICENSE` file if you want to publish it).

---

## Changelog (summary)
- Added optional Circuit Breaker and tests.
- Improved `Response.json()` to correctly decode compressed and charset-encoded payloads.
- Added async test coverage to ensure parity with the sync `Client`.
- Optional brotli (`br`) support when `brotli` package is installed.

---

If you'd like, I can also:
- Convert the bundled sync/async tests into `pytest`-style files under `tests/` (with `pytest-asyncio`), or
- Add a CI matrix job that installs `brotli` and validates `br` support.
