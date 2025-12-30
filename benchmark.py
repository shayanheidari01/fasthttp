#!/usr/bin/env python3
"""Heavyweight HTTP client benchmarking helper."""
from __future__ import annotations

import argparse
import asyncio
import math
import os
import random
import threading
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Optional, Sequence

AsyncRequestFn = Callable[[], Awaitable[int]]
SyncRequestFn = Callable[[], int]

DEFAULT_LIBRARIES = ["fasthttp", "aiohttp", "httpx", "requests"]


class Stats:
    """Thread-safe accumulator for request metrics with optional reservoir sampling."""

    __slots__ = (
        "_lock",
        "latencies",
        "latency_sum",
        "success",
        "errors",
        "bytes_received",
        "_max_samples",
        "_seen",
        "_rand",
        "_total_samples",
    )

    def __init__(self, max_samples: Optional[int] = None, seed: Optional[int] = None) -> None:
        self._lock = threading.Lock()
        self.latencies: List[float] = []
        self.latency_sum: float = 0.0
        self.success: int = 0
        self.errors: int = 0
        self.bytes_received: int = 0
        self._max_samples = max_samples if max_samples and max_samples > 0 else None
        self._seen = 0
        self._rand = random.Random(seed)
        self._total_samples = 0

    def record(self, ok: bool, latency: float, size: int) -> None:
        with self._lock:
            self._seen += 1
            self._total_samples += 1
            if self._max_samples is None:
                self.latencies.append(latency)
            else:
                current_len = len(self.latencies)
                if current_len < self._max_samples:
                    self.latencies.append(latency)
                else:
                    idx = self._rand.randint(0, self._seen - 1)
                    if idx < self._max_samples:
                        self.latencies[idx] = latency
            self.latency_sum += latency
            if ok:
                self.success += 1
                self.bytes_received += size
            else:
                self.errors += 1

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {
                "latencies": list(self.latencies),
                "latency_sum": self.latency_sum,
                "latency_count": self._total_samples,
                "success": self.success,
                "errors": self.errors,
                "bytes_received": self.bytes_received,
            }


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    k = (len(values) - 1) * pct
    lower = math.floor(k)
    upper = math.ceil(k)
    if lower == upper:
        return float(values[int(k)])
    return values[lower] * (upper - k) + values[upper] * (k - lower)


@dataclass
class LoadOutcome:
    duration: float
    success: int
    errors: int
    bytes_received: int
    latencies: List[float]
    latency_sum: float
    latency_count: int


def _build_result(name: str, outcome: LoadOutcome) -> "BenchmarkResult":
    return BenchmarkResult(
        name=name,
        duration=outcome.duration,
        success=outcome.success,
        errors=outcome.errors,
        bytes_received=outcome.bytes_received,
        latencies=outcome.latencies,
        latency_sum=outcome.latency_sum,
        latency_count=outcome.latency_count,
    )


@dataclass
class BenchmarkResult:
    name: str
    duration: float
    success: int
    errors: int
    bytes_received: int
    latencies: List[float]
    latency_sum: float
    latency_count: int

    @property
    def total_requests(self) -> int:
        return self.success + self.errors

    @property
    def req_per_sec(self) -> float:
        return self.success / self.duration if self.duration else 0.0

    @property
    def avg_latency_ms(self) -> float:
        if not self.latency_count:
            return 0.0
        return (self.latency_sum / self.latency_count) * 1000

    def percentile_ms(self, pct: float) -> float:
        return percentile(sorted(self.latencies), pct) * 1000 if self.latencies else 0.0

    @property
    def throughput_mbps(self) -> float:
        if not self.duration:
            return 0.0
        return (self.bytes_received * 8) / (self.duration * 1024 * 1024)


async def run_async_load(
    request_fn: AsyncRequestFn,
    concurrency: int,
    duration: float,
    sample_limit: Optional[int],
    seed: Optional[int],
) -> LoadOutcome:
    stats = Stats(sample_limit, seed)
    start_event = asyncio.Event()
    ready_event = asyncio.Event()
    ready_count = 0
    ready_lock = asyncio.Lock()
    end_time = 0.0

    async def worker() -> None:
        nonlocal ready_count
        async with ready_lock:
            ready_count += 1
            if ready_count == concurrency:
                ready_event.set()
        await start_event.wait()
        while True:
            now = time.perf_counter()
            if now >= end_time:
                break
            start_time = time.perf_counter()
            try:
                size = await request_fn()
                stats.record(True, time.perf_counter() - start_time, size)
            except Exception:
                stats.record(False, time.perf_counter() - start_time, 0)

    tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await ready_event.wait()
    start = time.perf_counter()
    end_time = start + duration
    start_event.set()
    await asyncio.gather(*tasks)
    elapsed = time.perf_counter() - start

    snapshot = stats.snapshot()
    return LoadOutcome(
        duration=elapsed,
        success=snapshot["success"],
        errors=snapshot["errors"],
        bytes_received=snapshot["bytes_received"],
        latencies=snapshot["latencies"],
        latency_sum=snapshot["latency_sum"],
        latency_count=snapshot["latency_count"],
    )


def run_sync_load(
    request_fn: SyncRequestFn,
    concurrency: int,
    duration: float,
    sample_limit: Optional[int],
    seed: Optional[int],
) -> LoadOutcome:
    stats = Stats(sample_limit, seed)
    start_barrier = threading.Barrier(concurrency + 1)
    end_time = 0.0

    def worker() -> None:
        start_barrier.wait()
        while True:
            now = time.perf_counter()
            if now >= end_time:
                break
            start_time = time.perf_counter()
            try:
                size = request_fn()
                stats.record(True, time.perf_counter() - start_time, size)
            except Exception:
                stats.record(False, time.perf_counter() - start_time, 0)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(concurrency)]
    for th in threads:
        th.start()
    start = time.perf_counter()
    end_time = start + duration
    start_barrier.wait()
    for th in threads:
        th.join()
    elapsed = time.perf_counter() - start

    snapshot = stats.snapshot()
    return LoadOutcome(
        duration=elapsed,
        success=snapshot["success"],
        errors=snapshot["errors"],
        bytes_received=snapshot["bytes_received"],
        latencies=snapshot["latencies"],
        latency_sum=snapshot["latency_sum"],
        latency_count=snapshot["latency_count"],
    )


def parse_headers(raw: Sequence[str], parser: argparse.ArgumentParser) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in raw:
        if "=" not in item:
            parser.error(f"Invalid header '{item}', expected KEY=VALUE")
        key, value = item.split("=", 1)
        headers[key.strip()] = value.strip()
    return headers


def human_int(value: float) -> str:
    if value >= 1_000_000:
        return f"{value/1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value/1_000:.1f}K"
    return f"{int(value)}"


def ensure_payload(args: argparse.Namespace) -> Optional[bytes]:
    if args.body_size <= 0:
        return None
    return os.urandom(args.body_size)


async def benchmark_fasthttp(
    args: argparse.Namespace,
    payload: Optional[bytes],
    headers: Dict[str, str],
    sample_limit: Optional[int],
) -> BenchmarkResult:
    try:
        from fasthttp import Client
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("fasthttp is not installed") from exc

    method = args.method.upper()
    send_body = payload if payload is not None and method not in {"GET", "HEAD"} else None

    client = Client(timeout=args.timeout)

    async def request_fn() -> int:
        resp = await client.request(
            method,
            args.url,
            content=send_body,
            headers=headers if headers else None,
            timeout=args.timeout,
            verify=not args.insecure,
        )
        body = resp.content or b""
        return len(body)

    if args.warmup > 0:
        for _ in range(args.warmup):
            try:
                await request_fn()
            except Exception:
                pass

    outcome = await run_async_load(
        request_fn,
        args.concurrency,
        args.duration,
        sample_limit,
        args.latency_seed,
    )
    await client.close()
    return _build_result("fasthttp", outcome)


async def benchmark_httpx(
    args: argparse.Namespace,
    payload: Optional[bytes],
    headers: Dict[str, str],
    sample_limit: Optional[int],
) -> BenchmarkResult:
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("httpx is not installed") from exc

    method = args.method.upper()
    send_body = payload if payload is not None and method not in {"GET", "HEAD"} else None

    client = httpx.AsyncClient(verify=not args.insecure, timeout=args.timeout)

    async def request_fn() -> int:
        resp = await client.request(method, args.url, content=send_body, headers=headers or None)
        return len(resp.content)

    if args.warmup > 0:
        for _ in range(args.warmup):
            try:
                await request_fn()
            except Exception:
                pass

    outcome = await run_async_load(
        request_fn,
        args.concurrency,
        args.duration,
        sample_limit,
        args.latency_seed + 1 if args.latency_seed is not None else None,
    )
    await client.aclose()
    return _build_result("httpx", outcome)


async def benchmark_aiohttp(
    args: argparse.Namespace,
    payload: Optional[bytes],
    headers: Dict[str, str],
    sample_limit: Optional[int],
) -> BenchmarkResult:
    try:
        import aiohttp
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("aiohttp is not installed") from exc

    method = args.method.upper()
    send_body = payload if payload is not None and method not in {"GET", "HEAD"} else None

    timeout = aiohttp.ClientTimeout(total=args.timeout)
    session = aiohttp.ClientSession(timeout=timeout)

    async def request_fn() -> int:
        async with session.request(
            method,
            args.url,
            data=send_body,
            headers=headers or None,
            ssl=None if not args.insecure else False,
        ) as resp:
            body = await resp.read()
            return len(body)

    if args.warmup > 0:
        for _ in range(args.warmup):
            try:
                await request_fn()
            except Exception:
                pass

    outcome = await run_async_load(
        request_fn,
        args.concurrency,
        args.duration,
        sample_limit,
        args.latency_seed + 2 if args.latency_seed is not None else None,
    )
    await session.close()
    return _build_result("aiohttp", outcome)


def benchmark_requests(
    args: argparse.Namespace,
    payload: Optional[bytes],
    headers: Dict[str, str],
    sample_limit: Optional[int],
) -> BenchmarkResult:
    try:
        import requests
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("requests is not installed") from exc

    method = args.method.upper()
    send_body = payload if payload is not None and method not in {"GET", "HEAD"} else None

    session = requests.Session()

    def request_fn() -> int:
        resp = session.request(
            method,
            args.url,
            data=send_body,
            headers=headers or None,
            timeout=args.timeout,
            verify=not args.insecure,
        )
        return len(resp.content)

    if args.warmup > 0:
        for _ in range(args.warmup):
            try:
                request_fn()
            except Exception:
                pass

    outcome = run_sync_load(
        request_fn,
        args.concurrency,
        args.duration,
        sample_limit,
        args.latency_seed + 3 if args.latency_seed is not None else None,
    )
    session.close()
    return _build_result("requests", outcome)


def format_result_row(result: BenchmarkResult) -> str:
    return (
        f"{result.name:10s} | "
        f"{human_int(result.total_requests):>8s} | "
        f"{human_int(result.success):>7s} | "
        f"{result.req_per_sec:9.0f} | "
        f"{result.avg_latency_ms:11.2f} | "
        f"{result.percentile_ms(0.95):11.2f} | "
        f"{result.percentile_ms(0.99):11.2f} | "
        f"{result.throughput_mbps:9.2f}"
    )


def print_summary(results: List[BenchmarkResult], args: argparse.Namespace) -> None:
    if not results:
        print("No benchmarks were executed.")
        return

    header = (
        "Library    | Requests | Success |   Req/s | Avg Lat (ms) | P95 Lat (ms) | P99 Lat (ms) | Mbps"
    )
    print("\n=== Benchmark Configuration ===")
    print(f"Target URL      : {args.url}")
    print(f"Method          : {args.method.upper()}")
    print(f"Duration / lib  : {args.duration}s")
    print(f"Concurrency     : {args.concurrency}")
    print(f"Payload bytes   : {args.body_size}")
    print(f"TLS verification: {'enabled' if not args.insecure else 'DISABLED'}")
    print(f"Warmup requests : {args.warmup}")

    print("\n=== Results ===")
    print(header)
    print("-" * len(header))

    for res in sorted(results, key=lambda r: r.req_per_sec, reverse=True):
        print(format_result_row(res))


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark fasthttp against aiohttp/httpx/requests.")
    parser.add_argument("--url", default="https://httpbin.org/get", help="Target URL to hit")
    parser.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], help="HTTP method")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration (seconds) to run each benchmark")
    parser.add_argument("--concurrency", type=int, default=32, help="Number of in-flight requests per client")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout (seconds)")
    parser.add_argument("--body-size", type=int, default=0, help="If >0, send this many random bytes as the request body")
    parser.add_argument(
        "--libraries",
        nargs="+",
        choices=DEFAULT_LIBRARIES,
        help="Subset of libraries to benchmark (default: all)",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Additional header to include (can be repeated)",
    )
    parser.add_argument("--warmup", type=int, default=5, help="Warmup requests before measuring")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument(
        "--latency-samples",
        type=int,
        default=50000,
        help="Maximum number of latency samples to keep per client (0 = keep all)",
    )
    parser.add_argument(
        "--latency-seed",
        type=int,
        default=42,
        help="Seed for latency reservoir sampling to keep results reproducible",
    )

    args = parser.parse_args(argv)
    headers = parse_headers(args.header, parser)
    if args.body_size > 0 and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/octet-stream"
    args.headers = headers
    args.method = args.method.upper()
    args.latency_seed = args.latency_seed if args.latency_seed >= 0 else None
    args.latency_samples = args.latency_samples if args.latency_samples > 0 else None
    if args.concurrency <= 0:
        parser.error("--concurrency must be > 0")
    if args.duration <= 0:
        parser.error("--duration must be > 0")
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    payload = ensure_payload(args)
    sample_limit = args.latency_samples

    selected = args.libraries or DEFAULT_LIBRARIES
    benchmarks: Dict[
        str,
        Callable[
            [argparse.Namespace, Optional[bytes], Dict[str, str], Optional[int]],
            Awaitable[BenchmarkResult] | BenchmarkResult,
        ],
    ] = {
        "fasthttp": benchmark_fasthttp,
        "aiohttp": benchmark_aiohttp,
        "httpx": benchmark_httpx,
        "requests": benchmark_requests,
    }

    results: List[BenchmarkResult] = []
    for name in selected:
        runner = benchmarks[name]
        print(f"\n--- Running {name} ---")
        try:
            if asyncio.iscoroutinefunction(runner):
                result = asyncio.run(runner(args, payload, args.headers, sample_limit))
            elif asyncio.iscoroutine(runner):  # pragma: no cover
                result = asyncio.run(runner)  # defensive
            else:
                if name in {"fasthttp", "aiohttp", "httpx"}:
                    result = asyncio.run(runner(args, payload, args.headers, sample_limit))  # type: ignore[arg-type]
                else:
                    result = runner(args, payload, args.headers, sample_limit)  # type: ignore[call-arg]
        except RuntimeError as exc:
            print(f"Skipping {name}: {exc}")
            continue
        results.append(result)

    print_summary(results, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
