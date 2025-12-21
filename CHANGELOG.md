# Changelog

## 0.1.0 - Unreleased

- Added Circuit Breaker support to `RetryPolicy` (optional, configurable thresholds).
- Improved `Response` API:
  - caching for decoded content and text
  - `encoding` property
  - `raise_for_status()` helper
  - `iter_text()` / `aiter_text()` for streaming text
  - context manager support and `__repr__`
- Fix: `Response.text()` now correctly extracts `charset` from `Content-Type` and falls back to UTF-8 when absent.
- Fix: Handle `Content-Encoding` and `Content-Type` header names case-insensitively.
- Fix: `Response.json()` now decodes compressed and charset-encoded responses before parsing.
- Test: Added tests for charset handling, lowercase headers, empty JSON body, and circuit breaker behavior.
- CI: Add GitHub Actions workflow and basic lint/type checks.
