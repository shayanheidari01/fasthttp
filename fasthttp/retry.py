from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Sequence, Tuple, Type
import time

from .errors import FastHTTPError, RequestError, ResponseError


DEFAULT_RETRY_EXC: Tuple[Type[BaseException], ...] = (RequestError, ResponseError, FastHTTPError, TimeoutError)


@dataclass
class RetryPolicy:
    max_attempts: int = 1
    backoff_factor: float = 0.2
    backoff_max: float = 2.0
    retry_on_status: Sequence[int] = (408, 429, 500, 502, 503, 504)
    retry_exceptions: Tuple[Type[BaseException], ...] = DEFAULT_RETRY_EXC

    # Circuit breaker options
    circuit_breaker: bool = False
    cb_failure_threshold: int = 5
    cb_recovery_seconds: float = 60.0
    # Internal state (host -> state)
    _cb_state: Dict[str, Dict[str, float]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            self.max_attempts = 1

    def should_retry_status(self, status: int) -> bool:
        return status in self.retry_on_status

    def iter_delays(self) -> Iterable[float]:
        for attempt in range(1, self.max_attempts):
            delay = min(self.backoff_factor * (2 ** (attempt - 1)), self.backoff_max)
            yield delay

    # Circuit breaker helpers
    def _now(self) -> float:
        return time.monotonic()

    def is_circuit_open(self, host: str) -> bool:
        if not self.circuit_breaker:
            return False
        st = self._cb_state.get(host)
        if not st:
            return False
        open_until = st.get("open_until", 0.0)
        if open_until > self._now():
            return True
        # If recovery time passed, clear state
        self._cb_state.pop(host, None)
        return False

    def record_failure(self, host: str) -> None:
        if not self.circuit_breaker:
            return
        st = self._cb_state.setdefault(host, {"fail_count": 0, "open_until": 0.0})
        st["fail_count"] = st.get("fail_count", 0) + 1
        if st["fail_count"] >= self.cb_failure_threshold:
            st["open_until"] = self._now() + self.cb_recovery_seconds
            # reset fail count after opening
            st["fail_count"] = 0

    def record_success(self, host: str) -> None:
        if not self.circuit_breaker:
            return
        # on success, clear fail_count
        st = self._cb_state.get(host)
        if st:
            st["fail_count"] = 0
            st["open_until"] = 0.0
