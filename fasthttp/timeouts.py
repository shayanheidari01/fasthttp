from dataclasses import dataclass
from typing import Optional, Union


@dataclass
class Timeout:
    total: Optional[float] = None
    connect: Optional[float] = None
    read: Optional[float] = None
    write: Optional[float] = None

    @classmethod
    def from_value(cls, value: Union["Timeout", float, int, None]) -> "Timeout":
        if isinstance(value, cls):
            return value
        if value is None:
            return cls()
        float_value = float(value)
        return cls(
            total=float_value,
            connect=float_value,
            read=float_value,
            write=float_value,
        )

    def merge(self, default: Optional["Timeout"]) -> "Timeout":
        default = default or Timeout()
        return Timeout(
            total=self.total if self.total is not None else default.total,
            connect=self.connect if self.connect is not None else default.connect,
            read=self.read if self.read is not None else default.read,
            write=self.write if self.write is not None else default.write,
        )

    def with_total(self, total: Optional[float]) -> "Timeout":
        """
        Return a copy of this timeout configuration with a new total value.
        """
        return Timeout(
            total=total,
            connect=self.connect,
            read=self.read,
            write=self.write,
        )
