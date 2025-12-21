from dataclasses import dataclass
from typing import Optional, Union


@dataclass
class Timeout:
    connect: Optional[float] = None
    read: Optional[float] = None
    write: Optional[float] = None

    @classmethod
    def from_value(cls, value: Union["Timeout", float, int, None]) -> "Timeout":
        if isinstance(value, cls):
            return value
        if value is None:
            return cls()
        return cls(connect=float(value), read=float(value), write=float(value))

    def merge(self, default: Optional["Timeout"]) -> "Timeout":
        default = default or Timeout()
        return Timeout(
            connect=self.connect if self.connect is not None else default.connect,
            read=self.read if self.read is not None else default.read,
            write=self.write if self.write is not None else default.write,
        )
