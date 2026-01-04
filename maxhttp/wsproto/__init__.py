"""Compatibility shim exposing third-party wsproto under maxhttp.wsproto."""
from importlib import import_module
import sys
from types import ModuleType
from typing import Dict

_wsproto = import_module("wsproto")

# Re-export public symbols from the real wsproto package for backwards compatibility.
__all__ = list(getattr(_wsproto, "__all__", []))
for name in __all__:
    globals()[name] = getattr(_wsproto, name)

# Ensure attribute lookups still work even if not explicitly listed in __all__.
for name in dir(_wsproto):
    if name.startswith("_") or name in globals():
        continue
    globals()[name] = getattr(_wsproto, name)

# Mirror common submodules so importers can continue using maxhttp.wsproto.*
_submodules: Dict[str, ModuleType] = {}
for submodule in ("connection", "events", "frame_protocol", "handshake", "typing"):
    module = import_module(f"wsproto.{submodule}")
    full_name = f"{__name__}.{submodule}"
    sys.modules[full_name] = module
    _submodules[submodule] = module

__all__.extend([f"wsproto_{name}" for name in _submodules.keys()])
