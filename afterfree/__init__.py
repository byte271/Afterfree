"""Afterfree: learn native computation, reclaim output, replay on access.

This experimental release exposes an explicit C ABI boundary. It does not
automatically discover arbitrary allocations in whole executables.
"""

from .runtime import Runtime, Buffer, Capture, AfterfreeError

__version__ = "0.1.0"
__all__ = ["Runtime", "Buffer", "Capture", "AfterfreeError"]
