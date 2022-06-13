from __future__ import annotations

from pyflocker.ciphers.backends import Backends


def make_buffer(data: bytes, offset: int = 15) -> memoryview:
    """
    Construct a buffer for in-place encryption/decryption. Offset should be a
    positive integer.
    """
    return memoryview(bytearray(data) + bytearray(offset))


def get_io_buffer(
    buffer: memoryview,
    backend: Backends,
    offset: int | None = 15,
) -> tuple[memoryview, memoryview]:
    """
    Create a input/output buffer pair. The size of the buffers varies with the
    given backend.
    """
    offset = -offset if offset else None
    if backend == Backends.CRYPTOGRAPHY:
        return buffer[:offset], buffer
    return buffer[:offset], buffer[:offset]
