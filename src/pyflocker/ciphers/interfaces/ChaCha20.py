"""Interface to ChaCha20(-Poly1305) cipher"""
from __future__ import annotations

import typing

from ..backends import load_algorithm as _load_algo

if typing.TYPE_CHECKING:  # pragma: no cover
    import io

    from .. import base
    from ..backends import Backends
    from ..backends.symmetric import FileCipherWrapper


def new(
    encrypting: bool,
    key: bytes,
    nonce: bytes,
    *,
    use_poly1305: bool = True,
    file: io.BufferedIOBase | None = None,
    backend: Backends | None = None,
) -> base.BaseNonAEADCipher | base.BaseAEADCipher | FileCipherWrapper:
    """Instantiate a new ChaCha20-Poly1305 cipher wrapper object.

    Args:
        encrypting: True is encryption and False is decryption.
        key: The key for the cipher.
        nonce:
            The Nonce for the cipher. It must not be repeated with the same
            key.

    Keyword Arguments:
        use_poly1305:
            Whether Poly1305 MAC will be used or not. Default is ``True``.
        file: The source file to read from.
        backend: The backend to use. It must be a value from :any:`Backends`.

    Returns:
        ChaCha20-(Poly1305) cipher from the appropriate backend module.

    Note:
        Any other error that is raised is from the backend itself.
    """
    return _load_algo("ChaCha20", backend).new(
        encrypting,
        key,
        nonce,
        file=file,
        use_poly1305=use_poly1305,
    )
