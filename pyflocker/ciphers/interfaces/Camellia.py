"""Interface to Camellia cipher"""
from __future__ import annotations

import typing

from ..backends import Backends
from ..backends import load_algorithm as _load_algo

if typing.TYPE_CHECKING:  # pragma: no cover
    import io

    from .. import base
    from ..backends.symmetric import FileCipherWrapper
    from ..modes import Modes


def supported_modes(backend: Backends) -> set[Modes]:
    """
    Lists all modes supported by the cipher. It is limited to backend's
    implementation and capability, and hence, varies from backend to backend.

    Args:
        backend: The backend to inspect.

    Returns:
        Set of :any:`Modes` supported by the backend.
    """
    return _load_algo("Camellia", backend).supported_modes()


def new(
    encrypting: bool,
    key: bytes,
    mode: Modes,
    iv_or_nonce: bytes,
    *,
    use_hmac: bool = False,
    tag_length: int | None = 16,
    digestmod: None | base.BaseHash = None,
    file: io.BufferedIOBase | None = None,
    backend: Backends = Backends.CRYPTOGRAPHY,
) -> base.BaseAEADCipher | base.BaseNonAEADCipher | FileCipherWrapper:
    """Instantiate a new Camellia cipher object.

    Args:
        encrypting: True is encryption and False is decryption.
        key: The key for the cipher.
        mode:
            The mode to use for Camellia cipher. All backends may not support
            that particular mode.
        iv_or_nonce:
            The Initialization Vector or Nonce for the cipher. It must not be
            repeated with the same key.

    Keyword Arguments:
        use_hmac:
            Should the cipher use HMAC as authentication or not. Default is
            False.
        tag_length:
            Length of HMAC tag. By default, a **16 byte tag** is generated. If
            ``tag_length`` is ``None``, a **non-truncated** tag is generated.
            Length of non-truncated tag depends on the digest size of the
            underlying hash algorithm used by HMAC.
        digestmod:
            The algorithm to use for HMAC. If ``None``, defaults to ``sha256``.
            Specifying this value without setting ``use_hmac`` to True has no
            effect.
        file:
            The source file to read from. If ``file`` is specified and the
            ``mode`` is not an AEAD mode, HMAC is always used.
        backend: The backend to use. It must be a value from :any:`Backends`.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``tag_length``
        - ``digestmod``

    Returns:
        Camellia cipher from the appropriate backend module.

    Raises:
        UnsupportedMode: if backend does not support that mode.
        UnsupportedAlgorithm: if the backend does not support Camellia.

    Note:
        Any other error that is raised is from the backend itself.
    """
    return _load_algo("Camellia", backend).new(
        encrypting,
        key,
        mode,
        iv_or_nonce,
        file=file,
        use_hmac=use_hmac,
        tag_length=tag_length,
        digestmod=digestmod,
    )
