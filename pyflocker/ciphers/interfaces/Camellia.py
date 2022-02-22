"""Interface to Camellia cipher"""
from __future__ import annotations

import typing
from typing import TYPE_CHECKING

from ..backends import Backends
from ..backends import load_algorithm as _load_algo

if TYPE_CHECKING:  # pragma: no cover
    from .. import base
    from ..modes import Modes


def supported_modes(backend: Backends) -> typing.Set[Modes]:
    """Lists all modes supported by the cipher. It is limited to backend's
    implementation and capability and hence, varies from backend to backend.

    Args:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            An attribute from :any:`Backends` enum.

    Returns:
        list: list of :any:`Modes` object supported by backend.
    """
    return _load_algo("Camellia", backend).supported_modes()


def new(
    encrypting: bool,
    key: bytes,
    mode: Modes,
    iv_or_nonce: bytes,
    *,
    use_hmac: bool = False,
    tag_length: typing.Optional[int] = 16,
    digestmod: typing.Union[str, base.BaseHash] = "sha256",
    file: typing.Optional[typing.BinaryIO] = None,
    backend: Backends = Backends.CRYPTOGRAPHY,
):
    """Instantiate a new Camellia cipher wrapper object.

    Args:
        encrypting (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        mode (:class:`pyflocker.ciphers.modes.Modes`):
            The mode to use for Camellia cipher. All backends may not support
            that particular mode.
        iv_or_nonce (bytes, bytearray, memoryview):
            The Initialization Vector or Nonce for the cipher. It must not be
            repeated with the same key.

    Keyword Arguments:
        use_hmac (bool):
            Should the cipher use HMAC as authentication or not.
            (Default: ``False``)
        tag_length (int, None):
            Length of HMAC tag. By default, a **16 byte tag** is generated. If
            ``tag_length`` is ``None``, a **non-truncated** tag is generated.
            Length of non-truncated tag depends on the digest size of the
            underlying hash algorithm used by HMAC.
        digestmod (str, BaseHash):
            The algorithm to use for HMAC. Defaults to ``sha256``.
            Specifying this value without setting ``use_hmac`` to True
            has no effect.
        file (filelike):
            The source file to read from. If ``file`` is specified
            and the ``mode`` is not an AEAD mode, HMAC is always used.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``tag_length``
        - ``digestmod``

    Returns:
        BaseSymmetricCipher:
            Camellia cipher from the appropriate backend module.

    Raises:
        NotImplementedError: if backend does not support that mode.
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
