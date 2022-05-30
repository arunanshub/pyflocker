"""Interface to AES cipher"""
from __future__ import annotations

import typing

from ..backends import load_algorithm as _load_algo
from ..modes import Modes

if typing.TYPE_CHECKING:  # pragma: no cover
    import io

    from .. import base
    from ..backends import Backends
    from ..backends.symmetric import FileCipherWrapper


# Prevent type checking errors from being raised.
MODE_GCM = Modes.MODE_GCM
MODE_CTR = Modes.MODE_CTR
MODE_CFB = Modes.MODE_CFB
MODE_CFB8 = Modes.MODE_CFB8
MODE_OFB = Modes.MODE_OFB
MODE_CCM = Modes.MODE_CCM
MODE_EAX = Modes.MODE_EAX
MODE_SIV = Modes.MODE_SIV
MODE_OCB = Modes.MODE_OCB


def supported_modes(backend: Backends) -> set[Modes]:
    """
    Lists all modes supported by the cipher. It is limited to backend's
    implementation and capability, and hence, varies from backend to backend.

    Args:
        backend: The backend to inspect.

    Returns:
        Set of :any:`Modes` supported by the backend.
    """
    return _load_algo("AES", backend).supported_modes()


def new(
    encrypting: bool,
    key: bytes,
    mode: Modes,
    iv_or_nonce: bytes,
    *,
    use_hmac: bool = False,
    tag_length: int | None = 16,
    digestmod: None | base.BaseHash = None,
    file: io.BufferedReader | None = None,
    backend: Backends | None = None,
) -> base.BaseAEADCipher | base.BaseNonAEADCipher | FileCipherWrapper:
    """Instantiate a new AES cipher object.

    Args:
        encrypting: True is encryption and False is decryption.
        key: The key for the cipher.
        mode:
            The mode to use for AES cipher. All backends may not support that
            particular mode.
        iv_or_nonce:
            The Initialization Vector or Nonce for the cipher. It must not be
            repeated with the same key.

    Keyword Arguments:
        use_hmac:
            Should the cipher use HMAC as authentication or not, if it does not
            support AEAD. (Default: False)
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
        AES cipher wrapper from the appropriate backend module.

    Raises:
        NotImplementedError:
            if backend does not support the given mode or the mode does not
            support encryption/decryption of files.
        UnsupportedAlgorithm: if the backend does not support AES.

    Note:
        Any other error that is raised is from the backend itself.
    """
    return _load_algo("AES", backend).new(
        encrypting,
        key,
        mode,
        iv_or_nonce,
        use_hmac=use_hmac,
        tag_length=tag_length,
        digestmod=digestmod,
        file=file,
    )
