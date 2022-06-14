from __future__ import annotations

import typing

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as algo
from cryptography.hazmat.primitives.ciphers import modes

from ... import exc
from ...modes import Modes
from ..symmetric import FileCipherWrapper, HMACWrapper
from . import Hash
from .misc import derive_hkdf_key
from .symmetric import NonAEADCipherTemplate

if typing.TYPE_CHECKING:  # pragma: no cover
    import io

    from ... import base

SUPPORTED = {
    Modes.MODE_CFB: modes.CFB,
    Modes.MODE_CTR: modes.CTR,
    Modes.MODE_OFB: modes.OFB,
}


class Camellia(NonAEADCipherTemplate):
    """Camellia cipher class."""

    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: Modes,
        iv_or_nonce: bytes,
    ):
        if mode not in supported_modes():
            raise exc.UnsupportedMode(f"{mode.name} not supported.")

        cipher = Cipher(
            algo.Camellia(key),
            SUPPORTED[mode](iv_or_nonce),  # type: ignore
        )
        self._ctx = (
            cipher.encryptor()  # type: ignore[misc]
            if encrypting
            else cipher.decryptor()  # type: ignore[misc]
        )
        self._encrypting = encrypting


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
) -> Camellia | FileCipherWrapper | HMACWrapper:
    """Instantiate a new Camellia cipher wrapper object.

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
            Should the cipher use HMAC as authentication or not.
            (Default: ``False``)
        tag_length:
            Length of HMAC tag. By default, a **16 byte tag** is generated. If
            ``tag_length`` is ``None``, a **non-truncated** tag is generated.
            Length of non-truncated tag depends on the digest size of the
            underlying hash algorithm used by HMAC.
        digestmod:
            The algorithm to use for HMAC. If ``None``, Defaults to ``sha256``.
            Specifying this value without setting ``use_hmac`` to True has no
            effect.
        file:
            The source file to read from. If ``file`` is specified and the
            ``mode`` is not an AEAD mode, HMAC is always used.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``tag_length``
        - ``digestmod``

    Returns:
        Camellia cipher.

    Raises:
        UnsupportedMode: if the given ``mode`` is not supported by the cipher.

    Note:
        Any other error that is raised is from the backend itself.
    """
    crp: typing.Any
    if file is not None:
        use_hmac = True

    if use_hmac:
        crp = _wrap_hmac(
            encrypting,
            key,
            mode,
            iv_or_nonce,
            digestmod if digestmod is not None else Hash.new("sha256"),
            tag_length,
        )
    else:
        crp = Camellia(encrypting, key, mode, iv_or_nonce)

    if file:
        crp = FileCipherWrapper(crp, file, offset=15)

    return crp


def supported_modes() -> set[Modes]:
    """Lists all modes supported by Camellia cipher of this backend.

    Returns:
        Set of :any:`Modes` object supported by backend.
    """
    return set(SUPPORTED)


def _wrap_hmac(
    encrypting: bool,
    key: bytes,
    mode: Modes,
    iv_or_nonce: bytes,
    digestmod: base.BaseHash,
    tag_length: int | None,
) -> HMACWrapper:
    ckey, hkey = derive_hkdf_key(key, len(key), digestmod, iv_or_nonce)
    return HMACWrapper(
        Camellia(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
        tag_length=tag_length,
        offset=15,
    )
