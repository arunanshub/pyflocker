import typing
from types import MappingProxyType

from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as algo
from cryptography.hazmat.primitives.ciphers import modes

from ... import base
from ...modes import Modes as _m
from ..symmetric import FileCipherWrapper, HMACWrapper
from .misc import derive_hkdf_key
from .symmetric import NonAEADCipherTemplate

SUPPORTED = MappingProxyType(
    {
        _m.MODE_CFB: modes.CFB,
        _m.MODE_CTR: modes.CTR,
        _m.MODE_OFB: modes.OFB,
    }
)

del MappingProxyType


class Camellia(NonAEADCipherTemplate):
    """Camellia cipher class."""

    def __init__(self, encrypting, key, mode, iv_or_nonce):
        cipher = Cipher(
            algo.Camellia(key),
            SUPPORTED[mode](iv_or_nonce),
            defb(),
        )

        self._ctx = cipher.encryptor() if encrypting else cipher.decryptor()
        self._encrypting = encrypting


def new(
    encrypting: bool,
    key: bytes,
    mode: _m,
    iv_or_nonce: bytes,
    *,
    use_hmac: bool = False,
    tag_length: typing.Optional[int] = 16,
    digestmod: typing.Union[str, base.BaseHash] = "sha256",
    file: typing.Optional[typing.BinaryIO] = None,
) -> typing.Union[Camellia, FileCipherWrapper, HMACWrapper]:
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
            The algorithm to use for HMAC. Defaults to ``sha256``. Specifying
            this value without setting ``use_hmac`` to True has no effect.
        file (filelike):
            The source file to read from. If ``file`` is specified and the
            ``mode`` is not an AEAD mode, HMAC is always used.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``tag_length``
        - ``digestmod``

    Returns:
        Camellia: Camellia cipher.

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
            digestmod,
            tag_length,
        )
    else:
        crp = Camellia(encrypting, key, mode, iv_or_nonce)

    if file:
        crp = FileCipherWrapper(crp, file, offset=15)

    return crp


def supported_modes() -> typing.Set[_m]:
    """Lists all modes supported by Camellia cipher of this backend.

    Returns:
        set: set of :any:`Modes` object supported by backend.
    """
    return set(SUPPORTED)


def _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod, tag_length):
    ckey, hkey = derive_hkdf_key(key, len(key), digestmod, iv_or_nonce)
    return HMACWrapper(
        Camellia(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
        tag_length=tag_length,
        offset=15,
    )
