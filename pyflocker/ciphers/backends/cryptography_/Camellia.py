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
    key: typing.ByteString,
    mode: _m,
    iv_or_nonce: typing.ByteString,
    *,
    file: typing.Optional[typing.BinaryIO] = None,
    use_hmac: bool = False,
    digestmod: [str, base.BaseHash] = "sha256",
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
        file (filelike):
            The source file to read from.
            HMAC is always used when file is supplied.
        use_hmac (bool):
            Should the cipher use HMAC as authentication or not.
            (Default: `False`)
        digestmod (str, BaseHash):
            The algorithm to use for ``HMAC``. Defaults to ``sha256``.
            Specifying this value without setting ``use_hmac`` to True
            has no effect.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
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
        crp = _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod)
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


def _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod):
    ckey, hkey = derive_hkdf_key(key, len(key), digestmod, iv_or_nonce)
    crp = HMACWrapper(
        Camellia(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
        offset=15,
    )
    return crp
