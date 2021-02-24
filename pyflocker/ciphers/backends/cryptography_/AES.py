"""Implementation of AES cipher."""

import hmac
import struct
import typing
from types import MappingProxyType

import cryptography.exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher as CrCipher
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.ciphers import algorithms as algo
from cryptography.hazmat.primitives.ciphers import modes

from ... import base, exc
from ... import modes as modes_
from ...modes import Modes as _m
from ..symmetric import (
    FileCipherWrapper,
    HMACWrapper,
    _DecryptionCtx,
    _EncryptionCtx,
)
from .misc import derive_hkdf_key
from .symmetric import AEADCipherTemplate, NonAEADCipherTemplate

SUPPORTED = MappingProxyType(
    {
        _m.MODE_GCM: modes.GCM,
        _m.MODE_EAX: None,  # not defined by backend
        _m.MODE_CTR: modes.CTR,
        _m.MODE_CFB8: modes.CFB8,
        _m.MODE_CFB: modes.CFB,
        _m.MODE_OFB: modes.OFB,
        _m.MODE_CCM: aead.AESCCM,
    }
)

del MappingProxyType


class AEAD(AEADCipherTemplate):
    def __init__(self, encrypting, key, mode, nonce):
        self._encrypting = encrypting
        self._updated = False
        self._tag = None
        self._mode = mode

        cipher = _aes_cipher(key, mode, nonce)
        # cryptography already provides a context
        if encrypting:
            self._ctx = cipher.encryptor()
        else:
            self._ctx = cipher.decryptor()

    @property
    def mode(self) -> _m:
        """The AES mode."""
        return self._mode


class NonAEAD(NonAEADCipherTemplate):
    def __init__(self, encrypting, key, mode, nonce):
        self._encrypting = encrypting
        self._mode = mode

        cipher = _aes_cipher(key, mode, nonce)
        # cryptography already provides a context
        if encrypting:
            self._ctx = cipher.encryptor()
        else:
            self._ctx = cipher.decryptor()

    @property
    def mode(self) -> _m:
        """The AES mode."""
        return self._mode


class AEADOneShot(base.BaseAEADCipher):
    def __init__(self, encrypting, key, mode, nonce):
        cipher = _aes_cipher(key, mode, nonce)

        self._mode = mode
        self._encrypting = encrypting
        self._aad = b""
        self._tag = None
        self._nonce = nonce
        self._update_func = cipher.encrypt if encrypting else cipher.decrypt

        self._raise_on_tag_err = False
        self._tag_length = 16

    @property
    def mode(self) -> _m:
        """The AES mode."""
        return self._mode

    def authenticate(self, data):
        if self._update_func is None:
            raise exc.AlreadyFinalized
        self._aad += data

    def is_encrypting(self):
        return self._encrypting

    def update(self, data, tag=None):
        if self._update_func is None:
            raise exc.AlreadyFinalized

        if self.is_encrypting():
            ctxt_tag = self._update_func(self._nonce, data, self._aad)
            self._tag = ctxt_tag[-self._tag_length :]
            self.finalize(tag)
            return ctxt_tag[: -self._tag_length]

        if tag is None:
            raise ValueError("tag is required for decryption.")

        try:
            return self._update_func(self._nonce, data + tag, self._aad)
        except bkx.InvalidTag:
            self._raise_on_tag_err = True
        finally:
            self.finalize(tag)

    def update_into(self, data, out, tag=None):
        raise NotImplementedError

    def finalize(self, tag=None):
        if self._update_func is None:
            raise exc.AlreadyFinalized

        self._update_func = None
        if self._raise_on_tag_err:
            raise exc.DecryptionError

    def calculate_tag(self):
        if self._update_func is not None:
            raise exc.NotFinalized
        return self._tag


class _AuthWrapper:
    """Wrapper class for objects that do not support memoryview objects."""

    __slots__ = ("_auth",)

    def __init__(self, auth):
        self._auth = auth

    def update(self, data):
        self._auth.update(bytes(data))

    def __getattr__(self, name):
        return getattr(self._auth, name)


class _EAX:
    """AES-EAX adapter for pyca/cryptography."""

    __slots__ = (
        "_mac_len",
        "_omac",
        "_auth",
        "_omac_cache",
        "_cipher",
        "_updated",
        "__ctx",
        "__tag",
    )

    def __init__(self, key, nonce, mac_len=16):
        self._mac_len = mac_len
        self._omac = [cmac.CMAC(algo.AES(key), defb()) for i in range(3)]

        for i in range(3):
            self._omac[i].update(
                bytes(1) * (algo.AES.block_size // 8 - 1)
                + struct.pack("B", i)  # noqa: W503
            )

        self._omac[0].update(nonce)
        self._auth = _AuthWrapper(self._omac[1])

        # create a cache since cryptography allows us to calculate tag
        # only once... why...
        self._omac_cache = []
        self._omac_cache.append(self._omac[0].finalize())

        self._cipher = CrCipher(
            algo.AES(key),
            modes.CTR(self._omac_cache[0]),
            defb(),
        )

        self.__ctx = None
        self._updated = False
        self.__tag = None

    @property
    def _ctx(self):
        """The Cipher context used by the backend.
        Maintains compatibility across pyca/cryptography style
        cipher instances.
        """
        if self.__ctx:
            return self.__ctx._ctx
        return None

    def authenticate_additional_data(self, data):
        if self.__ctx is None:
            raise bkx.AlreadyFinalized
        if self._updated:
            raise ValueError  # pragma: no cover
        self._auth.update(data)

    def encryptor(self):
        self.__ctx = _EncryptionCtx(
            self._cipher.encryptor(),
            _AuthWrapper(self._omac[2]),
            15,
        )
        return self

    def decryptor(self):
        self.__ctx = _DecryptionCtx(
            self._cipher.decryptor(), _AuthWrapper(self._omac[2])
        )
        return self

    def update(self, data):
        if self.__ctx is None:
            raise bkx.AlreadyFinalized
        self._updated = True
        return self.__ctx.update(data)

    def update_into(self, data, out):
        if self.__ctx is None:
            raise bkx.AlreadyFinalized
        self._updated = True
        self.__ctx.update_into(data, out)

    def finalize(self):
        """Finalizes the cipher."""
        if self.__ctx is None:
            raise bkx.AlreadyFinalized

        tag = bytes(algo.AES.block_size // 8)
        for i in range(3):
            try:
                tag = strxor(tag, self._omac_cache[i])
            except IndexError:
                self._omac_cache.append(self._omac[i].finalize())
                tag = strxor(tag, self._omac_cache[i])
        self.__tag, self.__ctx = tag[: self._mac_len], None

    def finalize_with_tag(self, tag):
        self.finalize()
        if not hmac.compare_digest(tag, self.__tag):
            raise bkx.InvalidTag  # pragma: no cover

    @property
    def tag(self):
        if self.__ctx is not None:
            raise bkx.NotYetFinalized
        return self.__tag


def strxor(x: typing.ByteString, y: typing.ByteString) -> bytes:
    """XOR two byte strings"""
    return bytes([ix ^ iy for ix, iy in zip(x, y)])


def new(
    encrypting: bool,
    key: typing.ByteString,
    mode: _m,
    iv_or_nonce: typing.ByteString,
    *,
    file: typing.Optional[typing.BinaryIO] = None,
    use_hmac: bool = False,
    digestmod: [str, base.BaseHash] = "sha256",
) -> typing.Union[AEAD, NonAEAD, FileCipherWrapper, HMACWrapper]:
    """Create a new backend specific AES cipher.

    Args:
        encrypting (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        mode (:any:`Modes`):
            The mode to use for AES cipher.
        iv_or_nonce (bytes, bytearray, memoryview):
            The Initialization Vector or Nonce for the cipher. It must not be
            repeated with the same key.

    Keyword Arguments:
        file (filelike):
            The source file to read from. If `file` is specified
            and the `mode` is not an AEAD mode, HMAC is always used.
        use_hmac (bool):
            Should the cipher use HMAC as authentication or not,
            if it does not support AEAD. (Default: False)
        digestmod (str, BaseHash):
            The algorithm to use for HMAC. Defaults to ``sha256``.
            Specifying this value without setting ``use_hmac`` to True
            has no effect.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``digestmod``

    Returns:
        :any:`BaseSymmetricCipher`: AES cipher.

    Raises:
        NotImplementedError:
            if the ``mode`` does not support encryption/decryption of files.

    Note:
        Any other error that is raised is from the backend itself.
    """
    crp: typing.Any

    if file is not None:
        use_hmac = True

    if mode in modes_.special:
        if file is not None:
            raise NotImplementedError(
                f"{mode} does not support encryption/decryption of files."
            )
        crp = AEADOneShot(encrypting, key, mode, iv_or_nonce)
    elif mode in modes_.aead:
        crp = AEAD(encrypting, key, mode, iv_or_nonce)
    else:
        if use_hmac:
            crp = _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod)
        else:
            crp = NonAEAD(encrypting, key, mode, iv_or_nonce)

    if file:
        crp = FileCipherWrapper(crp, file, offset=15)

    return crp


def supported_modes() -> typing.Set[_m]:
    """Lists all modes supported by AES cipher of this backend.

    Returns:
        set: set of :any:`Modes` object supported by backend.
    """
    return set(SUPPORTED)


def _aes_cipher(key, mode, nonce_or_iv):
    if mode == _m.MODE_EAX:
        return _EAX(key, nonce_or_iv)
    if mode in modes_.special:
        if mode == _m.MODE_CCM:
            if not 7 <= len(nonce_or_iv) <= 13:
                raise ValueError(
                    "Length of nonce must be between 7 and 13 bytes."
                )
        return SUPPORTED[mode](key)

    return CrCipher(algo.AES(key), SUPPORTED[mode](nonce_or_iv), defb())


def _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod):
    ckey, hkey = derive_hkdf_key(key, len(key), digestmod, iv_or_nonce)
    crp = HMACWrapper(
        NonAEAD(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
        offset=15,
    )
    return crp
