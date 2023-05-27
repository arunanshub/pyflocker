"""Implementation of AES cipher."""

from __future__ import annotations

import hmac
import struct
import typing
from types import MappingProxyType

import cryptography.exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher as CrCipher
from cryptography.hazmat.primitives.ciphers import aead, modes
from cryptography.hazmat.primitives.ciphers import algorithms as algo

from ... import base, exc
from ... import modes as modes_
from ...modes import Modes
from ..symmetric import (
    FileCipherWrapper,
    HMACWrapper,
    _DecryptionCtx,
    _EncryptionCtx,
)
from . import Hash
from .misc import derive_hkdf_key
from .symmetric import AEADCipherTemplate, NonAEADCipherTemplate

if typing.TYPE_CHECKING:
    import io

SUPPORTED = MappingProxyType(
    {
        Modes.MODE_GCM: modes.GCM,
        Modes.MODE_EAX: None,  # not defined by backend
        Modes.MODE_CTR: modes.CTR,
        Modes.MODE_CFB8: modes.CFB8,
        Modes.MODE_CFB: modes.CFB,
        Modes.MODE_OFB: modes.OFB,
        Modes.MODE_CCM: aead.AESCCM,
    }
)

del MappingProxyType


class AEAD(AEADCipherTemplate):
    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: Modes,
        nonce: bytes,
    ) -> None:
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
    def mode(self) -> Modes:
        """The AES mode."""
        return self._mode


class NonAEAD(NonAEADCipherTemplate):
    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: Modes,
        nonce: bytes,
    ) -> None:
        self._encrypting = encrypting
        self._mode = mode

        cipher = _aes_cipher(key, mode, nonce)
        # cryptography already provides a context
        if encrypting:
            self._ctx = cipher.encryptor()
        else:
            self._ctx = cipher.decryptor()

    @property
    def mode(self) -> Modes:
        """The AES mode."""
        return self._mode


class AEADOneShot(base.BaseAEADOneShotCipher):
    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: Modes,
        nonce: bytes,
    ) -> None:
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
    def mode(self) -> Modes:
        """The AES mode."""
        return self._mode

    def authenticate(self, data: bytes) -> None:
        if self._update_func is None:
            raise exc.AlreadyFinalized
        self._aad += data

    def is_encrypting(self) -> bool:
        return self._encrypting

    def update(
        self,
        data: bytes,
        tag: bytes | None = None,
    ) -> bytes:
        if self._update_func is None:
            raise exc.AlreadyFinalized

        if self.is_encrypting():
            ctxt_tag = self._update_func(self._nonce, data, self._aad)
            self._tag = ctxt_tag[-self._tag_length :]
            self.finalize(tag)
            return ctxt_tag[: -self._tag_length]

        if tag is None:
            msg = "tag is required for decryption."
            raise ValueError(msg)

        try:
            data = self._update_func(self._nonce, data + tag, self._aad)
        except bkx.InvalidTag:
            self._raise_on_tag_err = True
        finally:
            self.finalize(tag)
        return data

    def update_into(
        self,
        data: bytes,
        out: bytearray | memoryview,
        tag: bytes | None = None,
    ) -> None:
        del tag, out, data
        raise NotImplementedError

    def finalize(self, tag: bytes | None = None) -> None:
        if self._update_func is None:
            raise exc.AlreadyFinalized

        if not self.is_encrypting() and tag is None:
            msg = "tag is required for decryption."
            raise ValueError(msg)

        self._update_func = None
        if self._raise_on_tag_err:
            raise exc.DecryptionError

    def calculate_tag(self) -> bytes | None:
        if self._update_func is not None:
            raise exc.NotFinalized
        return self._tag


class _AuthWrapper:
    """Wrapper class for objects that do not support memoryview objects."""

    __slots__ = ("_auth",)

    def __init__(self, auth: typing.Any) -> None:
        self._auth = auth

    def update(self, data: bytes) -> None:
        self._auth.update(bytes(data))

    def __getattr__(self, name: str) -> typing.Any:
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

    def __init__(self, key: bytes, nonce: bytes, mac_len: int = 16) -> None:
        self._mac_len = mac_len
        self._omac = [cmac.CMAC(algo.AES(key), defb()) for _ in range(3)]

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
    def _ctx(self) -> typing.Any:  # pragma: no cover
        """The Cipher context used by the backend.
        Maintains compatibility across pyca/cryptography style
        cipher instances.
        """
        if self.__ctx:
            return self.__ctx._ctx
        return None

    def authenticate_additional_data(self, data: bytes) -> None:
        if self.__ctx is None:  # pragma: no cover
            raise bkx.AlreadyFinalized
        if self._updated:
            raise ValueError  # pragma: no cover
        self._auth.update(data)

    def encryptor(self) -> _EAX:
        self.__ctx = _EncryptionCtx(
            self._cipher.encryptor(),  # type: ignore
            _AuthWrapper(self._omac[2]),
            15,
        )
        return self

    def decryptor(self) -> _EAX:
        self.__ctx = _DecryptionCtx(
            self._cipher.decryptor(),  # type: ignore
            _AuthWrapper(self._omac[2]),
        )
        return self

    def update(self, data: bytes) -> bytes:
        if self.__ctx is None:  # pragma: no cover
            raise bkx.AlreadyFinalized
        self._updated = True
        return self.__ctx.update(data)

    def update_into(
        self,
        data: bytes,
        out: bytearray | memoryview,
    ) -> None:
        if self.__ctx is None:  # pragma: no cover
            raise bkx.AlreadyFinalized
        self._updated = True
        self.__ctx.update_into(data, out)

    def finalize(self) -> None:
        """Finalizes the cipher."""
        if self.__ctx is None:  # pragma: no cover
            raise bkx.AlreadyFinalized

        tag = bytes(typing.cast("int", algo.AES.block_size) // 8)
        for i in range(3):
            try:
                tag = strxor(tag, self._omac_cache[i])
            except IndexError:
                self._omac_cache.append(self._omac[i].finalize())
                tag = strxor(tag, self._omac_cache[i])
        self.__tag, self.__ctx = tag[: self._mac_len], None

    def finalize_with_tag(self, tag: bytes) -> None:
        self.finalize()
        assert self.__tag is not None
        if not hmac.compare_digest(tag, self.__tag):
            raise bkx.InvalidTag  # pragma: no cover

    @property
    def tag(self) -> bytes | None:
        if self.__ctx is not None:  # pragma: no cover
            raise bkx.NotYetFinalized
        return self.__tag


def strxor(x: bytes, y: bytes) -> bytes:
    """XOR two byte strings"""
    return bytes(ix ^ iy for ix, iy in zip(x, y))


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
) -> AEAD | NonAEAD | FileCipherWrapper | HMACWrapper:
    """Create a new backend specific AES cipher.

    Args:
        encrypting: True is encryption and False is decryption.
        key: The key for the cipher.
        mode: The mode to use for AES cipher.
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
            The algorithm to use for HMAC. If ``None``, Defaults to ``sha256``.
            Specifying this value without setting ``use_hmac`` to True has no
            effect.
        file:
            The source file to read from. If `file` is specified and the `mode`
            is not an AEAD mode, HMAC is always used.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``tag_length``
        - ``digestmod``

    Returns:
        AES cipher.

    Raises:
        NotImplementedError:
            if the ``mode`` does not support encryption/decryption of files.

    Note:
        Any other error that is raised is from the backend itself.
    """
    crp: typing.Any

    if mode not in supported_modes():
        msg = f"{mode.name} not supported."
        raise exc.UnsupportedMode(msg)

    if file is not None:
        use_hmac = True

    if mode in modes_.SPECIAL:
        if file is not None:
            msg = f"{mode} does not support encryption/decryption of files."
            raise NotImplementedError(msg)
        crp = AEADOneShot(encrypting, key, mode, iv_or_nonce)
    elif mode in modes_.AEAD:
        crp = AEAD(encrypting, key, mode, iv_or_nonce)
    else:
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
            crp = NonAEAD(encrypting, key, mode, iv_or_nonce)

    if file:
        crp = FileCipherWrapper(crp, file, offset=15)

    return crp


def supported_modes() -> set[Modes]:
    """Lists all modes supported by AES cipher of this backend.

    Returns:
        set of :any:`Modes` object supported by backend.
    """
    return set(SUPPORTED)


def _aes_cipher(key: bytes, mode: Modes, nonce_or_iv: bytes) -> typing.Any:
    if mode == Modes.MODE_EAX:
        return _EAX(key, nonce_or_iv)

    backend_mode = SUPPORTED[mode]
    assert backend_mode is not None

    if mode in modes_.SPECIAL and mode == Modes.MODE_CCM:
        if not 7 <= len(nonce_or_iv) <= 13:
            msg = "Length of nonce must be between 7 and 13 bytes"
            raise ValueError(msg)
        return backend_mode(key)

    assert not issubclass(backend_mode, aead.AESCCM)
    return CrCipher(algo.AES(key), backend_mode(nonce_or_iv))


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
        NonAEAD(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
        tag_length=tag_length,
        offset=15,
    )
