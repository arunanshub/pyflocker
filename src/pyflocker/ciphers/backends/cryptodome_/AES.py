"""Implementation of AES cipher."""
from __future__ import annotations

import contextlib
import typing
from types import MappingProxyType
from typing import TYPE_CHECKING

from Cryptodome.Cipher import AES

from pyflocker.ciphers import base, exc, modes
from pyflocker.ciphers.backends.symmetric import FileCipherWrapper, HMACWrapper
from pyflocker.ciphers.base import BaseAEADOneShotCipher
from pyflocker.ciphers.modes import Modes

from . import Hash
from .misc import derive_hkdf_key
from .symmetric import (
    AEADCipherTemplate,
    AuthenticationMixin,
    NonAEADCipherTemplate,
)

if TYPE_CHECKING:  # pragma: no cover
    import io

SUPPORTED = MappingProxyType(
    {
        # classic modes
        Modes.MODE_CTR: AES.MODE_CTR,
        Modes.MODE_CFB: AES.MODE_CFB,
        Modes.MODE_CFB8: AES.MODE_CFB,  # compat with pyca/cryptography
        Modes.MODE_OFB: AES.MODE_OFB,
        # AEAD modes
        Modes.MODE_GCM: AES.MODE_GCM,
        Modes.MODE_EAX: AES.MODE_EAX,
        Modes.MODE_SIV: AES.MODE_SIV,
        Modes.MODE_CCM: AES.MODE_CCM,
        Modes.MODE_OCB: AES.MODE_OCB,
    }
)

del MappingProxyType


def _get_aes_cipher(
    key: bytes,
    mode: Modes,
    iv_or_nonce: bytes,
) -> typing.Any:
    args: tuple[bytes, ...] = (iv_or_nonce,)
    kwargs = {}

    if mode == Modes.MODE_CFB:
        # compat with pyca/cryptography's CFB(...) mode
        kwargs = {"segment_size": 128}
    elif mode == Modes.MODE_CTR:
        kwargs = {
            # initial value of Cryptodome is nonce for pyca/cryptography
            "initial_value": int.from_bytes(iv_or_nonce, "big"),
            "nonce": typing.cast("int", b""),
        }

        args = ()

    return AES.new(key, SUPPORTED[mode], *args, **kwargs)  # type: ignore


class AEAD(AEADCipherTemplate):
    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: Modes,
        nonce: bytes,
    ) -> None:
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode
        self._tag = None
        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )

    @property
    def mode(self) -> Modes:  # pragma: no cover
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
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode

        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )

    @property
    def mode(self) -> Modes:  # pragma: no cover
        """The AES mode."""
        return self._mode


class AEADOneShot(AuthenticationMixin, BaseAEADOneShotCipher):
    _write_into_buffer_unsupported = {Modes.MODE_OCB}

    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: Modes,
        nonce: bytes,
    ) -> None:
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode

        # creating a context is relatively expensive here
        self._update_func = self._get_update_func(encrypting, self._cipher)

    def is_encrypting(self) -> bool:
        return self._encrypting

    @property
    def mode(self) -> Modes:  # pragma: no cover
        """The AES mode."""
        return self._mode

    @staticmethod
    def _get_update_func(
        encrypting: bool,
        cipher: typing.Any,
    ) -> typing.Callable:
        if encrypting:
            func = cipher.encrypt_and_digest
            return lambda data, _=None, **k: func(data, **k)[0]

        func = cipher.decrypt_and_verify
        return lambda data, tag, **k: func(data, tag, **k)

    def update(self, data: bytes, tag: bytes | None = None) -> bytes:
        result = self._update_helper(data, None, tag)
        assert result is not None
        return result

    def _update_helper(
        self,
        data: bytes,
        out: bytearray | memoryview | None,
        tag: bytes | None = None,
    ) -> bytes | None:
        if self._update_func is None:
            raise exc.AlreadyFinalized

        update_func_kwargs = {}
        if self.mode in self._write_into_buffer_unsupported:
            # the mode does not support writing into mutable buffers.
            if out is not None:
                msg = f"writing into buffer unsupported by {self.mode.name}"
                raise NotImplementedError(msg)
        else:
            update_func_kwargs = {"output": out}

        if not self.is_encrypting() and tag is None:
            msg = "tag is required for decryption"
            raise ValueError(msg)

        result: bytes | None = None
        with contextlib.suppress(ValueError):
            result = self._update_func(data, tag, **update_func_kwargs)

        self.finalize(tag)
        return result

    def update_into(
        self,
        data: bytes,
        out: bytearray | memoryview,
        tag: bytes | None = None,
    ) -> None:
        self._update_helper(data, out, tag)


def new(
    encrypting: bool,
    key: bytes,
    mode: Modes,
    iv_or_nonce: bytes,
    *,
    use_hmac: bool = False,
    tag_length: int | None = 16,
    digestmod: None | base.BaseHash = None,
    file: io.BytesIO | io.BufferedReader | None = None,
) -> AEAD | NonAEAD | AEADOneShot | FileCipherWrapper | HMACWrapper:
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
            The source file to read from. If ``file`` is specified and the
            ``mode`` is not an AEAD mode, HMAC is always used.

    Important:
        The following arguments are ignored if the mode is an AEAD mode:

        - ``use_hmac``
        - ``tag_length``
        - ``digestmod``

    Returns:
        AES cipher.

    Raises:
        NotImplementedError:
            if the ``mode`` does not support encryption/decryption of files or
            the mode is not supported by the backend.

    Note:
        Any other error that is raised is from the backend itself.
    """
    cipher: base.BaseAEADCipher | base.BaseNonAEADCipher | FileCipherWrapper

    if mode not in supported_modes():
        msg = f"{mode.name} not supported."
        raise exc.UnsupportedMode(msg)

    is_mode_aead = mode in modes.AEAD
    is_file = file is not None
    use_hmac = (is_file and not is_mode_aead) or (
        use_hmac and not is_mode_aead
    )

    if mode in modes.SPECIAL:
        if is_file:
            msg = (
                f"{mode.name} does not support encryption/decryption of files."
            )
            raise NotImplementedError(msg)
        return AEADOneShot(encrypting, key, mode, iv_or_nonce)

    if is_mode_aead:
        cipher = AEAD(encrypting, key, mode, iv_or_nonce)
    else:
        cipher = NonAEAD(encrypting, key, mode, iv_or_nonce)

    if use_hmac:
        cipher = _wrap_hmac(
            encrypting,
            key,
            mode,
            iv_or_nonce,
            digestmod or Hash.new("sha256"),
            tag_length,
        )

    if file:
        assert isinstance(cipher, base.BaseAEADCipher)
        cipher = FileCipherWrapper(cipher, file)

    return cipher


def supported_modes() -> set[Modes]:
    """Lists all modes supported by AES cipher of this backend.

    Returns:
        set of :any:`Modes` object supported by backend.
    """
    return set(SUPPORTED)


def _wrap_hmac(
    encrypting: bool,
    key: bytes,
    mode: Modes,
    iv_or_nonce: bytes,
    hashalgo: base.BaseHash,
    tag_length: int | None,
) -> HMACWrapper:
    ckey, hkey = derive_hkdf_key(key, len(key), hashalgo, iv_or_nonce)
    return HMACWrapper(
        NonAEAD(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        hashalgo,
        tag_length=tag_length,
    )
