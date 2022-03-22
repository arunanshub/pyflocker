"""Implementation of AES cipher."""
from __future__ import annotations

import contextlib
import typing
from types import MappingProxyType
from typing import TYPE_CHECKING

from Cryptodome.Cipher import AES

from ... import exc, modes
from ...modes import Modes as _Modes
from ..symmetric import FileCipherWrapper, HMACWrapper
from .misc import derive_hkdf_key
from .symmetric import AEADCipherTemplate, NonAEADCipherTemplate

if TYPE_CHECKING:  # pragma: no cover
    import io

    from ... import base

SUPPORTED = MappingProxyType(
    {
        # classic modes
        _Modes.MODE_CTR: AES.MODE_CTR,
        _Modes.MODE_CFB: AES.MODE_CFB,
        _Modes.MODE_CFB8: AES.MODE_CFB,  # compat with pyca/cryptography
        _Modes.MODE_OFB: AES.MODE_OFB,
        # AEAD modes
        _Modes.MODE_GCM: AES.MODE_GCM,
        _Modes.MODE_EAX: AES.MODE_EAX,
        _Modes.MODE_SIV: AES.MODE_SIV,
        _Modes.MODE_CCM: AES.MODE_CCM,
        _Modes.MODE_OCB: AES.MODE_OCB,
    }
)

del MappingProxyType


def _get_aes_cipher(
    key: bytes,
    mode: _Modes,
    iv_or_nonce: bytes,
) -> typing.Any:
    args = (iv_or_nonce,)
    kwargs = {}

    if mode == _Modes.MODE_CFB:
        # compat with pyca/cryptography's CFB(...) mode
        kwargs = {"segment_size": 128}
    elif mode == _Modes.MODE_CTR:
        kwargs = {
            # initial value of Cryptodome is nonce for pyca/cryptography
            "initial_value": int.from_bytes(iv_or_nonce, "big"),
            "nonce": b"",
        }

        args = ()

    return AES.new(key, SUPPORTED[mode], *args, **kwargs)  # type: ignore


class AEAD(AEADCipherTemplate):
    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: _Modes,
        nonce: bytes,
    ):
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode
        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )

    @property
    def mode(self) -> _Modes:
        """The AES mode."""
        return self._mode


class NonAEAD(NonAEADCipherTemplate):
    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: _Modes,
        nonce: bytes,
    ):
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode

        # creating a context is relatively expensive here
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )

    @property
    def mode(self) -> _Modes:
        """The AES mode."""
        return self._mode


class AEADOneShot(AEAD):
    def __init__(
        self,
        encrypting: bool,
        key: bytes,
        mode: _Modes,
        nonce: bytes,
    ):
        self._cipher = _get_aes_cipher(key, mode, nonce)
        self._updated = False
        self._encrypting = encrypting
        self._mode = mode

        # creating a context is relatively expensive here
        self._update_func = self._get_update_func(encrypting, self._cipher)

    @property
    def mode(self) -> _Modes:
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

    def update(self, data: bytes, tag: typing.Optional[bytes] = None) -> bytes:
        return self.update_into(data, None, tag)  # type: ignore

    def update_into(
        self,
        data: bytes,
        out: typing.Union[bytearray, memoryview],
        tag: typing.Optional[bytes] = None,
    ) -> bytes:
        if self._update_func is None:
            raise exc.AlreadyFinalized

        if not self._encrypting and tag is None:
            raise ValueError("tag is required for decryption.")

        # decryption error is ignored, and raised from finalize method
        with contextlib.suppress(ValueError):
            try:
                data = self._update_func(data, tag, output=out)
            except TypeError as e:
                # incorrect nos. of arguments.
                if out is not None:
                    raise TypeError(
                        f"{self._mode} does not support writing into mutable "
                        "buffers"
                    ) from e
                data = self._update_func(data, tag)

        self.finalize(tag)
        return data


def new(
    encrypting: bool,
    key: bytes,
    mode: _Modes,
    iv_or_nonce: bytes,
    *,
    use_hmac: bool = False,
    tag_length: typing.Optional[int] = 16,
    digestmod: typing.Union[str, base.BaseHash] = "sha256",
    file: typing.Optional[io.BufferedReader] = None,
) -> typing.Union[AEAD, NonAEAD, AEADOneShot, FileCipherWrapper, HMACWrapper]:
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
            The algorithm to use for HMAC. Defaults to ``sha256``. Specifying
            this value without setting ``use_hmac`` to True has no effect.
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
    crp: typing.Any

    if file is not None:
        use_hmac = True

    if mode not in supported_modes():
        raise NotImplementedError(f"{mode} not supported.")

    if mode in modes.SPECIAL:
        if file is not None:
            raise NotImplementedError(
                f"{mode} does not support encryption/decryption of files."
            )
        crp = AEADOneShot(encrypting, key, mode, iv_or_nonce)
    elif mode in modes.AEAD:
        crp = AEAD(encrypting, key, mode, iv_or_nonce)
    else:
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
            crp = NonAEAD(encrypting, key, mode, iv_or_nonce)

    if file:
        crp = FileCipherWrapper(crp, file)

    return crp


def supported_modes() -> typing.Set[_Modes]:
    """Lists all modes supported by AES cipher of this backend.

    Returns:
        set of :any:`Modes` object supported by backend.
    """
    return set(SUPPORTED)


def _wrap_hmac(
    encrypting: bool,
    key: bytes,
    mode: _Modes,
    iv_or_nonce: bytes,
    hashalgo: typing.Any,
    tag_length: typing.Optional[int],
) -> HMACWrapper:
    ckey, hkey = derive_hkdf_key(key, len(key), hashalgo, iv_or_nonce)
    return HMACWrapper(
        NonAEAD(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        hashalgo,
        tag_length=tag_length,
    )
