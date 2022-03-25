"""ChaCha20 and ChaCha20Poly1305 cipher implementation classes."""

from __future__ import annotations

import typing

from cryptography import exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as algo
from cryptography.hazmat.primitives.poly1305 import Poly1305

from ... import base, exc
from ..symmetric import FileCipherWrapper, _DecryptionCtx, _EncryptionCtx
from .misc import derive_poly1305_key
from .symmetric import NonAEADCipherTemplate

if typing.TYPE_CHECKING:
    import io


class ChaCha20Poly1305(base.BaseAEADCipher):
    """ChaCha20Poly1305 Cipher class."""

    def __init__(self, encrypting: bool, key: bytes, nonce: bytes):
        if not len(nonce) in (8, 12):
            raise ValueError("A 8 or 12 byte nonce is required")
        if len(nonce) == 8:
            nonce = bytes(4) + nonce

        cipher = Cipher(
            algo.ChaCha20(
                key,
                (1).to_bytes(4, "little") + nonce,
            ),
            None,
            defb(),
        )

        ctx = cipher.encryptor() if encrypting else cipher.decryptor()

        self._encrypting = encrypting
        self._auth = Poly1305(derive_poly1305_key(key, nonce))
        self._ctx = self._get_auth_ctx(encrypting, ctx, self._auth)
        self._len_aad, self._len_ct = 0, 0
        self._updated = False
        self._tag = None

    @staticmethod
    def _get_auth_ctx(
        encrypting: bool,
        ctx: typing.Any,
        auth: typing.Any,
    ) -> _EncryptionCtx | _DecryptionCtx:
        if encrypting:
            return _EncryptionCtx(ctx, auth, 0)
        return _DecryptionCtx(ctx, auth)

    def _pad_aad(self) -> None:
        if not self._updated and self._len_aad & 0x0F:
            self._auth.update(bytes(16 - (self._len_aad & 0x0F)))
        self._updated = True

    def is_encrypting(self) -> bool:
        return self._encrypting

    def authenticate(self, data: bytes) -> None:
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if self._updated:
            raise TypeError
        self._len_aad += len(data)
        self._auth.update(data)

    def update(self, data: bytes) -> bytes:
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._pad_aad()
        self._len_ct += len(data)
        return self._ctx.update(data)

    def update_into(
        self,
        data: bytes,
        out: memoryview | bytearray,
    ) -> None:
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._pad_aad()
        self._len_ct += len(out)
        self._ctx.update_into(data, out)

    def finalize(self, tag: bytes | None = None) -> None:
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if not self.is_encrypting() and tag is None:
            raise ValueError("tag is required for decryption")

        self._pad_aad()

        if self._len_ct & 0x0F:
            self._auth.update(bytes(16 - (self._len_ct & 0x0F)))

        self._auth.update(self._len_aad.to_bytes(8, "little"))
        self._auth.update(self._len_ct.to_bytes(8, "little"))

        self._ctx = None

        if not self.is_encrypting():
            assert tag is not None
            try:
                self._auth.verify(tag)
            except bkx.InvalidSignature as e:
                raise exc.DecryptionError from e
        else:
            self._tag = self._auth.finalize()

    def calculate_tag(self) -> bytes | None:
        if self._ctx is not None:
            raise exc.NotFinalized

        if self.is_encrypting():
            return self._tag


class ChaCha20(NonAEADCipherTemplate):
    """ChaCha20 Cipher class.

    This class alone does not provide any authentication. For AEAD purposes,
    wrap ``ChaCha20`` object with a class that implements ``BaseAEADCipher`` or
    use ``ChaCha20Poly1305``.
    """

    def __init__(self, encrypting: bool, key: bytes, nonce: bytes):
        if not len(nonce) in (8, 12):
            raise ValueError("A 8 or 12 byte nonce is required")
        if len(nonce) == 8:
            nonce = bytes(4) + nonce

        cipher = Cipher(
            algo.ChaCha20(
                key,
                bytes(4) + nonce,
            ),
            None,
            defb(),
        )

        self._ctx = cipher.encryptor() if encrypting else cipher.decryptor()
        self._encrypting = encrypting


def new(
    encrypting: bool,
    key: bytes,
    nonce: bytes,
    *,
    use_poly1305: bool = True,
    file: io.BufferedReader | None = None,
) -> ChaCha20 | ChaCha20Poly1305 | FileCipherWrapper:
    """Instantiate a new ChaCha20(-Poly1305) cipher object.

    Args:
        encrypting: True is encryption and False is decryption.
        key: The key for the cipher.
        nonce:
            The Nonce for the cipher. It must not be repeated with the same
            key.

    Keyword Arguments:
        use_poly1305: Whether to use Poly1305 MAC with ChaCha20 cipher.
        file: The source file to read from.

    Returns:
        ChaCha20(-Poly1305) cipher wrapper object.

    Note:
        Any other error that is raised is from the backend itself.
    """
    crp: typing.Any

    if file is not None:
        use_poly1305 = True

    if use_poly1305:
        crp = ChaCha20Poly1305(encrypting, key, nonce)
    else:
        crp = ChaCha20(encrypting, key, nonce)

    if file:
        crp = FileCipherWrapper(crp, file, offset=0)

    return crp
