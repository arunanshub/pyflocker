"""ChaCha20 and ChaCha20Poly1305 cipher implementation classes."""

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


class ChaCha20Poly1305(base.BaseAEADCipher):
    """ChaCha20Poly1305 Cipher class."""

    def __init__(self, encrypting, key, nonce):
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
    def _get_auth_ctx(encrypting, ctx, auth):
        if encrypting:
            return _EncryptionCtx(ctx, auth, 0)
        return _DecryptionCtx(ctx, auth)

    def _pad_aad(self):
        if not self._updated:
            if self._len_aad & 0x0F:
                self._auth.update(bytes(16 - (self._len_aad & 0x0F)))
        self._updated = True

    def is_encrypting(self):
        return self._encrypting

    def authenticate(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if self._updated:
            raise TypeError
        self._len_aad += len(data)
        self._auth.update(data)

    def update(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._pad_aad()
        self._len_ct += len(data)
        return self._ctx.update(data)

    def update_into(self, data, out):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._pad_aad()
        self._len_ct += len(out)
        self._ctx.update_into(data, out)

    def finalize(self, tag=None):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        if not self.is_encrypting():
            if tag is None:
                raise ValueError("tag is required for decryption")

        self._pad_aad()

        if self._len_ct & 0x0F:
            self._auth.update(bytes(16 - (self._len_ct & 0x0F)))

        self._auth.update(self._len_aad.to_bytes(8, "little"))
        self._auth.update(self._len_ct.to_bytes(8, "little"))

        self._ctx = None

        if not self.is_encrypting():
            try:
                self._auth.verify(tag)
            except bkx.InvalidSignature as e:
                raise exc.DecryptionError from e
        else:
            self._tag = self._auth.finalize()

    def calculate_tag(self):
        if self._ctx is not None:
            raise exc.NotFinalized

        if self.is_encrypting():
            return self._tag


class ChaCha20(NonAEADCipherTemplate):
    """ChaCha20 Cipher class.

    This class alone does not provide any authentication. For AEAD purposes,
    wrap `ChaCha20` object with a class that implements `BaseAEADCipher` or
    use `ChaCha20Poly1305`.
    """

    def __init__(self, encrypting, key, nonce):
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
    key: typing.ByteString,
    nonce: typing.ByteString,
    *,
    use_poly1305: bool = True,
    file: typing.Optional[typing.BinaryIO] = None,
) -> typing.Union[ChaCha20, ChaCha20Poly1305, FileCipherWrapper]:
    """Instantiate a new ChaCha20-Poly1305 cipher wrapper object.

    Args:
        encrypting (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        nonce (bytes, bytearray, memoryview):
            The Nonce for the cipher.
            It must not be repeated with the same key.

    Keyword Arguments:
        use_poly1305 (bool): Whether to use Poly1305 MAC with ChaCha20 cipher.
        file (filelike): The source file to read from.

    Returns:
        :any:`BaseSymmetricCipher`:
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
