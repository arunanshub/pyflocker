from cryptography.hazmat.primitives.ciphers import (
    algorithms as algo,
    Cipher as CrCipher,
)
from cryptography import exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.poly1305 import Poly1305

from ... import base, exc
from ..symmetric import _EncryptionCtx, _DecryptionCtx
from .symmetric import NonAEADCipherTemplate


def new(encrypting, key, nonce, *, file=None, use_poly1305=True):
    if file is not None:
        use_poly1305 = True

    if use_poly1305:
        crp = ChaCha20Poly1305(encrypting, key, nonce)
    else:
        crp = ChaCha20(encrypting, key, nonce)

    if file:
        crp = FileCipherWrapper(crp, file, offset=0)

    return crp


def get_poly1305_key(ckey, nonce):
    """Generate a poly1305 key.

    Args:
        ckey (bytes): The key used for the cipher
        nonce (bytes): The nonce used for the cipher. It must be 12 bytes.

    Returns:
        bytes: A Poly1305 key.

    Raises:
        ValueError: If the length of nonce is not equal to 8 or 12 bytes.
    """
    if len(nonce) not in (8, 12):
        raise ValueError("Poly1305 key must be 16 bytes long.")

    if len(nonce) == 8:
        nonce = bytes(4) + nonce

    crp = CrCipher(
        algo.ChaCha20(ckey, bytes(4) + nonce),
        None,
        defb(),
    ).encryptor()
    return crp.update(bytes(32))


class ChaCha20Poly1305(base.BaseAEADCipher):
    def __init__(self, encrypting, key, nonce):
        if not len(nonce) in (8, 12):
            raise ValueError("A 8 or 12 byte nonce is required")
        if len(nonce) == 8:
            nonce = bytes(4) + nonce

        cipher = CrCipher(
            algo.ChaCha20(
                key,
                (1).to_bytes(4, "little") + nonce,
            ),
            None,
            defb(),
        )

        ctx = cipher.encryptor() if encrypting else cipher.decryptor()

        self._encrypting = encrypting
        self._auth = Poly1305(get_poly1305_key(key, nonce))
        self._ctx = self._get_auth_ctx(encrypting, ctx, self._auth)
        self._len_aad, self._len_ct = 0, 0
        self._updated = False

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
    def __init__(self, encrypting, key, nonce):
        if not len(nonce) in (8, 12):
            raise ValueError("A 8 or 12 byte nonce is required")
        if len(nonce) == 8:
            nonce = bytes(4) + nonce

        cipher = CrCipher(
            algo.ChaCha20(
                key,
                bytes(4) + nonce,
            ),
            None,
            defb(),
        )

        self._ctx = cipher.encryptor() if encrypting else cipher.decryptor()
        self._encrypting = encrypting
