from cryptography.hazmat.primitives.ciphers import (algorithms as algo, Cipher
                                                    as CrCipher)
from cryptography import exceptions as bkx
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.poly1305 import Poly1305

from .. import exc, base
from ._symmetric import (CipherWrapper, FileCipherMixin)

# we don't have any mode to support
supported = frozenset()


@base.cipher
class ChaCha20Poly1305(CipherWrapper, base.Cipher):
    def __init__(self, locking, key, nonce):
        self._locking = locking
        self._hasher = Poly1305(key)
        self._cipher = CrCipher(algo.ChaCha20(key, nonce), None, defb())
        self._tag = None
        self._updated = False
        super().__init__()

    def authenticate(self, data):
        if self._updated:
            raise TypeError('cannot authenticate data '
                            'after update has been called')
        self._hasher.update(data)

    def finalize(self, tag=None):
        self._cipher.finalize()
        if not self._locking:
            try:
                self._hasher.verify(tag)
            except bkx.InvalidSignature as e:
                raise exc.DecryptionError from e

    def calculate_tag(self):
        if self._locking:
            if not self._tag:
                self._tag = self._hasher.finalize()
            return self._tag


class ChaCha20Poly1305File(FileCipherMixin, ChaCha20Poly1305):
    pass
