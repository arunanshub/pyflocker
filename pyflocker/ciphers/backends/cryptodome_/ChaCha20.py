try:
    from Cryptodome.Cipher import ChaCha20_Poly1305
except ModuleNotFoundError:
    from Crypto.Cipher import ChaCha20_Poly1305

from ._symmetric import AEADCipherWrapper, FileCipherMixin
from .. import base

supported = frozenset()


@base.cipher
class ChaCha20Poly1305(AEADCipherWrapper, base.Cipher):
    """The ChaCha20_Poly1305 cipher."""
    def __init__(self, locking, key, nonce):
        self._cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        self._locking = locking
        super().__init__()


class ChaCha20Poly1305File(FileCipherMixin, ChaCha20Poly1305):
    pass
