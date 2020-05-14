try:
    from Cryptodome.Cipher import ChaCha20_Poly1305
except ModuleNotFoundError:
    from Crypto.Cipher import ChaCha20_Poly1305

from .AES import AEAD


supported = frozenset()


class ChaCha20Poly1305(AEAD):
    """The ChaCha20_Poly1305 cipher."""

    def __init__(self, file, locking, key, nonce):
        self._locking = locking
        self._file = file
        self._cipher = ChaCha20_Poly1305.new(
            key=key, nonce=nonce)

