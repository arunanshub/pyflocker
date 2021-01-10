from Cryptodome.Cipher import (
    ChaCha20 as _ChaCha20,
    ChaCha20_Poly1305 as _ChaCha20_Poly1305,
)

from ... import base
from .symmetric import (
    NonAEADCipherTemplate,
    AEADCipherTemplate,
    FileCipherWrapper,
)


def new(encrypting, key, nonce, *, use_poly1305=True, file=None):
    if use_poly1305:
        crp = ChaCha20Poly1305(encrypting, key, nonce)
    else:
        crp = ChaCha20(encrypting, key, nonce)

    if file:
        crp = FileCipherWrapper(crp, file)

    return crp


class ChaCha20(NonAEADCipherTemplate):
    def __init__(self, encrypting, key, nonce):
        self._cipher = _ChaCha20.new(key=key, nonce=nonce)
        self._encrypting = encrypting
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )


class ChaCha20Poly1305(AEADCipherTemplate):
    def __init__(self, encrypting, key, nonce):
        self._cipher = _ChaCha20_Poly1305.new(key=key, nonce=nonce)
        self._encrypting = encrypting
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )
        self._updated = False
