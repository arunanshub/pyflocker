import os
from functools import partial
from itertools import product

import pytest

from pyflocker.ciphers import Backends, ChaCha20, exc

from .base import BaseSymmetric


@pytest.fixture
def cipher(nonce_length):
    return partial(
        ChaCha20.new, key=os.urandom(32), nonce=os.urandom(nonce_length)
    )


@pytest.mark.parametrize(
    "nonce_length",
    [8, 12],
)
@pytest.mark.parametrize(
    "backend1, backend2",
    list(product(list(Backends), repeat=2)),
)
class TestChaCha20Poly1305(BaseSymmetric):
    def test_update_into(self, cipher, backend1, backend2, authlen):
        return super().test_update_into(
            cipher,
            backend1,
            backend2,
            authlen,
            extend=None,
        )
