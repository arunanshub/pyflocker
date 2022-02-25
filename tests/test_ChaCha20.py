from __future__ import annotations

import hashlib
from functools import partial
from itertools import product

import pytest

from pyflocker.ciphers import ChaCha20
from pyflocker.ciphers.backends import Backends

from .base import BaseSymmetric, BaseSymmetricAEAD

TEST_VECTOR_KEY = hashlib.sha3_512(b"TEST_VECTOR_KEY for ChaCha20").digest()[
    :32
]
TEST_VECTOR_NONCE = hashlib.sha3_512(
    b"TEST_VECTOR_NONCE for ChaCha20"
).digest()


@pytest.fixture
def cipher(nonce_length, use_poly1305):
    return partial(
        ChaCha20.new,
        key=TEST_VECTOR_KEY,
        nonce=TEST_VECTOR_NONCE[:nonce_length],
        use_poly1305=use_poly1305,
    )


@pytest.mark.parametrize(
    "backend1, backend2",
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "nonce_length",
    [8, 12],
)
@pytest.mark.parametrize(
    "use_poly1305",
    [False],
)
class TestChaCha20(BaseSymmetric):
    def test_update_into(self, cipher, backend1, backend2):
        return super().test_update_into(
            cipher,
            backend1,
            backend2,
            offset=0,
        )


@pytest.mark.parametrize(
    "backend1, backend2",
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "nonce_length",
    [8, 12],
)
@pytest.mark.parametrize(
    "use_poly1305",
    [True],
)
class TestChaCha20Poly1305(BaseSymmetricAEAD):
    def test_update_into(self, cipher, backend1, backend2):
        return super().test_update_into(
            cipher,
            backend1,
            backend2,
            offset=0,
        )

    def test_update_into_with_auth(
        self,
        cipher,
        backend1,
        backend2,
    ):
        return super().test_update_into_with_auth(
            cipher,
            backend1,
            backend2,
            offset=0,
        )
