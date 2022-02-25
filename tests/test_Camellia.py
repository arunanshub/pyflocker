from __future__ import annotations

import hashlib
from functools import partial
from itertools import product

import pytest

from pyflocker.ciphers import Camellia, exc
from pyflocker.ciphers.backends import Backends
from pyflocker.ciphers.modes import Modes

from .base import BaseSymmetric, BaseSymmetricAEAD

_KEY_LENGTHS = (16, 24, 32)

_MODES = [Modes.MODE_CTR, Modes.MODE_CFB, Modes.MODE_OFB]

TEST_VECTOR_KEY = hashlib.sha3_512(b"TEST_VECTOR_KEY for AES").digest()
TEST_VECTOR_NONCE = hashlib.sha3_512(b"TEST_VECTOR_NONCE for AES").digest()[
    :16
]


@pytest.fixture
def cipher(key_length, mode, use_hmac, backend1, backend2):
    for b in backend1, backend2:
        try:
            if mode not in Camellia.supported_modes(b):
                pytest.skip(f"{mode} not supported by Camellia")
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Camellia not supported by {b}")

    return partial(
        Camellia.new,
        key=TEST_VECTOR_KEY[:key_length],
        mode=mode,
        iv_or_nonce=TEST_VECTOR_NONCE,
        use_hmac=use_hmac,
    )


@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "key_length",
    _KEY_LENGTHS,
)
@pytest.mark.parametrize(
    "mode",
    _MODES,
)
@pytest.mark.parametrize(
    "use_hmac",
    [False],
)
class TestCamellia(BaseSymmetric):
    def test_update_into(self, cipher, backend1, backend2):
        return super().test_update_into(cipher, backend1, backend2, offset=15)


@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "key_length",
    _KEY_LENGTHS,
)
@pytest.mark.parametrize(
    "mode",
    _MODES,
)
@pytest.mark.parametrize(
    "use_hmac",
    [True],
)
class TestCamelliaWithAuth(BaseSymmetricAEAD):
    def test_update_into(self, cipher, backend1, backend2):
        return super().test_update_into(cipher, backend1, backend2, offset=15)

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
            offset=15,
        )
