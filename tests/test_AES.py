"""
Simple tests for AES

These tests are meant to check the API and hence, do not use
the official test vectors. The backends used by pyflocker
implements the tests using the required test vectors.
"""
import os
from functools import partial
from itertools import product

import pytest

from pyflocker.ciphers import AES, exc, modes
from pyflocker.ciphers.backends import Backends

from .base import BaseSymmetric, BaseSymmetricAEAD

_LENGTH_NORMAL = (16, 24, 32)
_LENGTH_SPECIAL_SIV = (32, 48, 64)
_MODE_NON_AEAD = set(modes.Modes) ^ modes.aead


@pytest.fixture
def cipher(key_length, mode, use_hmac, iv_length, backend1, backend2):
    if mode not in AES.supported_modes(backend1):
        pytest.skip(f"{backend1} doesn't support {mode}")
    elif mode not in AES.supported_modes(backend2):
        pytest.skip(f"{backend2} doesn't support {mode}")

    return partial(
        AES.new,
        key=os.urandom(key_length),
        mode=mode,
        iv_or_nonce=os.urandom(iv_length),
        use_hmac=use_hmac,
    )


@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "key_length",
    _LENGTH_NORMAL,
)
@pytest.mark.parametrize(
    "mode",
    _MODE_NON_AEAD,
)
@pytest.mark.parametrize(
    "use_hmac",
    [False],
)
@pytest.mark.parametrize(
    "iv_length",
    [16],
)
class TestNonAEAD(BaseSymmetric):
    def test_update_into(self, cipher, backend1, backend2):
        return super().test_update_into(cipher, backend1, backend2, offset=15)


@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "key_length",
    _LENGTH_NORMAL,
)
@pytest.mark.parametrize(
    "mode",
    set(modes.Modes) ^ modes.special,
)
@pytest.mark.parametrize(
    "use_hmac",
    [True],
)
@pytest.mark.parametrize(
    "iv_length",
    [16],
)
class TestAEAD(BaseSymmetricAEAD):
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


class TestAEADOneShot:
    pass
