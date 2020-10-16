"""
Simple tests for AES

These tests are meant to check the API and hence, do not use
the official test vectors. The backends used by pyflocker
implements the tests using the required test vectors.
"""
import os
import io

import pytest
from functools import partial
from itertools import product
from pyflocker.ciphers import AES, Modes, Backends, exc

from .base import BaseSymmetric

_LENGTH_NORMAL = (16, 24, 32)
_LENGTH_SPECIAL_SIV = (32, 48, 64)


@pytest.fixture
def cipher(key_length, mode, iv_length, backend1, backend2):
    if mode not in AES.supported_modes(backend1):
        pytest.skip(f"{backend1} doesn't support {mode}")
    elif mode not in AES.supported_modes(backend2):
        pytest.skip(f"{backend2} doesn't support {mode}")

    return partial(
        AES.new,
        key=os.urandom(key_length),
        mode=mode,
        iv_or_nonce=os.urandom(iv_length),
    )


@pytest.mark.parametrize(
    "iv_length",
    [16],
)
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(list(Backends), repeat=2)),
)
@pytest.mark.parametrize(
    "key_length",
    _LENGTH_NORMAL,
)
@pytest.mark.parametrize(
    "mode",
    set(Modes) ^ AES.special,
)
class TestAES(BaseSymmetric):
    def test_auth(self, cipher, backend1, backend2, mode):
        """Check authentication for both HMAC and AEAD."""
        kwargs = {}
        if mode not in AES.aead:
            kwargs = dict(hashed=True)

        enc = cipher(True, backend=backend1, **kwargs)
        dec = cipher(False, backend=backend2, **kwargs)

        authdata, data = os.urandom(32).hex().encode(), bytes(32)
        enc.authenticate(authdata)
        dec.authenticate(authdata)

        assert dec.update(enc.update(data)) == data
        enc.finalize()
        try:
            dec.finalize(enc.calculate_tag())
        except exc.DecryptionError:
            pytest.fail("Authentication check failed")


@pytest.mark.parametrize(
    "backend1, backend2",
    list(product(list(Backends), repeat=2)),
)
@pytest.mark.parametrize(
    "key_length",
    set(_LENGTH_NORMAL) | set(_LENGTH_SPECIAL_SIV),
)
@pytest.mark.parametrize(
    "mode",
    AES.special,
)
@pytest.mark.parametrize(
    "iv_length",
    [13],
)
class TestAESAEADSpecial(BaseSymmetric):
    def test_update_into(self, cipher, mode, backend1, backend2):
        try:
            enc = cipher(True, backend=backend1)
            dec = cipher(False, backend=backend2)
        except NotImplementedError:
            return
            assert mode not in AES.supported_modes(backend1)
        except ValueError:
            # error raised by backend: probably key errors
            assert (
                mode == AES.MODE_SIV
                or len(cipher.keywords["key"])  # noqa: W503
                in _LENGTH_SPECIAL_SIV
            )
            return

        rbuf = memoryview(bytearray(16384))
        wbuf = memoryview(bytearray(16384))
        test = memoryview(bytearray(16384))

        try:
            enc.update_into(rbuf, wbuf)
        except TypeError:
            pytest.skip("Writing into buffer not supported " f"by mode {mode}")
        with pytest.raises(ValueError):
            dec.update_into(wbuf, test)

        try:
            dec.update_into(wbuf, test, enc.calculate_tag())
        except exc.DecryptionError:
            pytest.fail("Authentication check failed")

        assert rbuf.tobytes() == test.tobytes()

    def test_update(self, cipher, mode, backend1, backend2, key_length):
        try:
            enc = cipher(True, backend=backend1)
            enc1 = cipher(True, backend=backend1)
            dec = cipher(False, backend=backend2)
        except ValueError:
            assert mode == AES.MODE_SIV or key_length in _LENGTH_SPECIAL_SIV
            return

        data = bytes(32)
        with pytest.raises(ValueError):
            # test tag requirement case
            assert dec.update(enc1.update(data)) == data

        try:
            assert dec.update(enc.update(data), enc.calculate_tag()) == data
        except exc.DecryptionError:
            pytest.fail("Authentication check failed")
