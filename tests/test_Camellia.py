import pytest
import os

from functools import partial
from pyflocker.ciphers import Camellia, Modes, Backends, exc

from .base import BaseSymmetric

_KEY_LENGTHS = (16, 24, 32)


@pytest.fixture
def cipher(mode, key_length):
    return partial(
        Camellia.new,
        key=os.urandom(key_length),
        mode=mode,
        iv_or_nonce=os.urandom(16),
    )


@pytest.mark.parametrize(
    "backend",
    list(Backends),
)
@pytest.mark.parametrize(
    "mode",
    list(Modes),
)
@pytest.mark.parametrize(
    "key_length",
    _KEY_LENGTHS,
)
class TestCamellia(BaseSymmetric):
    def test_update(self, cipher, backend, mode):
        try:
            super().test_update(cipher, backend)
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Backend {backend} does not support Camellia")
        except NotImplementedError:
            assert mode not in Camellia.supported_modes(backend)

    def test_update_into(self, cipher, backend, mode):
        try:
            super().test_update_into(cipher, backend)
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Backend {backend} does not support Camellia")
        except NotImplementedError:
            assert mode not in Camellia.supported_modes(backend)

    def test_write_into_file_buffer(self, cipher, backend, mode):
        try:
            super().test_write_into_file_buffer(cipher, backend)
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Backend {backend} does not support Camellia")
        except NotImplementedError:
            assert mode not in Camellia.supported_modes(backend)

    def test_auth(self, cipher, backend, mode):
        """Check authentication for HMAC."""
        try:
            enc = cipher(True, backend=backend, hashed=True)
            dec = cipher(False, backend=backend, hashed=True)
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Backend {backend} does not support Camellia")
        except NotImplementedError:
            assert mode not in Camellia.supported_modes(backend)
            return

        authdata, data = os.urandom(32).hex().encode(), bytes(32)
        enc.authenticate(authdata)
        dec.authenticate(authdata)

        assert dec.update(enc.update(data)) == data
        enc.finalize()
        try:
            dec.finalize(enc.calculate_tag())
        except exc.DecryptionError:
            pytest.fail("Authentication check failed")
