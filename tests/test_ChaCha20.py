import os
import pytest

from functools import partial
from pyflocker.ciphers import ChaCha20, Backends, exc

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
    "backend",
    list(Backends),
)
class TestChaCha20Poly1305(BaseSymmetric):
    def test_auth(self, cipher, backend):
        """Check authentication for both HMAC and AEAD."""
        enc = cipher(True, backend=backend)
        dec = cipher(False, backend=backend)

        authdata, data = os.urandom(32).hex().encode(), bytes(32)
        enc.authenticate(authdata)
        dec.authenticate(authdata)

        assert dec.update(enc.update(data)) == data
        enc.finalize()
        try:
            dec.finalize(enc.calculate_tag())
        except exc.DecryptionError:
            pytest.fail("Authentication check failed")
