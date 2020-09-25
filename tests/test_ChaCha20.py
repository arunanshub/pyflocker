import os
import pytest

from functools import partial
from pyflocker.ciphers import ChaCha20, Backends

from .base import BaseSymmetric


@pytest.fixture
def cipher(nonce_length):
    return partial(ChaCha20.new,
                   key=os.urandom(32),
                   nonce=os.urandom(nonce_length))


@pytest.mark.parametrize(
    'nonce_length',
    [8, 12],
)
@pytest.mark.parametrize(
    'backend',
    list(Backends),
)
class TestChaCha20Poly1305(BaseSymmetric):
    pass
