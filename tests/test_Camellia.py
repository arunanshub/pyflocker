import pytest
import os

from functools import partial
from pyflocker.ciphers import Camellia, Modes, Backends

from .base import SymBase


@pytest.fixture
def cipher(mode, key_length):
    return partial(
        Camellia.new,
        key=os.urandom(key_length),
        mode=mode,
        iv_or_nonce=os.urandom(16),
    )


@pytest.mark.parametrize(
    'backend',
    list(Backends),
)
@pytest.mark.parametrize(
    'mode',
    [Modes.MODE_CFB, Modes.MODE_CTR, Modes.MODE_OFB],
)
@pytest.mark.parametrize(
    'key_length',
    (16, 24, 32),
)
class TestCamellia(SymBase):
    pass
