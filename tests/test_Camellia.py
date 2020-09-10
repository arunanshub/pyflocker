import pytest
import os

from functools import partial
from pyflocker.ciphers import Camellia, Modes, Backends

from .base import SymBase


@pytest.fixture
def cipher(mode, key):
    return partial(
        Camellia.new,
        key=key,
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
    'key',
    map(os.urandom, (16, 24, 32)),
)
class TestCamellia(SymBase):
    pass
