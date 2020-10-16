import pytest
import os

from functools import partial
from itertools import product
from pyflocker.ciphers import Camellia, Modes, Backends, exc

from .base import BaseSymmetric

_KEY_LENGTHS = (16, 24, 32)


@pytest.fixture
def cipher(mode, key_length, use_hmac, backend1, backend2):
    for b in [backend1, backend2]:
        try:
            if mode not in Camellia.supported_modes(b):
                pytest.skip(f"{mode} not supported by Camellia")
        except exc.UnsupportedAlgorithm:
            pytest.skip(f"Camellia not supported by {b}")

    return partial(
        Camellia.new,
        key=os.urandom(key_length),
        mode=mode,
        iv_or_nonce=os.urandom(16),
        hashed=use_hmac,
    )


@pytest.mark.parametrize(
    "use_hmac",
    [False, True],
)
@pytest.mark.parametrize(
    "backend1, backend2",
    list(product(list(Backends), repeat=2)),
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
    pass
