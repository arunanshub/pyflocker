import hashlib
from itertools import combinations_with_replacement as repcomb

import pytest

from pyflocker.ciphers import RSA
from pyflocker.ciphers.backends import Backends

SERIALIZATION_KEY = hashlib.sha256(b"SERIALIZATION_KEY").digest()


@pytest.mark.parametrize("key_size", [1024, 2048, 4096])
@pytest.mark.parametrize("backend1, backend2", list(repcomb(Backends, 2)))
def test_private_key_serde(
    key_size: int,
    backend1: Backends,
    backend2: Backends,
):
    priv_key = RSA.generate(key_size, backend=backend1)
    serialized = priv_key.serialize(passphrase=SERIALIZATION_KEY)

    with pytest.raises(ValueError):
        RSA.load_private_key(serialized, b"incorrect key", backend=backend2)

    priv_key_2 = RSA.load_private_key(
        serialized,
        SERIALIZATION_KEY,
        backend=backend2,
    )

    assert priv_key.n == priv_key_2.n  # type: ignore
    assert priv_key.e == priv_key_2.e  # type: ignore
    assert priv_key.p == priv_key_2.p  # type: ignore
    assert priv_key.q == priv_key_2.q  # type: ignore
    assert priv_key.d == priv_key_2.d  # type: ignore
