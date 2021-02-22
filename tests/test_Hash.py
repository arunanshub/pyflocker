import os
from itertools import product

import pytest

from pyflocker.ciphers import Hash, exc
from pyflocker.ciphers.backends import Backends

# shake* & blake* => variable digest size
# sha3_*, shake* => no block size

_HASHES = Hash.algorithms_available() ^ {
    "blake2b",
    "blake2s",
    "shake128",
    "shake256",
}
_SHAKE_HASHES = {
    "shake128",
    "shake256",
}
_BLAKE_HASHES = {
    "blake2b",
    "blake2s",
}


@pytest.fixture
def hashfunc(name, digest_size, backend1, backend2):
    try:
        h1 = Hash.new(name, digest_size=digest_size, backend=backend1)
    except KeyError:
        assert name not in Hash.algorithms_available(backend1)
        pytest.skip(f"{name} not supported by {backend1}")
    except ValueError:
        assert backend1 == Backends.CRYPTOGRAPHY
        pytest.skip(
            f"{backend1} does not support variable digest size for {name}."
        )

    try:
        h2 = Hash.new(name, digest_size=digest_size, backend=backend2)
    except KeyError:
        assert name not in Hash.algorithms_available(backend2)
        pytest.skip(f"{name} not supported by {backend2}")
    except ValueError:
        assert backend2 == Backends.CRYPTOGRAPHY
        pytest.skip(
            f"{backend2} does not support variable digest size for {name}."
        )
    return h1, h2


def _assert_finalized(hash1, hash2):
    for h in hash1, hash2:
        with pytest.raises(exc.AlreadyFinalized):
            h.update(b"monke")


@pytest.mark.parametrize(
    "name",
    _HASHES,
)
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "datalen",
    [0, 64, 128],
)
@pytest.mark.parametrize(
    "digest_size",
    [None],
)
def test_same_hash(hashfunc, backend1, backend2, datalen):
    h1, h2 = hashfunc
    data = os.urandom(datalen)
    h1.update(data)
    h2.update(data)
    assert h1.digest() == h2.digest()
    _assert_finalized(h1, h2)


def _hash_var_digest_size(hashfunc, backend1, backend2, datalen):
    h1, h2 = hashfunc
    data = os.urandom(datalen)
    h1.update(data)
    h2.update(data)
    assert h1.digest() == h2.digest()
    _assert_finalized(h1, h2)


@pytest.mark.parametrize(
    "name",
    _SHAKE_HASHES,
)
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "datalen",
    [0, 64, 128],
)
@pytest.mark.parametrize(
    "digest_size",
    list(range(1, 65)),
)
def test_same_hash_shake(hashfunc, backend1, backend2, datalen):
    return _hash_var_digest_size(hashfunc, backend1, backend2, datalen)


@pytest.mark.parametrize(
    "name",
    ["blake2b"],
)
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "datalen",
    [0, 64, 128],
)
@pytest.mark.parametrize(
    "digest_size",
    list(range(1, 65)),
)
def test_same_hash_blake2b(hashfunc, backend1, backend2, datalen):
    return _hash_var_digest_size(hashfunc, backend1, backend2, datalen)


@pytest.mark.parametrize(
    "name",
    ["blake2s"],
)
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
@pytest.mark.parametrize(
    "datalen",
    [0, 64, 128],
)
@pytest.mark.parametrize(
    "digest_size",
    list(range(1, 33)),
)
def test_same_hash_blake2s(hashfunc, backend1, backend2, datalen):
    return _hash_var_digest_size(hashfunc, backend1, backend2, datalen)
