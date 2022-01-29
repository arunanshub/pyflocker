import os
from itertools import combinations, product
from typing import Tuple

import pytest

from pyflocker.ciphers import Hash, exc
from pyflocker.ciphers.backends import Backends
from pyflocker.ciphers.base import BaseHash

ALL_HASHES = Hash.algorithms_available()

# XOF here is simply a catch-all term for hashes that are neither blakes nor
# fixed digest-size. This has no relation to the cryptographically defined XOF.
XOFS = {
    "shake128",
    "shake256",
    "cshake128",
    "cshake256",
    "kangarootwelve",
    "tuplehash128",
    "tuplehash256",
}

BLAKES = {
    "blake2b",
    "blake2s",
}

VAR_DIGEST_SIZE = XOFS | BLAKES

FIXED_DIGEST_SIZE = ALL_HASHES ^ VAR_DIGEST_SIZE


@pytest.fixture
def hashfuncs(
    name: str,
    digest_size: int,
    custom: bytes,
    key: bytes,
    backend1: Backends,
    backend2: Backends,
) -> Tuple[BaseHash, BaseHash]:
    hashes = []
    for backend in (backend1, backend2):
        try:
            hashes.append(
                Hash.new(
                    name,
                    digest_size=digest_size,
                    backend=backend,
                    custom=custom,
                    key=key,
                )
            )
        except KeyError:
            assert (
                name not in Hash.algorithms_available(backend)
                and name in Hash.algorithms_available()
            )
            return pytest.skip(f"{name!r} unsupported by {backend.name!r}")
        except ValueError:
            # CRYPTOGRAPHY does not support variable size digests for Blakes.
            # In essence, they function like fixed digest-size hashes (eg SHA).
            assert backend == Backends.CRYPTOGRAPHY
            assert name in BLAKES
            if name == "blake2s":
                assert digest_size != 32
            if name == "blake2b":
                assert digest_size != 64

            return pytest.skip(
                f"Variable digest size unsupported for {name!r} by"
                f" {backend.name!r}"
            )

    return tuple(hashes)


def _check_equal_and_check_finalize_once(h1: BaseHash, h2: BaseHash):
    """
    Assert that hash matches and assert that `update`, `copy` cannot be called
    after calling `finalize`.
    """
    assert h1.digest() == h2.digest()
    assert h1.hexdigest() == h2.hexdigest()

    for each in h1, h2:
        with pytest.raises(exc.AlreadyFinalized):
            each.update(b"")
        with pytest.raises(exc.AlreadyFinalized):
            each.copy()
        assert isinstance(each.new(), type(each))


@pytest.mark.parametrize("name", ALL_HASHES ^ BLAKES)
@pytest.mark.parametrize("digest_size", [15])
@pytest.mark.parametrize("custom", [None])
@pytest.mark.parametrize("key", [None])
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(combinations(Backends, 2)),
)
def test_oid_matches_except_blakes(hashfuncs: Tuple[BaseHash, BaseHash]):
    h1, h2 = hashfuncs
    assert h1.oid == h2.oid  # type: ignore


@pytest.mark.parametrize("name", FIXED_DIGEST_SIZE)
@pytest.mark.parametrize("digest_size", [None])
@pytest.mark.parametrize("custom", [None])
@pytest.mark.parametrize("key", [None])
@pytest.mark.parametrize("do_update", [False, True])
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
def test_fixed_digest_size_hash_matches(
    hashfuncs: Tuple[BaseHash, BaseHash],
    do_update,
):
    h1, h2 = hashfuncs
    if do_update:
        data = os.urandom(32)
        for each in h1, h2:
            each.update(data)
    _check_equal_and_check_finalize_once(h1, h2)


@pytest.mark.parametrize("name", XOFS)
@pytest.mark.parametrize("digest_size", range(8, 32))
@pytest.mark.parametrize("custom", [None, os.urandom(32)])
@pytest.mark.parametrize("key", [None])
@pytest.mark.parametrize("do_update", [False, True])
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
def test_xofs_with_custom_hash_matches(
    hashfuncs: Tuple[BaseHash, BaseHash],
    do_update,
):
    h1, h2 = hashfuncs
    if do_update:
        data = os.urandom(32)
        for each in h1, h2:
            each.update(data)
    _check_equal_and_check_finalize_once(h1, h2)


@pytest.mark.parametrize("name", ["blake2s"])
@pytest.mark.parametrize("digest_size", range(1, 32))
@pytest.mark.parametrize("custom", [None])
@pytest.mark.parametrize("key", [None, os.urandom(32)])
@pytest.mark.parametrize("do_update", [False, True])
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
def test_blake2s_with_key_hash_matches(
    hashfuncs: Tuple[BaseHash, BaseHash],
    do_update,
):
    h1, h2 = hashfuncs
    if do_update:
        data = os.urandom(32)
        for each in h1, h2:
            each.update(data)
    _check_equal_and_check_finalize_once(h1, h2)


@pytest.mark.parametrize("name", ["blake2b"])
@pytest.mark.parametrize("digest_size", range(1, 64))
@pytest.mark.parametrize("custom", [None])
@pytest.mark.parametrize("key", [None, os.urandom(32)])
@pytest.mark.parametrize("do_update", [False, True])
@pytest.mark.parametrize(
    ["backend1", "backend2"],
    list(product(Backends, repeat=2)),
)
def test_blake2b_with_key_hash_matches(
    hashfuncs: Tuple[BaseHash, BaseHash],
    do_update,
):
    h1, h2 = hashfuncs
    if do_update:
        data = os.urandom(32)
        for each in h1, h2:
            each.update(data)
    _check_equal_and_check_finalize_once(h1, h2)
