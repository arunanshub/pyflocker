from __future__ import annotations

import typing
from itertools import combinations
from itertools import combinations_with_replacement as repcomb

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyflocker.ciphers import Backends, Hash, exc

if typing.TYPE_CHECKING:
    from pyflocker.ciphers.base import BaseHash

ALL_HASHES = Hash.algorithms_available()

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


def make_hash(
    hashname: str,
    backend: Backends,
    *,
    digest_size: int | None,
    custom: bytes | None,
    key: bytes | None,
):
    """
    Instantiate a new hash function with the given parameters. If the
    parameters are invalid, then it is `pytest.skip`ped.

    Before returning, we perform some basic checks.
    """
    try:
        hashobj = Hash.new(
            hashname,
            digest_size=digest_size,
            backend=backend,
            custom=custom,
            key=key,
        )
    except KeyError:
        assert (
            hashname not in Hash.algorithms_available(backend)
            and hashname in Hash.algorithms_available()
        )
        return pytest.skip(f"{hashname!r} is unsupported by {backend.name!r}")
    except ValueError as e:
        # CRYPTOGRAPHY does not support variable size digests for Blakes.
        # In essence, they function like fixed digest-size hashes (eg SHA).
        if hashname in BLAKES and digest_size is not None:
            if hashname == "blake2s":
                assert digest_size != 32
                assert backend == Backends.CRYPTOGRAPHY
            if hashname == "blake2b":
                assert digest_size != 64
                assert backend == Backends.CRYPTOGRAPHY
        else:
            raise e

        return pytest.skip(
            f"Variable digest size unsupported for {hashname!r} by"
            f" {backend.name!r}"
        )
    except TypeError as e:
        assert "unexpected keyword argument" in str(e)
        assert backend == Backends.CRYPTOGRAPHY
        return pytest.skip(
            f"{backend.name} does not support keying or customization bytes"
        )

    assert hashobj.block_size is not None
    return hashobj


def make_hash_pairs(
    hashname: str,
    backend1: Backends,
    backend2: Backends,
    *,
    digest_size: int | None,
    custom: bytes | None,
    key: bytes | None,
) -> tuple[BaseHash, BaseHash]:
    """
    Create a pair of hash functions with the given parameters. The first
    element of the pair is instantiated with `backend1` and the last element is
    from `backend2`.

    If the parameters are invalid, then `pytest.skip` is called.

    Before returning, we perform some basic checks.
    """
    hash1, hash2 = (
        make_hash(
            hashname,
            backend,
            digest_size=digest_size,
            custom=custom,
            key=key,
        )
        for backend in (backend1, backend2)
    )

    assert hash1.digest_size == hash2.digest_size
    assert hash1.name == hash2.name

    return hash1, hash2


class TestHashEqual:
    @pytest.mark.parametrize("hashname", FIXED_DIGEST_SIZE)
    @pytest.mark.parametrize(
        "backend1,backend2", list(combinations(Backends, 2))
    )
    @given(data=st.binary() | st.none())
    def test_fixed_digest_size_hash_equal(
        self,
        hashname: str,
        backend1: Backends,
        backend2: Backends,
        data: bytes,
    ):
        hash1, hash2 = make_hash_pairs(
            hashname,
            backend1,
            backend2,
            digest_size=None,
            custom=None,
            key=None,
        )
        if data is not None:
            hash1.update(data)
            hash2.update(data)

        assert (
            hash1.hexdigest()
            == hash2.hexdigest()
            == hash1.new(data).hexdigest()
            == hash2.new(data).hexdigest()
        )

    @given(data=st.binary() | st.none())
    @pytest.mark.parametrize(
        "backend1,backend2", list(combinations(Backends, 2))
    )
    @pytest.mark.parametrize(
        "hashname,digest_size",
        [
            ("blake2b", 64),
            ("blake2s", 32),
        ],
    )
    def test_blake_hash_equal(
        self,
        hashname: str,
        digest_size: int,
        backend1: Backends,
        backend2: Backends,
        data: bytes,
    ):
        hash1, hash2 = make_hash_pairs(
            hashname,
            backend1,
            backend2,
            digest_size=digest_size,
            custom=None,
            key=None,  # TODO: `key` is not supported by cryptography yet
        )
        if data:
            hash1.update(data)
            hash2.update(data)

        assert (
            hash1.hexdigest()
            == hash2.hexdigest()
            == hash1.new(data).hexdigest()
            == hash2.new(data).hexdigest()
        )

    @given(data=st.binary() | st.none(), key=st.binary())
    @pytest.mark.parametrize("backend1,backend2", list(repcomb(Backends, 2)))
    @pytest.mark.parametrize(
        "hashname,digest_size",
        [
            ("blake2b", 64),
            ("blake2s", 32),
        ],
    )
    def test_blake_with_key_hash_equal(
        self,
        hashname: str,
        data: bytes,
        key: bytes,
        digest_size: int,
        backend1: Backends,
        backend2: Backends,
    ):
        hash1, hash2 = make_hash_pairs(
            hashname,
            backend1,
            backend2,
            digest_size=digest_size,
            key=key,
            custom=None,
        )
        if data:
            hash1.update(data)
            hash2.update(data)

        assert (
            hash1.hexdigest()
            == hash2.hexdigest()
            == hash1.new(data, key=key).hexdigest()
            == hash2.new(data, key=key).hexdigest()
        )

    @given(
        data=st.binary() | st.none(),
        digest_size=st.integers(min_value=1, max_value=1000),
    )
    @pytest.mark.parametrize("hashname", list(XOFS))
    @pytest.mark.parametrize(
        "backend1,backend2", list(combinations(Backends, 2))
    )
    def test_xofs_hash_equal(
        self,
        hashname: str,
        backend1: Backends,
        backend2: Backends,
        data: bytes | None,
        digest_size: int,
    ):
        hash1, hash2 = make_hash_pairs(
            hashname,
            backend1,
            backend2,
            digest_size=digest_size,
            custom=None,
            key=None,
        )
        if data:
            hash1.update(data)
            hash2.update(data)

        assert (
            hash1.hexdigest()
            == hash2.hexdigest()
            == hash1.new(data).hexdigest()
            == hash2.new(data).hexdigest()
        )

    @given(
        data=st.binary() | st.none(),
        digest_size=st.integers(min_value=8, max_value=1000),
        custom=st.binary(),
    )
    @pytest.mark.parametrize("hashname", list(XOFS))
    @pytest.mark.parametrize("backend1,backend2", list(repcomb(Backends, 2)))
    def test_xof_with_custom_bytes_hash_equal(
        self,
        hashname: str,
        backend1: Backends,
        backend2: Backends,
        data: bytes | None,
        custom: bytes,
        digest_size: int,
    ):
        hash1, hash2 = make_hash_pairs(
            hashname,
            backend1,
            backend2,
            digest_size=digest_size,
            custom=custom,
            key=None,
        )
        if data:
            hash1.update(data)
            hash2.update(data)

        # NOTE: TupleHash makes a distinction between empty bytes and a
        # None.
        assert hash1.hexdigest() == hash2.hexdigest()


class TestCopy:
    @given(data=st.binary() | st.none())
    @pytest.mark.parametrize("hashname", FIXED_DIGEST_SIZE)
    @pytest.mark.parametrize("backend1,backend2", list(repcomb(Backends, 2)))
    def test_fixed_digest_size_hash_copy(
        self,
        hashname: str,
        data: bytes | None,
        backend1: Backends,
        backend2: Backends,
    ):
        hash1, hash2 = make_hash_pairs(
            hashname,
            backend1,
            backend2,
            digest_size=None,
            custom=None,
            key=None,
        )
        if data is not None:
            hash1.update(data)
            hash2.update(data)

        hash1_copy = hash1.copy()
        hash2_copy = hash2.copy()

        assert (
            hash1.hexdigest()
            == hash1_copy.hexdigest()
            == hash2.hexdigest()
            == hash2_copy.hexdigest()
        )

    @given(data=st.binary() | st.none())
    @pytest.mark.parametrize("backend1,backend2", list(repcomb(Backends, 2)))
    @pytest.mark.parametrize(
        "hashname,digest_size",
        [
            ("blake2b", 64),
            ("blake2s", 32),
        ],
    )
    def test_blake_hash_copy(
        self,
        data: bytes | None,
        hashname: str,
        digest_size: int,
        backend1: Backends,
        backend2: Backends,
    ):
        hash1, hash2 = make_hash_pairs(
            hashname,
            backend1,
            backend2,
            digest_size=digest_size,
            custom=None,
            key=None,
        )
        if data is not None:
            hash1.update(data)
            hash2.update(data)

        try:
            hash1_copy = hash1.copy()
        except ValueError:
            return pytest.skip(
                f"Copying not supported by {backend1.name} for hash "
                f"{hashname!r}"
            )

        try:
            hash2_copy = hash2.copy()
        except ValueError:
            return pytest.skip(
                f"Copying not supported by {backend2.name} for hash "
                f"{hashname!r}"
            )

        assert (
            hash1.hexdigest()
            == hash1_copy.hexdigest()
            == hash2.hexdigest()
            == hash2_copy.hexdigest()
        )


class TestMisc:
    @pytest.mark.parametrize("backend", Backends)
    def test_digest_after_digest(self, backend: Backends):
        hash = Hash.new("sha256", backend=backend)
        assert hash.digest() == hash.digest()


class TestErrors:
    @pytest.mark.parametrize("hashname", VAR_DIGEST_SIZE)
    @pytest.mark.parametrize("backend", Backends)
    def test_digest_size_required_for_var_digest_size_hash(
        self,
        hashname: str,
        backend: Backends,
    ):
        with pytest.raises(ValueError, match="digest_size is required"):
            make_hash(
                hashname,
                backend,
                digest_size=None,
                custom=None,
                key=None,
            )

    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_update_after_digest(self, backend: Backends):
        hashobj = Hash.new("sha256", backend=backend)
        hashobj.digest()
        with pytest.raises(exc.AlreadyFinalized):
            hashobj.update(b"ASD")

    @pytest.mark.parametrize("backend", Backends)
    def test_error_on_copy_after_digest(self, backend: Backends):
        hashobj = Hash.new("sha256", backend=backend)
        hashobj.digest()
        with pytest.raises(exc.AlreadyFinalized):
            hashobj.copy()
