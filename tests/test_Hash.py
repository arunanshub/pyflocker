from itertools import combinations_with_replacement
import pytest

from pyflocker.ciphers import Hash, Backends
from pyflocker.ciphers import exc

_BLOCK_SIZE_DIFFERS = [
    "blake2s",
    "blake2b",
]


def create_hash(algo, data, *, backend, **kwargs):
    if algo not in Hash.get_available_hashes(backend):
        return pytest.skip(f"{backend.name} does not support {algo}")
    return Hash.new(algo, data, backend=backend, **kwargs)


class _TestHashBase:
    def test_same_hash(self, algo, backend1, backend2, **kwargs):
        data = bytes(1024)
        h1 = create_hash(algo, data, backend=backend1, **kwargs)
        h2 = create_hash(algo, data, backend=backend2, **kwargs)

        assert h1.digest_size == h2.digest_size
        assert h1.name == h2.name
        if algo not in _BLOCK_SIZE_DIFFERS:
            assert h1.block_size == h2.block_size

        h1.update(data)
        h2.update(data)

        assert h1.digest() == h2.digest()
        try:
            assert h1.oid == h2.oid
        except AttributeError:
            assert algo in ("blake2b", "blake2s")
            assert kwargs["digest_size"] not in (20, 32, 48, 64)

        with pytest.raises(exc.AlreadyFinalized):
            h1.update(data)
        with pytest.raises(exc.AlreadyFinalized):
            h1.copy()
        with pytest.raises(exc.AlreadyFinalized):
            h2.update(data)
        with pytest.raises(exc.AlreadyFinalized):
            h2.copy()

        assert h1.new().digest() == h2.new().digest()


@pytest.mark.parametrize(
    "algo",
    Hash.get_available_hashes()
    ^ set(("blake2b", "blake2s", "shake128", "shake256")),  # noqa: W503
)
@pytest.mark.parametrize(
    # all possible backend values -- both same and crossed
    "backend1, backend2",
    list(combinations_with_replacement(list(Backends), 2)),
)
class TestHash(_TestHashBase):
    pass


@pytest.mark.parametrize(
    # all possible backend values -- both same and crossed
    "backend1, backend2",
    list(combinations_with_replacement(list(Backends), 2)),
)
class TestHashExtra:
    @pytest.mark.parametrize(
        "algo",
        ("shake128", "shake256"),
    )
    @pytest.mark.parametrize(
        "digest_size",
        list(range(4, 512)),
    )
    def test_same_hash_shake(self, algo, digest_size, backend1, backend2):
        _TestHashBase().test_same_hash(
            algo, backend1, backend2, digest_size=digest_size
        )

    @pytest.mark.parametrize(
        "algo",
        ["blake2s"],
    )
    @pytest.mark.parametrize(
        "digest_size",
        range(1, 33),
    )
    def test_same_hash_blake2s(self, algo, digest_size, backend1, backend2):
        if digest_size != 32 and any(
            b == Backends.CRYPTOGRAPHY for b in [backend1, backend2]
        ):
            with pytest.raises(ValueError):
                _TestHashBase().test_same_hash(
                    algo,
                    backend1,
                    backend2,
                    digest_size=digest_size,
                )
            return

        _TestHashBase().test_same_hash(
            algo,
            backend1,
            backend2,
            digest_size=digest_size,
        )

    @pytest.mark.parametrize(
        "algo",
        ["blake2b"],
    )
    @pytest.mark.parametrize(
        "digest_size",
        range(1, 65),
    )
    def test_same_hash_blake2b(self, algo, digest_size, backend1, backend2):
        if digest_size != 64 and any(
            b == Backends.CRYPTOGRAPHY for b in [backend1, backend2]
        ):
            with pytest.raises(ValueError):
                _TestHashBase().test_same_hash(
                    algo,
                    backend1,
                    backend2,
                    digest_size=digest_size,
                )
            return

        _TestHashBase().test_same_hash(
            algo,
            backend1,
            backend2,
            digest_size=digest_size,
        )
