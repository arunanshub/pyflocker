import pytest

from pyflocker.ciphers import Hash, Backends


def create_hash(algo, data, *, backend, **kwargs):
    if algo not in Hash.get_available_hashes(backend):
        return pytest.skip(f"{backend.name} does not support {algo}")
    return Hash.new(algo, data, backend=backend, **kwargs)


@pytest.mark.parametrize(
    "algo",
    Hash.get_available_hashes()
    ^ set(("blake2b", "blake2s", "shake128", "shake256")),  # noqa: W503
)
@pytest.mark.parametrize(
    "backend",
    list(Backends),
)
class TestHash:
    def test_same_hash(self, algo, backend):
        data = bytes(64)
        h1 = create_hash(algo, data, backend=backend)
        h2 = create_hash(algo, data, backend=backend)

        assert h1.digest() == h2.digest()
