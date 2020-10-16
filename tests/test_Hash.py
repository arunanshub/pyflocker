from itertools import combinations_with_replacement
import pytest

from pyflocker.ciphers import Hash, Backends
from pyflocker.ciphers import exc


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
    # all possible backend values -- both same and crossed
    "backend1, backend2",
    list(combinations_with_replacement(list(Backends), 2)),
)
class TestHash:
    def test_same_hash(self, algo, backend1, backend2):
        data = bytes(64)
        h1 = create_hash(algo, data, backend=backend1)
        h2 = create_hash(algo, data, backend=backend2)

        h1.update(data)
        h2.update(data)

        assert h1.digest() == h2.digest()

        with pytest.raises(exc.AlreadyFinalized):
            h1.update(data)
        with pytest.raises(exc.AlreadyFinalized):
            h2.update(data)
