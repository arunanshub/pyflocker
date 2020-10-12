from itertools import permutations
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
    "backend",
    list(Backends),
)
class TestHash:
    def test_same_hash(self, algo, backend):
        data = bytes(64)
        h1 = create_hash(algo, data, backend=backend)
        h2 = create_hash(algo, data, backend=backend)

        assert h1.digest() == h2.digest()

        with pytest.raises(exc.AlreadyFinalized):
            h1.update(data)

    @pytest.mark.parametrize(
        "backends",
        permutations(list(Backends), 2),
    )
    def test_same_hash_crossed(self, algo, backends, *, backend):
        # 'backend' is not used since we are cross checking backends
        b1, b2 = backends
        data = bytes(64)
        h1 = create_hash(algo, data, backend=b1)
        h2 = create_hash(algo, data, backend=b2)

        assert h1.digest() == h2.digest()

        for h in [h1, h2]:
            with pytest.raises(exc.AlreadyFinalized):
                h.update(data)
