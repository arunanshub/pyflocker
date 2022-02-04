import hashlib
from itertools import product

import pytest

from pyflocker.ciphers import RSA
from pyflocker.ciphers.backends import Backends

SERIALIZATION_KEY = hashlib.sha256(b"SERIALIZATION_KEY").digest()

ENCRYPTION_PASSPHRASE = hashlib.sha256(b"ENCRYPTION_PASSPHRASE").digest()


def private_key_equal(private_key, private_key2):
    return (
        private_key.n == private_key2.n
        and private_key.e == private_key2.e
        and (
            (
                private_key.p == private_key2.p
                and private_key.q == private_key2.q
            )
            or (
                private_key.p == private_key2.q
                and private_key.p == private_key2.q
            )
        )
        and private_key.d == private_key2.d
    )


@pytest.fixture
def private_key(bits: int, backend: Backends):
    return RSA.generate(bits, backend=backend)


@pytest.mark.parametrize("bits", [1024, 2048])
@pytest.mark.parametrize(
    "backend, backend2",
    list(product(Backends, repeat=2)),
)
class TestPrivateKeyEncoding:
    @pytest.mark.parametrize("format", ["PKCS1", "PKCS8", "OpenSSH"])
    @pytest.mark.parametrize("passphrase", [None, ENCRYPTION_PASSPHRASE])
    def test_PEM(
        self,
        private_key,
        format: str,
        backend: Backends,
        backend2: Backends,
        passphrase,
    ):
        try:
            serialized = private_key.serialize(
                encoding="PEM",
                format=format,
                passphrase=passphrase,
            )
        except ValueError:
            assert backend == Backends.CRYPTODOME and format == "OpenSSH"
            return pytest.skip(f"{backend} does not support format {format}")

        private_key2 = RSA.load_private_key(
            serialized,
            backend=backend2,
            passphrase=passphrase,
        )
        assert private_key_equal(private_key, private_key2)

    @pytest.mark.parametrize("format", ["PKCS1", "PKCS8"])
    @pytest.mark.parametrize("passphrase", [None, ENCRYPTION_PASSPHRASE])
    def test_DER(
        self,
        private_key,
        format: str,
        backend2: Backends,
        passphrase,
    ):
        try:
            serialized = private_key.serialize(
                encoding="DER",
                format=format,
                passphrase=passphrase,
            )
        except ValueError:
            assert format == "PKCS1"
            return

        private_key2 = RSA.load_private_key(
            serialized,
            backend=backend2,
            passphrase=passphrase,
        )
        assert private_key_equal(private_key, private_key2)
