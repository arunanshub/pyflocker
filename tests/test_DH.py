import hashlib
from itertools import product

import pytest

from pyflocker.ciphers import DH, exc
from pyflocker.ciphers.backends import Backends

SERIALIZATION_KEY = hashlib.sha256(b"SERIALIZATION_KEY").digest()


@pytest.fixture(scope="module")
def dh_param(key_size, backend):
    try:
        return DH.generate(key_size, backend=backend)
    except exc.UnsupportedAlgorithm:
        assert backend == Backends.CRYPTODOME
        return pytest.skip("DH not supported by Cryptodome")


key_size_fixture = pytest.mark.parametrize(
    "key_size",
    [512, 1024],
    scope="module",
)

backend_cross_fixture = pytest.mark.parametrize(
    "backend, backend2",
    list(product(Backends, repeat=2)),
    scope="module",
)


@key_size_fixture
@backend_cross_fixture
class TestDHParameters:
    @pytest.mark.parametrize("encoding", ["PEM", "DER"])
    @pytest.mark.parametrize("format", ["PKCS3"])
    def test_serde(self, dh_param, encoding, format, backend2):
        serialized = dh_param.serialize(encoding, format)

        try:
            dh_param2 = DH.load_parameters(serialized, backend=backend2)
        except exc.UnsupportedAlgorithm:
            assert backend2 == Backends.CRYPTODOME
            return pytest.skip("DH not supported by Cryptodome")

        assert (
            dh_param.g == dh_param2.g
            and dh_param.p == dh_param2.p
            and dh_param.q == dh_param2.q
        )

    def test_load_from_parameters(self, dh_param, backend2):
        try:
            dh_param2 = DH.load_from_parameters(
                dh_param.p,
                dh_param.g,
                dh_param.q,
                backend=backend2,
            )
        except exc.UnsupportedAlgorithm:
            assert backend2 == Backends.CRYPTODOME
            return pytest.skip("DH not supported by Cryptodome")

        assert (
            dh_param.g == dh_param2.g
            and dh_param.p == dh_param2.p
            and dh_param.q == dh_param2.q
        )


@key_size_fixture
@backend_cross_fixture
class TestDHPrivateKeyEncoding:
    @pytest.mark.parametrize("format", ["PKCS8"])
    @pytest.mark.parametrize("passphrase", [None, SERIALIZATION_KEY])
    def test_PEM(self, dh_param, format, passphrase, backend2):
        private_key = dh_param.private_key()
        serialized = private_key.serialize("PEM", format, passphrase)

        try:
            private_key2 = DH.load_private_key(
                serialized,
                passphrase,
                backend=backend2,
            )
        except exc.UnsupportedAlgorithm:
            assert backend2 == Backends.CRYPTODOME
            return pytest.skip("DH not supported by Cryptodome")

        assert (
            private_key.x == private_key2.x  # type: ignore
            and private_key.key_size == private_key2.key_size  # type: ignore
        )


@key_size_fixture
@backend_cross_fixture
class TestDHPublicKeyEncoding:
    @pytest.mark.parametrize("format", ["SubjectPublicKeyInfo"])
    def test_PEM(self, dh_param, format, backend2):
        public_key = dh_param.private_key().public_key()
        serialized = public_key.serialize("PEM", format)

        try:
            public_key2 = DH.load_public_key(
                serialized,
                backend=backend2,
            )
        except exc.UnsupportedAlgorithm:
            assert backend2 == Backends.CRYPTODOME
            return pytest.skip("DH not supported by Cryptodome")

        assert (
            public_key.y == public_key2.y  # type: ignore
            and public_key.key_size == public_key2.key_size  # type: ignore
        )
