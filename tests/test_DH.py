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


def dh_params_equal(dh_param, dh_param2):
    return (
        dh_param.g == dh_param2.g
        and dh_param.p == dh_param2.p
        and dh_param.q == dh_param2.q
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

        assert dh_params_equal(dh_param, dh_param2)

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

        assert dh_params_equal(dh_param, dh_param2)

    def test_same_parameters(self, dh_param, backend2):
        del backend2  # we don't need this
        dh_param2 = dh_param.private_key().parameters()
        dh_param3 = dh_param.private_key().public_key().parameters()

        assert dh_params_equal(dh_param, dh_param2)
        assert dh_params_equal(dh_param2, dh_param3)


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


@key_size_fixture
@backend_cross_fixture
class TestDHExchange(object):
    def test_exchange(self, dh_param, backend2):
        try:
            dh_param2 = DH.load_parameters(
                dh_param.serialize(),
                backend=backend2,
            )
        except exc.UnsupportedAlgorithm:
            assert backend2 == Backends.CRYPTODOME
            return pytest.skip("DH not supported by Cryptodome")

        private_key = dh_param.private_key()
        private_key2 = dh_param2.private_key()

        assert private_key.exchange(
            private_key2.public_key().serialize()
        ) == private_key2.exchange(private_key.public_key().serialize())

    def test_exchange_bytes(self, dh_param, backend2):
        try:
            dh_param2 = DH.load_parameters(
                dh_param.serialize(),
                backend=backend2,
            )
        except exc.UnsupportedAlgorithm:
            assert backend2 == Backends.CRYPTODOME
            return pytest.skip("DH not supported by Cryptodome")

        private_key = dh_param.private_key()
        private_key2 = dh_param2.private_key()

        assert private_key.exchange(
            private_key2.public_key()
        ) == private_key2.exchange(private_key.public_key())


@pytest.mark.parametrize("backend", [Backends.CRYPTOGRAPHY], scope="module")
class TestDHErrors:
    @key_size_fixture
    def test_dh_param_serialize_invalid_encoding_format(self, dh_param):
        with pytest.raises(ValueError):
            dh_param.serialize(encoding="nonexistent")

        with pytest.raises(ValueError):
            dh_param.serialize(format="nonexistent")

    def test_dh_param_load_invalid_data_format(self, backend):
        with pytest.raises(ValueError):
            DH.load_parameters(b"invalid", backend=backend)

        with pytest.raises(ValueError):
            DH.load_parameters(b"012323", backend=backend)

        with pytest.raises(ValueError):
            DH.load_parameters(b"-----BEGIN DH PARAMETERS123", backend=backend)

    @key_size_fixture
    def test_dh_private_key_invalid_encoding_format(self, dh_param):
        private_key = dh_param.private_key()

        with pytest.raises(ValueError):
            private_key.serialize(encoding="nonexistent")

        with pytest.raises(ValueError):
            private_key.serialize(format="nonexistent")

    def test_dh_private_key_load_invalid_data_format(self, backend):
        with pytest.raises(ValueError):
            DH.load_private_key(b"invalid", backend=backend)

        with pytest.raises(ValueError):
            DH.load_private_key(b"012323", backend=backend)

        with pytest.raises(ValueError):
            DH.load_private_key(
                b"-----BEGIN",
                backend=backend,
            )

    @key_size_fixture
    def test_dh_public_key_invalid_encoding_format(self, dh_param):
        public_key = dh_param.private_key().public_key()

        with pytest.raises(ValueError):
            public_key.serialize(encoding="nonexistent")

        with pytest.raises(ValueError):
            public_key.serialize(format="nonexistent")

        with pytest.raises(ValueError):
            public_key.serialize(format="PKCS8")

    def test_dh_public_key_load_invalid_data_format(self, backend):
        with pytest.raises(ValueError):
            DH.load_public_key(b"invalid", backend=backend)

        with pytest.raises(ValueError):
            DH.load_public_key(b"012323", backend=backend)

        with pytest.raises(ValueError):
            DH.load_public_key(
                b"-----BEGIN",
                backend=backend,
            )
