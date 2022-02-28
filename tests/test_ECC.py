from __future__ import annotations

import hashlib
import typing
from itertools import product

import pytest

from pyflocker.ciphers import ECC, ECDSA, Backends, exc
from pyflocker.ciphers.backends.asymmetric import ECDH
from pyflocker.ciphers.interfaces import Hash

ENCRYPTION_PASSPHRASE = hashlib.sha256(b"ENCRYPTION_PASSPHRASE").digest()

SIGNING_DATA = b"SIGNING_DATA for SignerContext and VerifierContext"


if typing.TYPE_CHECKING:
    from pyflocker.ciphers import base


@pytest.fixture(scope="module")
def private_key(curve: str, backend: Backends):
    return ECC.generate(curve, backend=backend)


@pytest.fixture(scope="module")
def public_key(private_key: base.BaseECCPrivateKey):
    return private_key.public_key()


curve_fixture = pytest.mark.parametrize(
    "curve",
    ["p192", "p224", "p256", "p384", "p521"],
    scope="module",
)
backend_cross_fixture = pytest.mark.parametrize(
    "backend, backend2",
    list(product(Backends, repeat=2)),
    scope="module",
)


def private_key_equal(
    key1: base.BaseECCPrivateKey,
    key2: base.BaseECCPrivateKey,
):
    return key1.key_size == key2.key_size


def public_key_equal(
    key1: base.BaseECCPublicKey,
    key2: base.BaseECCPublicKey,
):
    return key1.key_size == key2.key_size


@curve_fixture
@backend_cross_fixture
class TestPrivateKeyEncoding:
    @pytest.mark.parametrize("format", ["PKCS1", "PKCS8"])
    @pytest.mark.parametrize("passphrase", [None, ENCRYPTION_PASSPHRASE])
    def test_PEM(
        self,
        private_key,
        format: str,
        backend2: Backends,
        passphrase,
    ):
        serialized = private_key.serialize(
            encoding="PEM",
            format=format,
            passphrase=passphrase,
        )

        private_key2 = ECC.load_private_key(
            serialized,
            backend=backend2,
            passphrase=passphrase,
        )
        assert private_key_equal(private_key, private_key2)

    def _test_PEM_OpenSSH(
        self,
        private_key: base.BaseECCPrivateKey,
    ):
        pass

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

        private_key2 = ECC.load_private_key(
            serialized,
            backend=backend2,
            passphrase=passphrase,
        )
        assert private_key_equal(private_key, private_key2)


@curve_fixture
@backend_cross_fixture
class TestPublicKeyEncoding:
    @pytest.mark.parametrize("format", ["SubjectPublicKeyInfo"])
    def test_PEM(self, public_key, format, backend, backend2):
        try:
            serialized = public_key.serialize(encoding="PEM", format=format)
        except ValueError:
            assert backend == Backends.CRYPTODOME
            return pytest.skip(
                f"{backend} does not support format {format} for public key",
            )

        public_key2 = ECC.load_public_key(serialized, backend=backend2)
        assert public_key_equal(public_key, public_key2)

    @pytest.mark.parametrize("format", ["SubjectPublicKeyInfo"])
    def test_DER(self, public_key, format, backend, backend2):
        try:
            serialized = public_key.serialize(encoding="DER", format=format)
        except ValueError:
            assert backend == Backends.CRYPTODOME
            return pytest.skip(
                f"{backend} does not support format {format} for public key",
            )

        public_key2 = ECC.load_public_key(serialized, backend=backend2)
        assert public_key_equal(public_key, public_key2)


@curve_fixture
@backend_cross_fixture
class TestSigningVerifying:
    @pytest.mark.parametrize("hashname", ["sha256", "sha512", "sha3_512"])
    # maximum and minimum salt lengths
    def test_ECDSA(
        self,
        private_key,
        backend2,
        hashname,
    ):
        public_key = ECC.load_public_key(
            private_key.public_key().serialize(),
            backend=backend2,
        )

        ecdsa = ECDSA()
        signer = private_key.signer(ecdsa)
        verifier = public_key.verifier(ecdsa)

        to_sign = Hash.new(hashname, SIGNING_DATA)
        signature = signer.sign(to_sign)
        verifier.verify(to_sign, signature)

        with pytest.raises(exc.SignatureError):
            verifier.verify(Hash.new("sha256", b"bogus"), signature)


@curve_fixture
@backend_cross_fixture
class TestECCExchange:
    def test_exchange_bytes_ECDH(
        self,
        private_key: base.BaseECCPrivateKey,
        backend,
        backend2,
    ):
        algorithm = ECDH()

        try:
            private_key2 = ECC.generate(private_key.curve, backend=backend2)
            assert private_key.exchange(
                private_key2.public_key().serialize(
                    "PEM",
                    "SubjectPublicKeyInfo",
                ),
                algorithm=algorithm,
            ) == private_key2.exchange(
                private_key.public_key().serialize(
                    "PEM",
                    "SubjectPublicKeyInfo",
                ),
                algorithm=algorithm,
            )
        except NotImplementedError:
            assert Backends.CRYPTODOME in (backend, backend2)
            return pytest.skip("Key exchange not supported by Cryptodome")
