import hashlib
from itertools import product

import pytest

from pyflocker.ciphers import RSA, exc
from pyflocker.ciphers.backends import Backends
from pyflocker.ciphers.backends.asymmetric import MGF1, OAEP, PSS
from pyflocker.ciphers.interfaces import Hash

SERIALIZATION_KEY = hashlib.sha256(b"SERIALIZATION_KEY").digest()

ENCRYPTION_PASSPHRASE = hashlib.sha256(b"ENCRYPTION_PASSPHRASE").digest()

SIGNING_DATA = b"SIGNING_DATA for SignerContext and VerifierContext"

ENCRYPTION_DECRYPTION_DATA = b"ENCRYPTION_DECRYPTION_DATA for testing"


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


def public_key_equal(public_key, public_key2):
    return public_key.n == public_key2.n and public_key.e == public_key2.e


# Fixtures with scope ``module`` are associated with a fixture that is
# computationally heavy to generate. Here, the hard to compute fixture is
# ``private_key``. Hence, we will reuse them throughout the test module.
@pytest.fixture(scope="module")
def private_key(bits: int, backend: Backends):
    return RSA.generate(bits, backend=backend)


@pytest.fixture(scope="module")
def public_key(private_key):
    return private_key.public_key()


bits_fixture = pytest.mark.parametrize(
    "bits",
    [1024, 2048, 4096],
    scope="module",
)
backend_cross_fixture = pytest.mark.parametrize(
    "backend, backend2",
    list(product(Backends, repeat=2)),
    scope="module",
)


@bits_fixture
@backend_cross_fixture
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
            return pytest.skip(
                f"{backend} does not support format {format} for private key",
            )

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


@bits_fixture
@backend_cross_fixture
class TestPublicKeyEncoding:
    @pytest.mark.parametrize("format", ["SubjectPublicKeyInfo", "PKCS1"])
    def test_PEM(self, public_key, format, backend, backend2):
        try:
            serialized = public_key.serialize(encoding="PEM", format=format)
        except KeyError:
            assert backend == Backends.CRYPTODOME
            return pytest.skip(
                f"{backend} does not support format {format} for public key",
            )

        public_key2 = RSA.load_public_key(serialized, backend=backend2)
        assert public_key_equal(public_key, public_key2)

    @pytest.mark.parametrize("format", ["SubjectPublicKeyInfo", "PKCS1"])
    def test_DER(self, public_key, format, backend, backend2):
        try:
            serialized = public_key.serialize(encoding="DER", format=format)
        except KeyError:
            assert backend == Backends.CRYPTODOME
            return pytest.skip(
                f"{backend} does not support format {format} for public key",
            )

        public_key2 = RSA.load_public_key(serialized, backend=backend2)
        assert public_key_equal(public_key, public_key2)

    @pytest.mark.parametrize("format", ["SubjectPublicKeyInfo", "OpenSSH"])
    def test_OpenSSH(self, public_key, format, backend, backend2):
        try:
            serialized = public_key.serialize(
                encoding="OpenSSH", format=format
            )
        except KeyError:
            assert backend == Backends.CRYPTODOME
            return pytest.skip(
                f"{backend} does not support format {format} for public key",
            )
        except ValueError:
            assert format != "OpenSSH"
            return

        public_key2 = RSA.load_public_key(serialized, backend=backend2)
        assert public_key_equal(public_key, public_key2)


@bits_fixture
@backend_cross_fixture
class TestSigningVerifying(object):
    @pytest.mark.parametrize("hashname", ["sha256", "sha512", "sha3_512"])
    # maximum and minimum salt lengths
    @pytest.mark.parametrize("salt_length", [None, 0])
    def test_PSS_MGF1(
        self,
        private_key,
        backend2,
        hashname,
        salt_length,
    ):
        public_key = RSA.load_public_key(
            private_key.public_key().serialize(),
            backend=backend2,
        )

        pss = PSS(MGF1(Hash.new(hashname)), salt_length)
        signer = private_key.signer(pss)
        verifier = public_key.verifier(pss)

        to_sign = Hash.new("sha256", SIGNING_DATA)
        signature = signer.sign(to_sign)
        verifier.verify(to_sign, signature)

        with pytest.raises(exc.SignatureError):
            verifier.verify(Hash.new("sha256", b"bogus"), signature)


@bits_fixture
@backend_cross_fixture
class TestEncryptionDecryption:
    @pytest.mark.parametrize("mgf_hash", ["sha256"])
    @pytest.mark.parametrize("oaep_hash", ["sha256"])
    def test_OAEP_MGF1(self, private_key, backend2, mgf_hash, oaep_hash):
        public_key = RSA.load_public_key(
            private_key.public_key().serialize(),
            backend=backend2,
        )

        oaep = OAEP(MGF1(Hash.new(mgf_hash)), Hash.new(oaep_hash), b"")
        encryptor = public_key.encryptor(oaep)
        decryptor = private_key.decryptor(oaep)

        ciphertext = encryptor.encrypt(ENCRYPTION_DECRYPTION_DATA)
        plaintext = decryptor.decrypt(ciphertext)

        assert plaintext == ENCRYPTION_DECRYPTION_DATA
        with pytest.raises(exc.DecryptionError):
            decryptor.decrypt(b"bogus")
