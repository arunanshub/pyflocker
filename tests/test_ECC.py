from __future__ import annotations

from itertools import product

import pytest
from hypothesis import strategies as st
from hypothesis.core import given
from pyflocker.ciphers import ECC, ECDSA, Backends, base, exc
from pyflocker.ciphers.backends.asymmetric import ECDH, EdDSA
from pyflocker.ciphers.interfaces import Hash

# an encrypted DH private key. passphrase is "helloworld"
TESTING_DH_PRIVATE_KEY = b"""\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBjTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIzowzofKfAGACAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBArFYSwsP4mEyCu79uP+GOZBIIB
MK4sOioQz0algdwTMI6gSJ+5FvmuxLxBiSp02gUDrpZoHRs/K7NSZ6AeTPvVUYBO
/C3Vjg3aJYVyK4V2elhjVOfpq2n9eIfBwHvu+NGH8NZdOGmi2/jK4yDSzcZJF9Bh
jcINW5DqjyZiCBhvJgzBtYKs0XuQ0Yc/xE/loy5qufP7rxSdzMHr+AuwOSUj5LVO
AFzqrQlPn8j2mNAw6YKDNKoFNq4S8bIhktBo3+FBcYDk02iDf47eNodJB5wQpWug
iu6pl6Yr+OpIwD3hpKi+73BegAKT5uc23tHX9o6Oa9j8eLJz5TMgfrSHii9MDUZQ
H3RGMEsP1mfW81R0UiPKlufCwJ/wqFfkTymGdpemYu0L4E7tj8AdiA0JD23Wui+c
UuB24iHAujMntADTlMDI83g=
-----END ENCRYPTED PRIVATE KEY-----
"""

TESTING_DH_PUBLIC_KEY = b"""\
-----BEGIN PUBLIC KEY-----
MIIBIDCBlQYJKoZIhvcNAQMBMIGHAoGBANpLQ3kmQ//xRiBjnsiohGcJc/HpRxEp
KC1Io8GSiXl8XeABrRvWYai3rY7ylFrupfWfEP8vBC1uf2lHm7ZNFQOnTsLCUpw3
BlORkP/H80tNjhn1CA7YwGMxF3DYuxDmKUGJcpucvErVf5Y/KbFlE7fbfXtoEeCK
Gduu/aUWo1/bAgECA4GFAAKBgQCh2cr189Ag1wowpYNDRsk79L4KRidXYJbGlDsB
eRrZ02861z2aWNtwjqFMlGTdbikJ8zCYV/wFzDkPyBHY8UFwyvvZMhCcL7aP+ZJb
TuIWaJnduPv+7NnVXztyz0Jqk+GPrmiAhaOpZdDc2XvUQeuzNuYlg9oDTgWobuMX
c42Kpw==
-----END PUBLIC KEY-----
"""

# encrpyted ECC private key. passphrase is "helloworld"
TESTING_ENCRYPTED_PRIVATE_KEY = b"""\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBXTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIiPDccoM2IRkCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAI99JBsmRKT1udO2hzIBVJBIIB
AORDEPZRIvR8Q6803Qo47vT6Dv9HYMkrlWkWoJb5Rtns/w9rAbFxTV5QbwKFHYmu
+4PHlOvygGqnHD0BHNfa7iXcj4J1JCaLKDVMcCKwRFd6k66pvuRdlr+o0t+p7OAN
sC4OyFFCoW2IIv0FhYOOjGRjZ/SIP0XFeJoNkCGPW+RuvhuoxqQs4nsmDUHBMZ/a
i1vLX7IwCEGzQ1yuh98qpskyz7rLfVl3HXOC5Up0OaIb0RFWhASZGk5dSHiZ7xyU
pWhSJb5SVMeRcwA9dMGAUI6cMkmtUz2L+0aD6fhlFWg7pxdERTiBul63dMPOnvLL
xs87hw8M5asrMuELxcFJh9s=
-----END ENCRYPTED PRIVATE KEY-----
"""

TESTING_UNENCRYPTED_PRIVATE_KEY = b"""\
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBU0YHkKbrufzQYQ1n
JtD03T/tbA1TYxQAyJdvfWNSoCEN1DqfmEvAJiw0fCgGjNGvRQ6jNhr2LPhwPOch
DQ29uC2hgYkDgYYABAF6iFlfWiA0Obc05eOaZEy5kBe7Fep8/vi7w3mYZkqV7Yvv
w1J/8ACaxhXuJOr+x6lcL/4e4k0apwEh0y/6qecdywB2C+Vvf0ELwuNtEP0PsY+s
F2JEONee3Cc4h0wdXhRrPlT4F1ZkYdDKdqDSY/4HSPzKxDJNd8J/Xf7GLoQ3aO5F
LQ==
-----END PRIVATE KEY-----
"""

TESTING_PUBLIC_KEY = b"""\
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBeohZX1ogNDm3NOXjmmRMuZAXuxXq
fP74u8N5mGZKle2L78NSf/AAmsYV7iTq/sepXC/+HuJNGqcBIdMv+qnnHcsAdgvl
b39BC8LjbRD9D7GPrBdiRDjXntwnOIdMHV4Uaz5U+BdWZGHQynag0mP+B0j8ysQy
TXfCf13+xi6EN2juRS0=
-----END PUBLIC KEY-----
"""


NIST_CURVES = ["p192", "p224", "p256", "p384", "p521"]

EDWARDS_CURVES = ["ed25519", "ed448"]

nist_curves_fixture = pytest.mark.parametrize(
    "curve",
    NIST_CURVES,
    scope="module",
)
edwards_curves_fixture = pytest.mark.parametrize(
    "curve",
    EDWARDS_CURVES,
    scope="module",
)
all_curves_fixture = pytest.mark.parametrize(
    "curve",
    NIST_CURVES + EDWARDS_CURVES,
    scope="module",
)
backend_cross_fixture = pytest.mark.parametrize(
    "backend1, backend2",
    list(product(Backends, repeat=2)),
    scope="module",
)
p256_curve_fixture = pytest.mark.parametrize("curve", ["p256"], scope="module")


@pytest.fixture(scope="module")
def private_key(curve: str, backend1: Backends):
    """
    Generate a private key. It will be generated only once for the entire
    test suite.
    """
    try:
        return ECC.generate(curve, backend=backend1)
    except ValueError as e:
        assert "Invalid curve" in str(e)
        return pytest.skip(f"{curve} not supported by {backend1.name}")


@pytest.fixture(scope="module")
def public_key(private_key: base.BaseECCPrivateKey):
    """Derive a public key from a private key fixture."""
    return private_key.public_key()


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


class TestPrivateKeySerde:
    @nist_curves_fixture
    @backend_cross_fixture
    @pytest.mark.parametrize("format", ["PKCS1", "PKCS8"])
    @given(passphrase=st.binary(min_size=1) | st.none())
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

    @all_curves_fixture
    @backend_cross_fixture
    @pytest.mark.parametrize("format", ["PKCS8"])
    @given(passphrase=st.binary(min_size=1) | st.none())
    def test_DER(
        self,
        private_key,
        format: str,
        backend2: Backends,
        passphrase,
    ):
        serialized = private_key.serialize(
            encoding="DER",
            format=format,
            passphrase=passphrase,
        )

        private_key2 = ECC.load_private_key(
            serialized,
            backend=backend2,
            passphrase=passphrase,
        )
        assert private_key_equal(private_key, private_key2)

    @nist_curves_fixture
    @backend_cross_fixture
    def test_error_DER_PKCS1_with_passphrase(
        self,
        private_key: base.BaseECCPrivateKey,
        backend2: Backends,
    ):
        del backend2
        with pytest.raises(ValueError):
            private_key.serialize("DER", "PKCS1", b"passwd")

    @pytest.mark.parametrize("backend1", Backends)
    def test_error_load_invalid_password(self, backend1):
        with pytest.raises(ValueError):
            ECC.load_private_key(
                TESTING_ENCRYPTED_PRIVATE_KEY,
                backend=backend1,
            )
        with pytest.raises(ValueError):
            ECC.load_private_key(
                TESTING_ENCRYPTED_PRIVATE_KEY,
                passphrase=b"nothepassphrase",
                backend=backend1,
            )
            ECC.load_private_key(
                TESTING_UNENCRYPTED_PRIVATE_KEY,
                passphrase=b"nothepassphrase",
                backend=backend1,
            )
        with pytest.raises(ValueError):
            ECC.load_private_key(
                TESTING_DH_PRIVATE_KEY,
                passphrase=b"helloworld",
                backend=backend1,
            )
        with pytest.raises(ValueError):
            ECC.load_private_key(TESTING_PUBLIC_KEY, backend=backend1)

    @pytest.mark.parametrize("backend1", Backends)
    def test_error_load_invalid_data(self, backend1):
        with pytest.raises(ValueError):
            ECC.load_private_key(b"invalid-data", backend=backend1)
        with pytest.raises(ValueError):
            ECC.load_private_key(
                b"invalid-data",
                backend=backend1,
                passphrase=b"invalid",
            )

    @p256_curve_fixture
    @pytest.mark.parametrize(
        "backend1",
        [Backends.CRYPTOGRAPHY],
        scope="module",
    )
    @pytest.mark.skipif(
        "int(__import__('cryptography').__version__.split('.')[0]) >= 38",
        reason="Cryptography supports passwords greater than 72 bytes since "
        " version 38.0.0",
    )
    def test_error_PEM_OpenSSH_password_less_than_72_bytes(
        self,
        private_key,
    ):
        with pytest.raises(ValueError):
            private_key.serialize("PEM", "OpenSSH", passphrase=bytes(73))

    @p256_curve_fixture
    @pytest.mark.parametrize("backend1", Backends, scope="module")
    def test_error_invalid_encoding_format(self, private_key):
        with pytest.raises(ValueError):
            private_key.serialize(encoding="nonexistent")
        with pytest.raises(ValueError):
            private_key.serialize(format="nonexistent")

    @pytest.mark.parametrize("curve", ["p192", "p224"], scope="module")
    @pytest.mark.parametrize(
        "backend1",
        [Backends.CRYPTOGRAPHY],
        scope="module",
    )
    def test_PEM_OpenSSH_unsupported_curves(self, private_key):
        with pytest.raises(ValueError):
            private_key.serialize("PEM", "OpenSSH")


class TestPublicKeySerde:
    @all_curves_fixture
    @backend_cross_fixture
    @pytest.mark.parametrize("format", ["SubjectPublicKeyInfo"])
    def test_PEM(self, public_key, format, backend1, backend2):
        try:
            serialized = public_key.serialize(encoding="PEM", format=format)
        except ValueError:
            assert backend1 == Backends.CRYPTODOME
            return pytest.skip(
                f"{backend1} does not support format {format} for public key",
            )

        public_key2 = ECC.load_public_key(serialized, backend=backend2)
        assert public_key_equal(public_key, public_key2)

    @pytest.mark.parametrize("format", ["SubjectPublicKeyInfo"])
    @all_curves_fixture
    @backend_cross_fixture
    def test_DER(self, public_key, format, backend2):
        serialized = public_key.serialize(encoding="DER", format=format)
        public_key2 = ECC.load_public_key(serialized, backend=backend2)
        assert public_key_equal(public_key, public_key2)

    @pytest.mark.parametrize(
        "format",
        ["CompressedPoint", "UncompressedPoint"],
    )
    @nist_curves_fixture
    @backend_cross_fixture
    def test_SEC1(self, public_key, format, backend2):
        serialized = public_key.serialize("SEC1", format)
        public_key2 = ECC.load_public_key(
            serialized,
            backend=backend2,
            curve=public_key.curve,
        )
        assert public_key_equal(public_key, public_key2)

    @edwards_curves_fixture
    @backend_cross_fixture
    def test_Raw(self, public_key, backend2):
        serialized = public_key.serialize("Raw", "Raw")
        public_key2 = ECC.load_public_key(
            serialized,
            backend=backend2,
            curve=public_key.curve,
        )
        assert public_key_equal(public_key, public_key2)

    @pytest.mark.parametrize(
        "curve",
        ["p256", "p384", "p521", "ed25519"],
        scope="module",
    )
    @backend_cross_fixture
    def test_OpenSSH(self, public_key, backend2):
        serialized = public_key.serialize("OpenSSH", "OpenSSH")
        public_key2 = ECC.load_public_key(serialized, backend=backend2)
        assert public_key_equal(public_key, public_key2)

    @p256_curve_fixture
    @pytest.mark.parametrize("backend1", Backends, scope="module")
    def test_error_openssh_not_with_openssh(self, private_key):
        public_key = private_key.public_key()
        with pytest.raises(ValueError):
            public_key.serialize("OpenSSH", "SubjectPublicKeyInfo")
        with pytest.raises(ValueError):
            public_key.serialize("PEM", "OpenSSH")

    @pytest.mark.parametrize("backend1", Backends)
    def test_error_load_invalid_data(self, backend1):
        with pytest.raises(ValueError):
            ECC.load_public_key(b"invalid-data", backend=backend1)
        with pytest.raises(ValueError):
            ECC.load_public_key(
                TESTING_ENCRYPTED_PRIVATE_KEY,
                backend=backend1,
            )
        with pytest.raises(ValueError):
            ECC.load_public_key(
                TESTING_UNENCRYPTED_PRIVATE_KEY,
                backend=backend1,
            )
        with pytest.raises(ValueError):
            ECC.load_public_key(
                TESTING_DH_PUBLIC_KEY,
                backend=backend1,
            )

    @p256_curve_fixture
    @pytest.mark.parametrize("backend1", Backends, scope="module")
    def test_error_invalid_encoding_format(self, private_key):
        public_key = private_key.public_key()
        with pytest.raises(ValueError):
            public_key.serialize(encoding="nonexistent")
        with pytest.raises(ValueError):
            public_key.serialize(format="nonexistent")


class TestSigningVerifying:
    @nist_curves_fixture
    @backend_cross_fixture
    @pytest.mark.parametrize("hashname", ["sha256", "sha512", "sha3_512"])
    @given(data=st.binary())
    # maximum and minimum salt lengths
    def test_ECDSA(
        self,
        private_key,
        backend2,
        hashname,
        data,
    ):
        public_key = ECC.load_public_key(
            private_key.public_key().serialize(),
            backend=backend2,
        )

        ecdsa = ECDSA()
        signer = private_key.signer(ecdsa)
        assert isinstance(signer, base.BaseSignerContext)
        verifier = public_key.verifier(ecdsa)
        assert isinstance(verifier, base.BaseVerifierContext)

        to_sign = Hash.new(hashname, data)
        signature = signer.sign(to_sign)
        verifier.verify(to_sign, signature)

        with pytest.raises(exc.SignatureError):
            verifier.verify(Hash.new("sha256", b"bogus"), signature)

    @given(data=st.binary())
    @backend_cross_fixture
    @edwards_curves_fixture
    def test_EdDSA(self, private_key, backend2, data):
        public_key = ECC.load_public_key(
            private_key.public_key().serialize(),
            backend=backend2,
        )

        eddsa = EdDSA()
        signer = private_key.signer(eddsa)
        verifier = public_key.verifier(eddsa)

        signature = signer.sign(data)
        verifier.verify(data, signature)

    @p256_curve_fixture
    @pytest.mark.parametrize("backend1", Backends, scope="module")
    def test_private_key_signer_invalid_algorithm(self, private_key):
        class FakeAlgo:
            pass

        with pytest.raises(TypeError):
            private_key.signer(FakeAlgo())

    @p256_curve_fixture
    @pytest.mark.parametrize("backend1", Backends, scope="module")
    def test_public_key_verifier_invalid_algorithm(self, public_key):
        class FakeAlgo:
            pass

        with pytest.raises(TypeError):
            public_key.verifier(FakeAlgo())


class TestECCExchange:
    @nist_curves_fixture
    @backend_cross_fixture
    def test_exchange_bytes_ECDH(
        self,
        private_key: base.BaseECCPrivateKey,
        backend1,
        backend2,
    ):
        algorithm = ECDH()

        try:
            private_key2 = ECC.generate(private_key.curve, backend=backend2)
        except ValueError as e:
            assert "Invalid curve" in str(e)
            return pytest.skip(
                f"{private_key.curve} not supported by {backend2.name}"
            )

        try:
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
            assert Backends.CRYPTODOME in (backend1, backend2)
            return pytest.skip("Key exchange not supported by Cryptodome")

    @nist_curves_fixture
    @backend_cross_fixture
    def test_exchange_key_ECDH(
        self,
        private_key: base.BaseECCPrivateKey,
        backend1,
        backend2,
    ):
        algorithm = ECDH()

        try:
            private_key2 = ECC.generate(private_key.curve, backend=backend2)
        except ValueError as e:
            assert "Invalid curve" in str(e)
            return pytest.skip(
                f"{private_key.curve} not supported by {backend2.name}"
            )

        try:
            assert private_key.exchange(
                private_key2.public_key(),
                algorithm=algorithm,
            ) == private_key2.exchange(
                private_key.public_key(),
                algorithm=algorithm,
            )
        except NotImplementedError:
            assert Backends.CRYPTODOME in (backend1, backend2)
            return pytest.skip("Key exchange not supported by Cryptodome")

    @edwards_curves_fixture
    @backend_cross_fixture
    def test_error_EdDSA_cannot_exchange(
        self,
        private_key,
        backend2,
    ):
        private_key2 = ECC.generate(private_key.curve, backend=backend2)

        with pytest.raises(NotImplementedError):
            assert private_key.exchange(
                private_key2.public_key()
            ) == private_key2.exchange(private_key.public_key())


class TestECCErrors:
    @pytest.mark.parametrize("backend1", Backends)
    def test_invalid_curve_name(self, backend1):
        with pytest.raises(ValueError):
            ECC.generate("invalid-curve", backend=backend1)

    @pytest.mark.parametrize("backend1", Backends)
    def test_invalid_curve_type(self, backend1):
        with pytest.raises(TypeError, match="curve name must be a string"):
            ECC.generate(233, backend=backend1)  # type: ignore
