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

# encrypted using passphrase "helloworld"
TESTING_ENCRYPTED_PRIVATE_KEY = b"""\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIpBVSu3ot+94CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDCLQrxZcdJdXJJJDkvTjhmBIIE
0DOEqNh3yxFV69ZvxZd247+H7oZ5bzwj97PxNhUNDRPnRHAx5PUlKRly6DxV2Kh+
3H456MAfvasquROI4r4YD9AqeaFMLsdLC9vFCxljxNyNIsvi99ypBhQKOXzESpI3
GJkUUaod3qIsNGHAv4mNesIFg2K/WR2Cfp2upzr8Cx507TgDyqwHHR+GkpBn8BWd
/Sfg9CK4VRB16n7Tbdb+QvL++Al7Qu+c183b+r+2AOo+YTuUvP92zfg3zQpSSZAm
18YnZKeYPckSJAPNqaxF2HAk55qDJCxMr/0xMw8NPoMc7ZZZvdkOhWWQsbUtygWz
0aJ4a1H/BOyB43CzKg5HezBd7KwJHu9G0kpAqn12/fcl+wb2RqpzqGYRQv/lSDlp
5zbWG7Nq8R7q2dQhqxPiXLDTUfdT9nAd8T8B2b2AhBm7BofTkSwjT0iLieHcZGKQ
79RIRVPUtjHQBS7j7xVJdkWDSiHmRd/OzrbpTVynZUacGhah3NBbOYmsvYU17UZ2
l6NVLfKeqFyIRHzXmhO0WFWT3WEeFCvnsIjM8s4X+sI7HR1/GeymMRFeoelDhO/Y
MpO2PgqodkjtzX0R6gA0/XLyb/Yypl4K+QV1z59pp61L24LOQESbl3bPJGWbudzp
4QIAzzpocBecJ96Z3LJm+kmuuqR4HP7A+7EzdBClLN3dTz5PoAKnXLYwcrbipfpB
8oow2f52xvo6FgMchokxJKF+Ba8eccBNXTFiZAc9rakq1wOD/FzoyP/jcRlpOO53
OU/E9UP+goSQ64P0rUyUdbhAFDaBEco0sOHukBkJ1rn+OBpVDoqr7jYCqm/vAxMb
12ycMHkoIc4JZx+okLgYKyWAO43BlSScy4BxTinmIeYRYwme6Z4BuWtIJ0niRhJp
cKJFHiDipNaOj6nRigkH7VHTxlwGCRoycHC0POVkgmk8cfAxgjK701i40UIxHNka
cp0EkVIjT6BX2DX5wdDyh59/dy/YtbEgmHDxpM5eCf9yeUSScu+MXRbAQ1qxGy+D
zB4qRnTh0yzRJ+wWK2sapfuaj8S9Oz9hKjl39QlxFiq/8Tsu6kNO+aFfQnrJ1B/E
VIbwUA+0yCJt6GKr+y2d+qV2r61JBpbWWlCBDugoaHBMQpW53P8okFE2p07LaGZN
R2b6fzAf6NvY89+V81NbkizR7e8InjqRp+wiVO7bYJewznusAv1uS5EOmmzDjfTN
+qrc3NTzqWyNGV4g29MGJ2+9EWlrv1sknO4DBr7Ur+CFkamWQVAh/2hhtqyJmu0B
2HGnWmGyncE+zEVGjUfQPa1QwugcZyb6jFcs0xuzWFXT6O1D8SFGJezZ7I3jI5bN
IkHyJHDRlxJF8x5+6v/BDCfraPl/qaubNiXNzBPCKjNhPmX/iROUzJ/CytwRYx+q
smjbnIcUbSeAIawdjjPJMe8X2X6d3sOT2S2UBXgf8Gh/wio6fT3+bNTV/n2aSoc1
TexsLRwRsHPlZXe24pvIrpqw2pAm9dE72QhZKmB8s30Nb0GAzEnZR0uZzYONWOFX
Ybcd+m9Zi4VpTvUSnzmSece5z7LX8DHQaT9wIwMBoxOCz6PpggtqyHbQumtS5ql7
kLncszp5YXunDgfvoHCFUrgWzRlCDNWusjyEquuydkM3
-----END ENCRYPTED PRIVATE KEY-----
"""

TESTING_UNENCRYPTED_PRIVATE_KEY = b"""\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFQK4cwSiS4IOw
yG2Ukx1FRcxhqpGr1OxdNYBYZskUko+14FrCRBhPTpdOhNDs0BoqLxOBmajwbdKz
EZp4Weib5l+xYUjEGasNrEtE7lS87XndRNvUPZ5GcOqY4mjH70cY6tYppwVujXZr
7NCL7eMzPV2j0BIT4GJ4DRSxO4cCUh9eouQeI1rTA5CqyCt98AFngTxNuKfn7JEF
B92btsQ6RAdl1PZgzq1soIX9k5JwLMDhBf23jD2zizW4D/fm0l8l2/kW6O0YbrTl
BL/ltOPR18/5jWfJlm85IPNJXFgVRzqQ/L8Cm6c2qokUCWRmhvp6lcmJZPwOGQ2v
mjBETgZ7AgMBAAECggEAT1KycgfPfDljXA1N2+jJZZkrFr+UMyi+IMGqKmKzTF2g
A0EE3oipygLN4BqTNhh93SbvTjfv8zgG+lIC75EgdMlRBDEeJRY5bpcx8bdyRkOt
tSjCyng5FRTFktPB1V1JFyEhHMD48ztaOw6R0yPIMUvlQ0IicvHSR3rjLl7E7U5K
Z9dxKfETnaY4LsxTwYb9tYgYmuh/r5z3A2f05Pzxade6Z7F7aTdpk8FG98qmhgml
T4Z+DGsFlkSuKM2QnCyGwE3MbPnnKftoFUSV2urDWqtNdwj6qtqDxSwXxbwTftWU
w0LFEIu1PDfxYjR2kF6opxtIh98J8nm0ONC303RdwQKBgQDiKVsqels+Vg/OvAzP
D8FqqqCB2OlfIV1aLqwaO4lMsq42qHmyHh5XQsOvz08wozz31svDGHmNmhvlTgm/
NGRm6xjrLlDT8EoNwA4yrr+reY30jdSeqAO8lk5UZo7ecNTo9Ol/1Tx9b4bKtB/B
4D975tlNEtagsH6w70r50/2MIQKBgQDfRuviOpdw67UY40tKbEVYZqmX0VvzJlkQ
nud6yXvIfnQADNfo2/DbF22DOf67pNtkqx1Q4roesdtc/Q0JTqahHsqVvqXe5WzV
X80X1N/ZAxqtXZ0L9jrBU293K0RbVkfzycqlDLUU2wz1pyS2+5tXZR8mZlazPSnG
mC71H5BfGwKBgQCog6gqPoE+MWIV6IiiwFqd4AU4uycoevPT/nK+GR50x66Hi4Eh
9s8ktdqZZR7cXsVO5f1toQ7xM6MVeNBKZ/9nsEUg96HCSYjkNfZeTVcDrc7YKdYD
Ya1nF5fFy6UomWoLKnHRjlFEJZWJ9Cy1iSHEcH35r8+8a8X6kFKNVCfYAQKBgCaQ
4X2aET53+DfsSrz4JqI2WWTXzMIbBZdRWzpiQvdGoFLB5SlblCbDzS61fcJ7n0ms
JMwr3Wof3nwZWX8aDr4Vy3hCDfSKPFo+yfYr1t5tItZ/LPk79rod50r2NkBwjs0V
NeN8ZmrLy1lDHZxdqV9XICJJ2v/quKSM9M9yPEWxAoGAMdcK2EnKMIsG9KqK8aju
NDvJO20KQrpGdU30w6wljZvyoJyp5QZGc7ATF+HOYvqr1ifJ4JsvXQQ1mkkZC5wf
bzEkY67EShNPxoXHc6igbxGLPiTzSAOrW0faV7KuZ0Y8evN8VLxt19ROsVPlwjzc
pZ1ucX7XLD/0Wykje0gxiq4=
-----END PRIVATE KEY-----
"""

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

TESTING_PUBLIC_KEY = b"""\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxUCuHMEokuCDsMhtlJMd
RUXMYaqRq9TsXTWAWGbJFJKPteBawkQYT06XToTQ7NAaKi8TgZmo8G3SsxGaeFno
m+ZfsWFIxBmrDaxLRO5UvO153UTb1D2eRnDqmOJox+9HGOrWKacFbo12a+zQi+3j
Mz1do9ASE+BieA0UsTuHAlIfXqLkHiNa0wOQqsgrffABZ4E8Tbin5+yRBQfdm7bE
OkQHZdT2YM6tbKCF/ZOScCzA4QX9t4w9s4s1uA/35tJfJdv5FujtGG605QS/5bTj
0dfP+Y1nyZZvOSDzSVxYFUc6kPy/ApunNqqJFAlkZob6epXJiWT8DhkNr5owRE4G
ewIDAQAB
-----END PUBLIC KEY-----
"""


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
        and private_key.key_size == private_key2.key_size
    )


def public_key_equal(public_key, public_key2):
    return (
        public_key.n == public_key2.n
        and public_key.e == public_key2.e
        and public_key.key_size == public_key2.key_size
    )


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
    [1024, 2048],
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
        except ValueError:
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
        except ValueError:
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
class TestSigningVerifying:
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


bits_1024_fixture = pytest.mark.parametrize("bits", [1024], scope="module")


@pytest.mark.parametrize("backend", list(Backends), scope="module")
class TestRSAErrors:
    @bits_1024_fixture
    def test_private_key_invalid_encoding_format(self, private_key):
        with pytest.raises(ValueError):
            private_key.serialize(encoding="nonexistent")
        with pytest.raises(ValueError):
            private_key.serialize(format="nonexistent")

    @bits_1024_fixture
    def test_public_key_serialize_invalid_encoding_format(self, private_key):
        public_key = private_key.public_key()
        with pytest.raises(ValueError):
            public_key.serialize(encoding="nonexistent")
        with pytest.raises(ValueError):
            public_key.serialize(format="nonexistent")

    def test_private_key_load_invalid_data(self, backend):
        with pytest.raises(ValueError):
            RSA.load_private_key(b"invalid-data", backend=backend)
        with pytest.raises(ValueError):
            RSA.load_private_key(
                b"invalid-data",
                backend=backend,
                passphrase=b"invalid",
            )

    def test_private_key_load_invalid_password(self, backend):
        with pytest.raises(ValueError):
            RSA.load_private_key(
                TESTING_ENCRYPTED_PRIVATE_KEY,
                backend=backend,
            )
        with pytest.raises(ValueError):
            RSA.load_private_key(
                TESTING_ENCRYPTED_PRIVATE_KEY,
                passphrase=b"nothepassphrase",
                backend=backend,
            )
            RSA.load_private_key(
                TESTING_UNENCRYPTED_PRIVATE_KEY,
                passphrase=b"nothepassphrase",
                backend=backend,
            )
        with pytest.raises(ValueError):
            RSA.load_private_key(
                TESTING_DH_PRIVATE_KEY,
                passphrase=b"helloworld",
                backend=backend,
            )
        with pytest.raises(ValueError):
            RSA.load_private_key(TESTING_PUBLIC_KEY, backend=backend)

    def test_public_key_load_invalid_data(self, backend):
        with pytest.raises(ValueError):
            RSA.load_public_key(b"invalid-data", backend=backend)
        with pytest.raises(ValueError):
            RSA.load_public_key(
                TESTING_ENCRYPTED_PRIVATE_KEY,
                backend=backend,
            )
        with pytest.raises(ValueError):
            RSA.load_public_key(
                TESTING_UNENCRYPTED_PRIVATE_KEY,
                backend=backend,
            )

    @bits_1024_fixture
    def test_public_key_openssh_not_with_openssh(self, private_key):
        public_key = private_key.public_key()
        with pytest.raises(ValueError):
            public_key.serialize("OpenSSH", "SubjectPublicKeyInfo")
        with pytest.raises(ValueError):
            public_key.serialize("PEM", "OpenSSH")
