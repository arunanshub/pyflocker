# ed448, ed25519, x448, x25519,
from __future__ import annotations

import typing

import cryptography.exceptions as bkx
from cryptography.hazmat.primitives import serialization as serial
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
)

from ... import base, exc
from ..asymmetric import ECDH, ECDSA
from . import Hash
from .asymmetric import get_ec_exchange_algorithm, get_ec_signature_algorithm

CURVES: typing.Dict[str, typing.Type[ec.EllipticCurve]] = {
    # p192 and aliases
    "NIST P-192": ec.SECP192R1,
    "P-192": ec.SECP192R1,
    "p192": ec.SECP192R1,
    "prime192v1": ec.SECP192R1,
    "secp192r1": ec.SECP192R1,
    # p224 and aliases
    "NIST P-224": ec.SECP224R1,
    "P-224": ec.SECP224R1,
    "p224": ec.SECP224R1,
    "prime224v1": ec.SECP224R1,
    "secp224r1": ec.SECP224R1,
    # p256 and aliases
    "NIST P-256": ec.SECP256R1,
    "P-256": ec.SECP256R1,
    "p256": ec.SECP256R1,
    "prime256v1": ec.SECP256R1,
    "secp256r1": ec.SECP256R1,
    # p384 and aliases
    "NIST P-384": ec.SECP384R1,
    "P-384": ec.SECP384R1,
    "p384": ec.SECP384R1,
    "prime384v1": ec.SECP384R1,
    "secp384r1": ec.SECP384R1,
    # p521 and aliases
    "NIST P-521": ec.SECP521R1,
    "P-521": ec.SECP521R1,
    "p521": ec.SECP521R1,
    "secp521r1": ec.SECP521R1,
    "prime521v1": ec.SECP521R1,
}


class ECCPrivateKey(base.BaseECCPrivateKey):
    _encodings = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }
    _formats = {
        "TraditionalOpenSSL": PrivateFormat.TraditionalOpenSSL,
        "PKCS1": PrivateFormat.TraditionalOpenSSL,
        "OpenSSH": PrivateFormat.OpenSSH,
        "PKCS8": PrivateFormat.PKCS8,
    }

    def __init__(
        self,
        curve: typing.Optional[str] = None,
        _key: typing.Optional[ec.EllipticCurvePrivateKey] = None,
    ):
        if _key is not None:
            self._key = _key
        else:
            if not isinstance(curve, str):  # pragma: no cover
                raise TypeError("curve name must be a string")
            try:
                self._key = ec.generate_private_key(CURVES[curve]())
            except KeyError as e:
                raise ValueError(f"Invalid curve: {e.args[0]!r}") from e

        self._key_size = self._key.key_size
        self._curve = self._key.curve.name

    @property
    def key_size(self) -> int:
        return self._key_size

    @property
    def curve(self):
        return self._curve

    def public_key(self) -> ECCPublicKey:
        return ECCPublicKey(self._key.public_key())

    def exchange(
        self,
        peer_public_key: typing.Union[
            bytes,
            ECCPublicKey,
            base.BaseECCPublicKey,
        ],
        algorithm: typing.Optional[
            base.BaseEllepticCurveExchangeAlgorithm,
        ] = None,
    ):
        if algorithm is None:  # pragma: no cover
            algorithm = ECDH()
        algo = get_ec_exchange_algorithm(algorithm, algorithm)
        if isinstance(peer_public_key, bytes):
            return self._key.exchange(
                algo,
                ECCPublicKey.load(peer_public_key)._key,
            )
        # optimizing case: key is made from this Backend
        if isinstance(peer_public_key, ECCPublicKey):
            return self._key.exchange(algo, peer_public_key._key)
        return self._key.exchange(
            algo,
            ECCPublicKey.load(
                peer_public_key.serialize("PEM", "SubjectPublicKeyInfo"),
            )._key,
        )

    def signer(
        self,
        algorithm: typing.Optional[
            base.BaseEllepticCurveSignatureAlgorithm
        ] = None,
    ):
        if algorithm is None:  # pragma: no cover
            algorithm = ECDSA()
        return SignerContext(
            self._key,
            get_ec_signature_algorithm(algorithm, algorithm),
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[bytes] = None,
    ) -> bytes:
        try:
            encd = self._encodings[encoding]
            fmt = self._formats[format]
        except KeyError as e:
            raise ValueError(
                f"The encoding or format is invalid: {e.args[0]!r}"
            ) from e

        protection: serial.KeySerializationEncryption
        if passphrase is None:
            protection = serial.NoEncryption()
        else:
            protection = serial.BestAvailableEncryption(
                memoryview(passphrase).tobytes()
            )
        return self._key.private_bytes(encd, fmt, protection)

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: typing.Optional[bytes] = None,
    ) -> ECCPrivateKey:
        formats = {
            b"-----BEGIN OPENSSH PRIVATE KEY": serial.load_ssh_private_key,
            b"-----": serial.load_pem_private_key,
            b"0": serial.load_der_private_key,
        }
        try:
            loader = formats[next(filter(data.startswith, formats))]
        except StopIteration:
            raise ValueError("Invalid format") from None

        if passphrase is not None:
            passphrase = memoryview(passphrase).tobytes()

        try:
            key = loader(memoryview(data), passphrase)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise ValueError("The key is not an EC private key.")
            return cls(None, _key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                "passphrase is incorrect."
            ) from e
        except TypeError as e:
            raise ValueError(
                "The key is encrypted but the passphrase is not given or the"
                " key is not encrypted but the passphrase is given."
                " Cannot deserialize the key."
            ) from e


class ECCPublicKey(base.BaseECCPublicKey):
    _encodings = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }
    _formats = {
        "SubjectPublicKeyInfo": PublicFormat.SubjectPublicKeyInfo,
    }

    def __init__(self, key: ec.EllipticCurvePublicKey):
        if not isinstance(key, ec.EllipticCurvePublicKey):  # pragma: no cover
            raise TypeError("key is not an EC public key")
        self._key = key
        self._key_size = key.key_size
        self._curve = key.curve.name

    @property
    def key_size(self):
        return self._key_size

    @property
    def curve(self):  # pragma: no cover
        return self._curve

    def verifier(
        self,
        algorithm: typing.Optional[
            base.BaseEllepticCurveSignatureAlgorithm
        ] = None,
    ):
        if algorithm is None:  # pragma: no cover
            algorithm = ECDSA()
        return VerifierContext(
            self._key,
            get_ec_signature_algorithm(algorithm, algorithm),
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "SubjectPublicKeyInfo",
    ) -> bytes:
        try:
            encd = self._encodings[encoding]
            fmt = self._formats[format]
        except KeyError as e:
            raise ValueError(
                f"Invalid encoding or format: {e.args[0]!r}"
            ) from e
        return self._key.public_bytes(encd, fmt)

    @classmethod
    def load(cls, data: bytes) -> ECCPublicKey:
        formats = {
            b"-----": serial.load_pem_public_key,
            b"0": serial.load_der_public_key,
        }

        try:
            loader = formats[next(filter(data.startswith, formats))]
        except StopIteration:
            raise ValueError("Invalid format.") from None

        try:
            key = loader(memoryview(data))
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ValueError("The key is not an EC public key")
            return cls(key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. The key format might be invalid."
            ) from e


class VerifierContext(base.BaseVerifierContext):
    def __init__(self, key: ec.EllipticCurvePublicKey, signature_algorithm):
        self._verify_func = key.verify
        self._signature_algorithm = signature_algorithm

    def verify(self, msghash: base.BaseHash, signature: bytes):
        try:
            return self._verify_func(
                signature=signature,
                data=msghash.digest(),
                signature_algorithm=self._signature_algorithm(
                    utils.Prehashed(Hash._get_hash_algorithm(msghash)),
                ),
            )
        except bkx.InvalidSignature as e:
            raise exc.SignatureError from e


class SignerContext(base.BaseSignerContext):
    def __init__(self, key: ec.EllipticCurvePrivateKey, signature_algorithm):
        self._sign_func = key.sign
        self._signature_algorithm = signature_algorithm

    def sign(self, msghash: base.BaseHash):
        return self._sign_func(
            data=msghash.digest(),
            signature_algorithm=self._signature_algorithm(
                utils.Prehashed(Hash._get_hash_algorithm(msghash)),
            ),
        )


def generate(curve: str):
    """
    Generate a private key with given curve ``curve``.

    Args:
        curve: The name of the curve to use.

    Returns:
        An ECC private key.

    Raises:
        ValueError: if the curve the name of the curve is invalid.
    """
    return ECCPrivateKey(curve)


def load_private_key(
    data: bytes,
    passphrase: typing.Optional[bytes] = None,
) -> ECCPrivateKey:
    """Loads the private key and returns a Key interface.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase (in bytes) that was used to encrypt the private key.
            ``None`` if the key was not encrypted.

    Returns:
        ECCPrivateKey: An ECC private key.
    """
    return ECCPrivateKey.load(data, passphrase)


def load_public_key(data: bytes) -> ECCPublicKey:
    """Loads the public key.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Returns:
        An ECC public key.
    """
    return ECCPublicKey.load(data)
