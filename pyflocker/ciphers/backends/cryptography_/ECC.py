# ed448, ed25519, x448, x25519,
from __future__ import annotations

import typing

import cryptography.exceptions as bkx
from cryptography.hazmat.primitives import serialization as serial
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
)

from ... import base, exc
from ..asymmetric import ECDH, ECDSA, EdDSA
from . import Hash
from .asymmetric import get_ec_exchange_algorithm, get_ec_signature_algorithm


class _Curves:
    """Group curve names under one namespace."""

    NIST_CURVES: dict[str, type[ec.EllipticCurve]] = {
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

    EDWARDS_CURVES = {
        # ed25519 and aliases
        "ed25519": lambda: _EdDSAPrivateKeyAdapter(
            ed25519.Ed25519PrivateKey.generate(),
            _name="ed25519",
        ),
        "Ed25519": lambda: _EdDSAPrivateKeyAdapter(
            ed25519.Ed25519PrivateKey.generate(),
            _name="ed25519",
        ),
        # ed448 and aliases
        "ed448": lambda: _EdDSAPrivateKeyAdapter(
            ed448.Ed448PrivateKey.generate(),
            _name="ed448",
        ),
        "Ed448": lambda: _EdDSAPrivateKeyAdapter(
            ed448.Ed448PrivateKey.generate(),
            _name="ed448",
        ),
    }

    CURVES: dict[
        str,
        type[ec.EllipticCurve] | typing.Callable[[], _EdDSAPrivateKeyAdapter],
    ] = {**NIST_CURVES, **EDWARDS_CURVES}


class ECCPrivateKey(base.BaseECCPrivateKey):
    # Encodings supported by this key.
    _ENCODINGS = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
        "Raw": Encoding.Raw,
    }

    # Formats supported by this key.
    _FORMATS = {
        "TraditionalOpenSSL": PrivateFormat.TraditionalOpenSSL,
        "PKCS1": PrivateFormat.TraditionalOpenSSL,
        "OpenSSH": PrivateFormat.OpenSSH,
        "PKCS8": PrivateFormat.PKCS8,
        "Raw": PrivateFormat.Raw,
    }

    # Key loaders indexed by the key format.
    _LOADERS = {
        b"-----BEGIN OPENSSH PRIVATE KEY": serial.load_ssh_private_key,
        b"-----": serial.load_pem_private_key,
        b"0": serial.load_der_private_key,
    }

    # possible key types returned by load_*_private_key(...). The keys are
    # wrapped according to their type.
    _KEY_TYPE_WRAPPERS = {
        ec.EllipticCurvePrivateKey: lambda key: key,
        ed25519.Ed25519PrivateKey: lambda key: _EdDSAPrivateKeyAdapter(
            key,
            _name="ed25519",
        ),
        ed448.Ed448PrivateKey: lambda key: _EdDSAPrivateKeyAdapter(
            key,
            _name="ed448",
        ),
    }

    def __init__(
        self,
        curve: str | None = None,
        _key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        if _key is not None:
            self._key = _key
            self._curve = _key.curve.name
        else:
            if not isinstance(curve, str):  # pragma: no cover
                raise TypeError("curve name must be a string")
            try:
                curve_obj = _Curves.CURVES[curve]()
            except KeyError as e:
                raise ValueError(f"Invalid curve: {e.args[0]!r}") from e

            if isinstance(curve_obj, ec.EllipticCurve):
                self._key = ec.generate_private_key(curve_obj)
            else:
                self._key = curve_obj

        self._key_size = self._key.key_size
        self._curve = self._key.curve.name

    @property
    def key_size(self) -> int:
        return self._key_size

    @property
    def curve(self) -> str:
        return self._curve

    def public_key(self) -> ECCPublicKey:
        return ECCPublicKey(self._key.public_key())

    def exchange(
        self,
        peer_public_key: bytes | ECCPublicKey | base.BaseECCPublicKey,
        algorithm: None | base.BaseEllepticCurveExchangeAlgorithm = None,
    ) -> bytes:
        if isinstance(self._key, _EdDSAPrivateKeyAdapter):
            raise NotImplementedError("EdDSA keys cannot perform key exchange")

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
        algorithm: None | base.BaseEllepticCurveSignatureAlgorithm = None,
    ) -> SignerContext | EdDSASignerContext:
        """Creates a signer context.

        Args:
            algorithm:
                The signing algorithm to use. Default is ECDSA for NIST curves
                and EdDSA for Edwards curves.

        Returns:
            signer object for signing.

        Warning:
            If the key is an ``EdDSA`` key, then the ``EdDSA`` parameters are
            ignored.
        """
        if self.curve.lower().startswith("ed"):
            if algorithm is not None and not isinstance(algorithm, EdDSA):
                raise TypeError(f"Invalid signature algorithm: {algorithm}")
            assert isinstance(self._key, _EdDSAPrivateKeyAdapter)
            return EdDSASignerContext(self._key)

        algorithm = ECDSA() if algorithm is None else algorithm
        return SignerContext(
            self._key,
            get_ec_signature_algorithm(algorithm, algorithm),
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: bytes | None = None,
    ) -> bytes:
        try:
            encd = self._ENCODINGS[encoding]
            fmt = self._FORMATS[format]
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

        try:
            return self._key.private_bytes(encd, fmt, protection)
        except ValueError as e:
            raise ValueError(f"Failed to serialize key: {e!s}") from e

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: bytes | None = None,
        *,
        curve: str | None = None,
    ) -> ECCPrivateKey:
        if curve is not None:
            return cls._load_raw(data, curve.lower())

        loader = cls._get_loader(data)

        if passphrase is not None:
            passphrase = memoryview(passphrase).tobytes()

        try:
            key = cls._validate_key_type(loader(memoryview(data), passphrase))
        except (ValueError, TypeError) as e:
            raise ValueError(f"Failed to load key: {e!s}") from e

        return cls(None, _key=key)

    @classmethod
    def _get_loader(cls, data: bytes) -> typing.Callable:
        """
        Returns a loader function depending on the initial bytes of the key.
        """
        try:
            return cls._LOADERS[next(filter(data.startswith, cls._LOADERS))]
        except StopIteration:
            raise ValueError("Invalid format") from None

    @classmethod
    def _validate_key_type(cls, key: typing.Any) -> ec.EllipticCurvePrivateKey:
        """
        Working principle: The loader will return a private key of certain
        type. We will use the knowledge of the type to wrap the key. This
        helps in handling Edwards keys (or any other key that might be added
        in the future).
        """
        try:
            klass = next(
                filter(lambda t: isinstance(key, t), cls._KEY_TYPE_WRAPPERS)
            )
        except StopIteration:
            raise ValueError("The key is not an EC private key.") from None

        return cls._KEY_TYPE_WRAPPERS[klass](key)

    @classmethod
    def _load_raw(cls, data: bytes, curve: str) -> ECCPrivateKey:
        if curve not in _Curves.EDWARDS_CURVES:
            raise ValueError(f"Curve {curve!r} does not support Raw encoding.")
        return cls(
            None,
            _key=_EdDSAPrivateKeyAdapter.from_private_bytes(data, curve),
        )


class ECCPublicKey(base.BaseECCPublicKey):
    # Encodings supported by this key.
    _ENCODINGS = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
        "OpenSSH": Encoding.OpenSSH,
        "Raw": Encoding.Raw,
        "X962": Encoding.X962,
        "SEC1": Encoding.X962,
    }

    # Formats supported by this key.
    _FORMATS = {
        "SubjectPublicKeyInfo": PublicFormat.SubjectPublicKeyInfo,
        "OpenSSH": PublicFormat.OpenSSH,
        "Raw": PublicFormat.Raw,
        # `SEC1 compress=True` as in pycryptodome
        "CompressedPoint": PublicFormat.CompressedPoint,
        "UncompressedPoint": PublicFormat.UncompressedPoint,
    }

    # Key loaders indexed by the key format.
    _LOADERS = {
        b"-----": serial.load_pem_public_key,
        b"0": serial.load_der_public_key,
        b"ecdsa": serial.load_ssh_public_key,
        b"ssh-ed25519": serial.load_ssh_public_key,
    }

    # possible key types returned by load_*_private_key(...). The keys are
    # wrapped according to their type.
    _KEY_TYPE_WRAPPERS = {
        ec.EllipticCurvePublicKey: lambda key: key,
        ed25519.Ed25519PublicKey: lambda key: _EdDSAPublicKeyAdapter(
            key,
            _name="ed25519",
        ),
        ed448.Ed448PublicKey: lambda key: _EdDSAPublicKeyAdapter(
            key,
            _name="ed448",
        ),
    }

    def __init__(self, key: ec.EllipticCurvePublicKey) -> None:
        if not isinstance(key, ec.EllipticCurvePublicKey):  # pragma: no cover
            raise TypeError("key is not an EC public key")
        self._key = key
        self._key_size = key.key_size
        self._curve = key.curve.name

    @property
    def key_size(self) -> int:
        return self._key_size

    @property
    def curve(self) -> str:  # pragma: no cover
        return self._curve

    def verifier(
        self,
        algorithm: None | base.BaseEllepticCurveSignatureAlgorithm = None,
    ) -> VerifierContext | EdDSAVerifierContext:
        if self.curve.startswith("ed"):
            if algorithm is not None and not isinstance(algorithm, EdDSA):
                raise TypeError(f"Invalid signature algorithm: {algorithm}")
            assert isinstance(self._key, _EdDSAPublicKeyAdapter)
            return EdDSAVerifierContext(self._key)

        algorithm = ECDSA() if algorithm is None else algorithm
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
            encd = self._ENCODINGS[encoding]
            fmt = self._FORMATS[format]
        except KeyError as e:
            raise ValueError(
                f"Invalid encoding or format: {e.args[0]!r}"
            ) from e

        try:
            return self._key.public_bytes(encd, fmt)
        except ValueError as e:
            raise ValueError(f"Failed to serialize key: {e!s}") from e

    @classmethod
    def load(cls, data: bytes, *, curve: str | None = None) -> ECCPublicKey:

        if curve is not None:
            return cls._load_raw_or_sec1(data, curve)

        loader = cls._get_loader(data)
        try:
            key = cls._validate_key_type(loader(memoryview(data)))
        except ValueError as e:
            raise ValueError(f"Failed to load key: {e!s}") from e

        assert isinstance(key, ec.EllipticCurvePublicKey)
        return cls(key)

    @classmethod
    def _load_raw_or_sec1(cls, data: bytes, curve: str) -> ECCPublicKey:
        if curve in _Curves.NIST_CURVES:
            return cls(
                ec.EllipticCurvePublicKey.from_encoded_point(
                    _Curves.NIST_CURVES[curve](),
                    data,
                )
            )
        if curve not in _Curves.EDWARDS_CURVES:
            raise ValueError(f"Curve {curve!r} does not support Raw encoding.")
        return cls(_EdDSAPublicKeyAdapter.from_public_bytes(data, curve))

    @classmethod
    def _validate_key_type(cls, key: typing.Any) -> ec.EllipticCurvePublicKey:
        """
        Working principle: The loader will return a public key of certain
        type. We will use the knowledge of the type to wrap the key. This
        helps in handling Edwards keys (or any other key that might be added
        in the future).
        """
        try:
            klass = next(
                filter(lambda t: isinstance(key, t), cls._KEY_TYPE_WRAPPERS)
            )
            return cls._KEY_TYPE_WRAPPERS[klass](key)
        except StopIteration:
            raise ValueError("The key is not an EC public key.") from None

    @classmethod
    def _get_loader(cls, data: bytes) -> typing.Callable:
        """
        Returns a loader function depending on the initial bytes of the key.
        """
        try:
            return cls._LOADERS[next(filter(data.startswith, cls._LOADERS))]
        except StopIteration:
            raise ValueError("Invalid format.") from None


class VerifierContext(base.BaseVerifierContext):
    def __init__(
        self,
        key: ec.EllipticCurvePublicKey,
        signature_algorithm: typing.Any,
    ) -> None:
        self._verify_func = key.verify
        self._signature_algorithm = signature_algorithm

    def verify(self, msghash: base.BaseHash, signature: bytes) -> None:
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
    def __init__(
        self, key: ec.EllipticCurvePrivateKey, signature_algorithm: typing.Any
    ) -> None:
        self._sign_func = key.sign
        self._signature_algorithm = signature_algorithm

    def sign(self, msghash: base.BaseHash) -> bytes:
        return self._sign_func(
            data=msghash.digest(),
            signature_algorithm=self._signature_algorithm(
                utils.Prehashed(Hash._get_hash_algorithm(msghash)),
            ),
        )


class EdDSASignerContext(base.BaseEdDSASignerContext):
    def __init__(self, key: _EdDSAPrivateKeyAdapter) -> None:
        self._key = key

    # TODO: Currently we have no way use a backend agnostic hash object for
    # `msghash`.
    def sign(
        self,
        msghash: bytes,
    ) -> bytes:
        if isinstance(msghash, base.BaseHash):
            raise TypeError(
                "Due to the limitations of cryptography backend, only binary "
                "object is supported."
            )
        return self._key.sign(msghash, None)


class EdDSAVerifierContext(base.BaseEdDSAVerifierContext):
    def __init__(self, key: _EdDSAPublicKeyAdapter) -> None:
        self._key = key

    # TODO: Currently we have no way use a backend agnostic hash object for
    # `msghash`.
    def verify(
        self,
        msghash: bytes,
        signature: bytes,
    ) -> None:
        if isinstance(msghash, base.BaseHash):
            raise TypeError(
                "Due to the limitations of cryptography backend, only binary "
                "object is supported."
            )
        try:
            return self._key.verify(signature, msghash, None)
        except bkx.InvalidSignature as e:
            raise exc.SignatureError from e


class _EllepticCurve(ec.EllipticCurve):
    def __init__(self, name: str, key_size: int):
        self._name = name
        self._key_size = key_size

    @property
    def name(self) -> str:
        return self._name

    @property
    def key_size(self) -> int:
        return self._key_size


class _EdDSAPrivateKeyAdapter(ec.EllipticCurvePrivateKey):
    _KEY_SIZES = {
        "ed25519": 255,
        "ed448": 448,
    }

    # Key loaders indexed by the key format.
    _LOADERS = {
        "ed25519": ed25519.Ed25519PrivateKey.from_private_bytes,
        "ed448": ed448.Ed448PrivateKey.from_private_bytes,
    }

    def __init__(
        self,
        key: ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey,
        *,
        _name: str,
    ) -> None:
        self._key = key
        self._name = _name

    @property
    def curve(self) -> ec.EllipticCurve:
        return _EllepticCurve(self._name, self.key_size)

    @property
    def key_size(self) -> int:
        return self._KEY_SIZES[self._name]

    def exchange(
        self,
        algorithm: ec.ECDH,
        peer_public_key: ec.EllipticCurvePublicKey,
    ) -> typing.NoReturn:
        del algorithm, peer_public_key
        raise NotImplementedError

    def private_numbers(self) -> typing.NoReturn:
        raise NotImplementedError

    def public_key(self) -> _EdDSAPublicKeyAdapter:
        return _EdDSAPublicKeyAdapter(
            self._key.public_key(),
            _name=self._name,
        )

    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: serial.KeySerializationEncryption,
    ) -> bytes:
        return self._key.private_bytes(encoding, format, encryption_algorithm)

    def sign(
        self,
        data: bytes,
        hash_algorithm: ec.EllipticCurveSignatureAlgorithm | None,
    ) -> bytes:
        del hash_algorithm
        return self._key.sign(data)

    @classmethod
    def from_private_bytes(
        cls,
        data: bytes,
        curve: str,
    ) -> _EdDSAPrivateKeyAdapter:
        key = cls._LOADERS[curve](data)
        assert isinstance(
            key,
            (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey),
        )
        return cls(key, _name=curve)


class _EdDSAPublicKeyAdapter(ec.EllipticCurvePublicKey):
    _KEY_SIZES = {
        "ed25519": 255,
        "Ed25519": 255,
        "ed448": 448,
        "Ed448": 448,
    }

    # Key loaders indexed by the key format.
    _LOADERS = {
        "ed25519": ed25519.Ed25519PublicKey.from_public_bytes,
        "Ed25519": ed25519.Ed25519PublicKey.from_public_bytes,
        "ed448": ed448.Ed448PublicKey.from_public_bytes,
        "Ed448": ed448.Ed448PublicKey.from_public_bytes,
    }

    def __init__(
        self,
        key: ed25519.Ed25519PublicKey | ed448.Ed448PublicKey,
        *,
        _name: str,
    ) -> None:
        self._key = key
        self._name = _name

    def public_bytes(self, encoding: Encoding, format: PublicFormat) -> bytes:
        return self._key.public_bytes(encoding, format)

    @property
    def key_size(self) -> int:
        return self._KEY_SIZES[self._name]

    @property
    def curve(self) -> ec.EllipticCurve:
        return _EllepticCurve(self._name, self.key_size)

    def public_numbers(self) -> typing.NoReturn:
        raise NotImplementedError

    def verify(
        self,
        signature: bytes,
        data: bytes,
        hash_algorithm: ec.EllipticCurveSignatureAlgorithm | None,
    ) -> None:
        del hash_algorithm
        return self._key.verify(signature, data)

    @classmethod
    def from_public_bytes(
        cls,
        data: bytes,
        curve: str,
    ) -> _EdDSAPublicKeyAdapter:
        key = cls._LOADERS[curve](data)
        assert isinstance(
            key,
            (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey),
        )
        return cls(key, _name=curve)


def generate(curve: str) -> ECCPrivateKey:
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
    passphrase: bytes | None = None,
    *,
    curve: str | None = None,
) -> ECCPrivateKey:
    """Loads the private key and returns a Key interface.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase (in bytes) that was used to encrypt the private key.
            ``None`` if the key was not encrypted.
        curve:
            The name of the curve as string. It is required only for ``Raw``
            keys.

    Returns:
        ECCPrivateKey: An ECC private key.
    """
    return ECCPrivateKey.load(data, passphrase, curve=curve)


def load_public_key(data: bytes, *, curve: str | None = None) -> ECCPublicKey:
    """Loads the public key.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Returns:
        An ECC public key.
    """
    return ECCPublicKey.load(data, curve=curve)
