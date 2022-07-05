from __future__ import annotations

import typing

from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import eddsa

from ... import base, exc
from ..asymmetric import ECDSA, EdDSA
from .asymmetric import PROTECTION_SCHEMES, get_ec_signature_algorithm


class _Curves:
    NIST_CURVES = {
        # p192 and aliases
        "NIST P-192": "p192",
        "p192": "p192",
        "P-192": "p192",
        "prime192v1": "p192",
        "secp192r1": "p192",
        # p224 and aliases
        "NIST P-224": "p224",
        "p224": "p224",
        "P-224": "p224",
        "prime224v1": "p224",
        "secp224r1": "p224",
        # p256 and aliases
        "NIST P-256": "p256",
        "p256": "p256",
        "P-256": "p256",
        "prime256v1": "p256",
        "secp256r1": "p256",
        # p521 and aliases
        "NIST P-521": "p521",
        "p521": "p521",
        "P-521": "p521",
        "prime521v1": "p521",
        "secp521r1": "p521",
    }

    EDWARDS_CURVES = {
        # ed25519 and aliases
        "ed25519": "ed25519",
        "Ed25519": "ed25519",
        # ed448 and aliases
        "ed448": "ed448",
        "Ed448": "ed448",
    }

    CURVES = {**NIST_CURVES, **EDWARDS_CURVES}


class ECCPrivateKey(base.BaseECCPrivateKey):
    # Encodings supported by this key.
    _ENCODINGS = {
        "PEM": "PEM",
        "DER": "DER",
    }

    # Formats supported by this key.
    _FORMATS = {
        "PKCS1": "PKCS1",
        "TraditionalOpenSSL": "PKCS1",
        "PKCS8": "PKCS8",
    }

    # The default protection algorithm used for encrypting the private key.
    _DEFAULT_PROTECTION = "scryptAndAES256-CBC"

    def __init__(
        self,
        curve: str | None,
        _key: ECC.EccKey | None = None,
    ) -> None:
        if _key is not None:
            self._key = _key
        else:
            if not isinstance(curve, str):
                raise TypeError("curve must be a string")
            try:
                self._key = ECC.generate(curve=_Curves.CURVES[curve])
            except KeyError as e:
                raise ValueError(f"Invalid curve: {curve}") from e

        self._key_size = self._key.pointQ.size_in_bits()
        self._curve = self._key.curve

    @property
    def key_size(self) -> int:
        return self._key_size

    @property
    def curve(self) -> str:
        return self._curve

    def public_key(self) -> ECCPublicKey:
        return ECCPublicKey(self._key.public_key())

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: bytes | None = None,
        *,
        protection: str | None = None,
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding: PEM or DER (defaults to PEM).
            format:
                PKCS8 or PKCS1 (TraditionalOpenSSL). TraditionalOpenSSL is an
                alias for PKCS1.
            passphrase:
                A bytes-like object to protect the private key. If
                ``passphrase`` is None, the private key will be exported
                in the clear!

        Keyword Arguments:
            protection:
                The protection scheme to use. If passphrase is provided and
                protection is None, ``scryptAndAES256-CBC`` is used.

        Returns:
            bytes: The private key as a bytes object.

        Raises:
            ValueError:
                If the encoding is incorrect or, if DER is used with PKCS1 or,
                protection value is supplied with PKCS1 format or, passphrase
                is empty when protection value is supplied.
            KeyError: if the format is invalid or not supported.
            TypeError:
                if the passphrase is not a bytes-like object when protection
                is supplied.
        """
        try:
            encoding, format = self._ENCODINGS[encoding], self._FORMATS[format]
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e}") from e

        if (
            protection is not None and protection not in PROTECTION_SCHEMES
        ):  # pragma: no cover
            raise ValueError(f"invalid protection scheme: {protection!r}")

        if passphrase:
            passphrase = memoryview(passphrase).tobytes()

        kwargs: dict[str, typing.Any] = {}
        if encoding == "PEM":
            self._set_pem_args(format, passphrase, protection, kwargs)
        elif encoding == "DER":
            self._set_der_args(format, passphrase, protection, kwargs)

        try:
            key = self._key.export_key(**kwargs)
        except ValueError as e:
            raise ValueError(f"Failed to serialize key: {e!s}") from e
        return key if isinstance(key, bytes) else key.encode()

    @classmethod
    def _set_pem_args(
        cls,
        format: str,
        passphrase: bytes | None,
        protection: str | None,
        kwargs: dict,
    ) -> None:
        kwargs["format"] = "PEM"
        if format == "PKCS8":
            kwargs["use_pkcs8"] = True
            cls._set_pkcs8_passphrase_args(passphrase, protection, kwargs)
        elif format == "PKCS1":
            kwargs["use_pkcs8"] = False
            cls._set_pkcs1_passphrase_args(passphrase, protection, kwargs)
        else:
            raise ValueError(f"Invalid format for PKCS8: {format!r}")

    @classmethod
    def _set_der_args(
        cls,
        format: str,
        passphrase: bytes | None,
        protection: str | None,
        kwargs: dict,
    ) -> None:
        kwargs["format"] = "DER"
        if format == "PKCS8":
            kwargs["use_pkcs8"] = True
            cls._set_pkcs8_passphrase_args(passphrase, protection, kwargs)
        elif format == "PKCS1":
            kwargs["use_pkcs8"] = False
            cls._set_pkcs1_passphrase_args(passphrase, protection, kwargs)
        else:
            raise ValueError(f"Invalid format for PKCS8: {format!r}")

    @classmethod
    def _set_pkcs8_passphrase_args(
        cls,
        passphrase: bytes | None,
        protection: str | None,
        kwargs: dict,
    ) -> None:
        if not passphrase and protection:
            raise ValueError("Using protection without passphrase is invalid")
        kwargs["passphrase"] = passphrase
        kwargs["protection"] = (
            protection if protection else cls._DEFAULT_PROTECTION
        )

    @staticmethod
    def _set_pkcs1_passphrase_args(
        passphrase: bytes | None,
        protection: str | None,
        kwargs: dict,
    ) -> None:
        if protection is not None:  # pragma: no cover
            raise ValueError("protection is meaningful only for PKCS8")
        if passphrase is not None:
            kwargs["passphrase"] = passphrase

    def signer(
        self,
        algorithm: None | base.BaseEllepticCurveSignatureAlgorithm = None,
    ) -> SignerContext | EdDSASignerContext:
        if self.curve in _Curves.EDWARDS_CURVES:
            algorithm = EdDSA() if algorithm is None else algorithm
            return EdDSASignerContext(
                get_ec_signature_algorithm(
                    algorithm,
                    self._key,
                    algorithm,
                )
            )

        algorithm = ECDSA() if algorithm is None else algorithm
        return SignerContext(
            get_ec_signature_algorithm(algorithm, self._key, algorithm),
        )

    def exchange(
        self,
        peer_public_key: bytes | ECCPublicKey | base.BaseECCPublicKey,
        algorithm: None | base.BaseEllepticCurveExchangeAlgorithm = None,
    ) -> bytes:
        del peer_public_key, algorithm
        raise NotImplementedError(
            "key exchange is currently not supported by the backend."
        )

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: bytes | None = None,
        *,
        curve: str | None = None,
    ) -> ECCPrivateKey:
        if curve is not None:
            raise NotImplementedError(
                "Cryptodome does not support Raw encoded private keys yet."
            )
        try:
            key = ECC.import_key(data, passphrase)  # type: ignore
            if not key.has_private():
                raise ValueError("The key is not a private key")
        except ValueError as e:
            raise ValueError(f"Failed to load key: {e!s}") from e
        return cls(None, _key=key)


class ECCPublicKey(base.BaseECCPublicKey):
    """Represents ECC public key."""

    # Encodings supported by this key.
    _ENCODINGS = {
        "PEM": "PEM",
        "DER": "DER",
        "OpenSSH": "OpenSSH",
        "SEC1": "SEC1",
        "X962": "SEC1",
        "Raw": "raw",
    }

    # Formats supported by this key.
    _FORMATS = {
        "SubjectPublicKeyInfo": "SubjectPublicKeyInfo",
        "OpenSSH": "OpenSSH",
        "Raw": "raw",
        # `SEC1 compress=True` as in pycryptodome
        "CompressedPoint": "CompressedPoint",
        "UncompressedPoint": "UncompressedPoint",
    }

    def __init__(self, key: ECC.EccKey) -> None:
        self._key = key
        self._key_size = key.pointQ.size_in_bits()
        self._curve = key.curve

    @property
    def key_size(self) -> int:
        return self._key_size

    @property
    def curve(self) -> str:  # pragma: no cover
        return self._curve

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "SubjectPublicKeyInfo",
    ) -> bytes:
        """Serialize the public key.

        Args:
            encoding:
                PEM, DER, OpenSSH, SEC1 (X962) or Raw. Raw is valid only for
                Edwards curves. X962 is an alias for SEC1.
            format: The supported formats are:

                - SubjectPublicKeyInfo
                - OpenSSH
                - Raw
                - CompressedPoint
                - UncompressedPoint

                Note:
                    ``format`` argument is not actually used by Cryptodome. It
                    is here to maintain compatibility with pyca/cryptography
                    backend counterpart.

        Returns:
            The serialized public key as bytes object.

        Raises:
            ValueError: if the encoding or format is invalid.
        """
        try:
            encoding, format = self._ENCODINGS[encoding], self._FORMATS[format]
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e}") from e

        kwargs: dict[str, typing.Any] = {}
        if encoding == "SEC1":
            self._set_sec1_args(format, kwargs)
        elif encoding == "OpenSSH":
            self._set_openssh_args(format, kwargs)
        elif encoding == "raw":
            if self.curve in _Curves.NIST_CURVES:
                raise ValueError(
                    "Failed to serialize key: NIST curves do not support Raw "
                    "encoding. Use SEC1 instead."
                )
            self._set_raw_args(format, kwargs)
        elif encoding == "PEM":
            self._set_pem_args(format, kwargs)
        elif encoding == "DER":
            self._set_der_args(format, kwargs)

        try:
            data = self._key.export_key(**kwargs)
        except ValueError as e:
            raise ValueError(f"Failed to serialize key: {e!s}") from e
        return data if isinstance(data, bytes) else data.encode("utf-8")

    @staticmethod
    def _set_sec1_args(format: str, kwargs: dict) -> None:
        kwargs["format"] = "SEC1"
        if format == "UncompressedPoint":
            kwargs["compress"] = False
        elif format == "CompressedPoint":
            kwargs["compress"] = True
        else:
            raise ValueError(f"Invalid format for SEC1: {format!r}")

    @staticmethod
    def _set_openssh_args(format: str, kwargs: dict) -> None:
        if format == "OpenSSH":
            kwargs["format"] = "OpenSSH"
            return
        raise ValueError(f"Invalid format for OpenSSH: {format!r}")

    @staticmethod
    def _set_raw_args(format: str, kwargs: dict) -> None:
        if format == "raw":
            kwargs["format"] = "raw"
            return
        raise ValueError(f"Invalid format for Raw: {format!r}")

    @staticmethod
    def _set_pem_args(format: str, kwargs: dict) -> None:
        if format == "SubjectPublicKeyInfo":
            kwargs["format"] = "PEM"
            return
        raise ValueError(f"Invalid format for PEM: {format!r}")

    @staticmethod
    def _set_der_args(format: str, kwargs: dict) -> None:
        if format == "SubjectPublicKeyInfo":
            kwargs["format"] = "DER"
            return
        raise ValueError(f"Invalid format for DER: {format!r}")

    def verifier(
        self,
        algorithm: None | base.BaseEllepticCurveSignatureAlgorithm = None,
    ) -> VerifierContext | EdDSAVerifierContext:
        if self.curve.lower().startswith("ed"):
            algorithm = EdDSA() if algorithm is None else algorithm
            return EdDSAVerifierContext(
                get_ec_signature_algorithm(
                    algorithm,
                    self._key,
                    algorithm,
                )
            )

        algorithm = ECDSA() if algorithm is None else algorithm
        return VerifierContext(
            get_ec_signature_algorithm(algorithm, self._key, algorithm),
        )

    @classmethod
    def load(
        cls,
        data: bytes,
        *,
        curve: str | None = None,
    ) -> ECCPublicKey:
        """Loads the public key as binary object and returns the Key object.

        Args:
            data: The key as bytes object.
            curve: The name of the curve. Only for SEC1 and Raw keys.

        Returns:
            ECCPublicKey: An ECC public key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        try:
            if curve in _Curves.EDWARDS_CURVES:
                key = eddsa.import_public_key(data)
            else:
                key = ECC.import_key(data, curve_name=curve)
                if key.has_private():
                    raise ValueError("The key is not a private key")
        except ValueError as e:
            raise ValueError(f"Failed to load key: {e!s}") from e
        return cls(key)


class SignerContext(base.BaseSignerContext):
    def __init__(self, ctx: typing.Any) -> None:
        self._ctx = ctx

    def sign(self, msghash: base.BaseHash) -> bytes:
        return self._ctx.sign(msghash)


class EdDSASignerContext(base.BaseEdDSASignerContext):
    def __init__(self, ctx: eddsa.EdDSASigScheme) -> None:
        self._ctx = ctx

    def sign(self, msghash: bytes) -> bytes:
        # Cryptodome supports HashedEdDSA, but cryptography doesn't. But the
        # catch is that Cryptodome requires its own hash object. It's too much
        # of an hassle. We will use PureEdDSA only.
        return self._ctx.sign(msghash)


class VerifierContext(base.BaseVerifierContext):
    def __init__(self, ctx: typing.Any) -> None:
        self._ctx = ctx

    def verify(self, msghash: base.BaseHash, signature: bytes) -> None:
        try:
            self._ctx.verify(msghash, signature)
        except ValueError as e:
            raise exc.SignatureError from e


class EdDSAVerifierContext(base.BaseEdDSAVerifierContext):
    def __init__(self, ctx: eddsa.EdDSASigScheme) -> None:
        self._ctx = ctx

    def verify(self, msghash: bytes, signature: bytes) -> None:
        # Cryptodome supports HashedEdDSA, but cryptography doesn't. But the
        # catch is that Cryptodome requires its own hash object. It's too much
        # of an hassle. We will use PureEdDSA only.
        if isinstance(msghash, bytes):
            try:
                return self._ctx.verify(msghash, signature)
            except ValueError as e:
                raise exc.SignatureError from e


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


def load_public_key(
    data: bytes,
    *,
    curve: str | None = None,
) -> ECCPublicKey:
    """Loads the public key.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Returns:
        An ECC public key.
    """
    return ECCPublicKey.load(data, curve=curve)


def load_private_key(
    data: bytes,
    passphrase: bytes | None = None,
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
