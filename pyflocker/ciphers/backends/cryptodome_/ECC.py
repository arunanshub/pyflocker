from __future__ import annotations

import typing

from Cryptodome.PublicKey import ECC

from ... import base, exc
from ..asymmetric import ECDSA
from .asymmetric import PROTECTION_SCHEMES, get_ec_signature_algorithm

CURVES = {k: k for k in ECC._curves}


class ECCPrivateKey(base.BaseECCPrivateKey):
    _encodings = ("PEM", "DER")
    _formats = ("PKCS1", "PKCS8")

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
                self._key = ECC.generate(curve=CURVES[curve])
            except KeyError as e:
                raise ValueError(f"Invalid curve: {curve}") from e

        # XXX: rough hack to get the key size from name as Cryptodome does not
        # provide it.
        self._key_size = int(self._key.curve[-3:])

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
            format: PKCS8 (default) or PKCS1.
            passphrase:
                A bytes-like object to protect the private key. If
                ``passphrase`` is None, the private key will be exported
                in the clear!

        Keyword Arguments:
            protection (str):
                The protection scheme to use. If passphrase is provided
                and protection is None, ``PBKDF2WithHMAC-SHA1AndAES256-CBC``
                is used.

        Returns:
            bytes: The private key as a bytes object.

        Raises:
            ValueError:
                If the encoding is incorrect or,
                if DER is used with PKCS1 or,
                protection value is supplied with PKCS1 format or,
                passphrase is empty when protection value is supplied.
            KeyError: if the format is invalid or not supported.
            TypeError:
                if the passphrase is not a bytes-like object when protection
                is supplied.
        """
        if encoding not in self._encodings:
            raise ValueError(f"Invalid encoding: {encoding!r}")
        if format not in self._formats:
            raise ValueError(f"Invalid format: {format!r}")

        if (
            protection is not None and protection not in PROTECTION_SCHEMES
        ):  # pragma: no cover
            raise ValueError("invalid protection scheme")

        if format == "PKCS1":
            self._validate_pkcs1_args(encoding, protection)

        protection_args = {}
        if passphrase is not None and protection is None and format != "PKCS1":
            # use a curated encryption choice and not DES-EDE3-CBC
            protection_args = {
                "protection": "PBKDF2WithHMAC-SHA1AndAES256-CBC",
            }

        key = self._key.export_key(
            format=encoding,
            use_pkcs8=format == "PKCS8",
            passphrase=(
                memoryview(passphrase).tobytes()  # type: ignore
                if passphrase is not None
                else None
            ),
            **protection_args,
        )
        return key if isinstance(key, bytes) else key.encode()

    @staticmethod
    def _validate_pkcs1_args(
        encoding: str,
        protection: str | None,
    ) -> None:
        if protection is not None:  # pragma: no cover
            raise ValueError("protection is meaningful only for PKCS8")
        if encoding == "DER":
            raise ValueError("cannot use DER with PKCS1 format")

    def signer(
        self,
        algorithm: None | base.BaseEllepticCurveSignatureAlgorithm = None,
    ) -> SignerContext:
        if algorithm is None:  # pragma: no cover
            algorithm = ECDSA()
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
    ) -> ECCPrivateKey:
        try:
            key = ECC.import_key(data, passphrase)  # type: ignore
            if not key.has_private():
                raise ValueError("The key is not a private key")
            return cls(None, _key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                "passphrase is missing or incorrect."
            ) from e


class ECCPublicKey(base.BaseECCPublicKey):
    """Represents ECC public key."""

    _encodings = ("PEM", "DER", "OpenSSH", "SEC1")
    _formats = ("SubjectPublicKeyInfo", "OpenSSH", "SEC1")

    def __init__(self, key: ECC.EccKey) -> None:
        self._key = key
        self._key_size = int(self._key.curve[-3:])
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
        *,
        compress: bool = False,
    ) -> bytes:
        """Serialize the public key.

        Args:
            encoding: PEM, DER, OpenSSH or SEC1.
            format: The supported formats are:

                - SubjectPublicKeyInfo
                - OpenSSH

                Note:
                    ``format`` argument is not actually used by Cryptodome. It
                    is here to maintain compatibility with pyca/cryptography
                    backend counterpart.

        Keyword Arguments:
            compress:
                Whether to export the public key with a more compact
                representation with only the x-coordinate. Default is False.

        Returns:
            The serialized public key as bytes object.

        Raises:
            ValueError: if the encoding is not supported or invalid.
        """
        if encoding not in self._encodings:
            raise ValueError(f"Invalid encoding: {encoding!r}")
        if format not in self._formats:
            raise ValueError(f"Invalid format: {format!r}")

        self._validate_encoding_format_args(encoding, format)

        key = self._key.export_key(
            format=encoding,
            compress=compress,
        )
        return key if isinstance(key, bytes) else key.encode()

    @staticmethod
    def _validate_encoding_format_args(encoding: str, format: str) -> None:
        to_validate = ("SEC1", "OpenSSH")
        is_encoding_present = encoding in to_validate
        is_format_present = format in to_validate
        if not is_encoding_present and not is_format_present:
            return None
        if encoding != format:
            encoding_or_format = encoding if is_encoding_present else format
            raise ValueError(
                f"{encoding_or_format!r} format can be used only with"
                f" {encoding_or_format!r} encoding",
            )

    def verifier(
        self,
        algorithm: None | base.BaseEllepticCurveSignatureAlgorithm = None,
    ) -> VerifierContext:
        if algorithm is None:
            algorithm = ECDSA()
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
            curve: The name of the curve. Only for SEC1 keys.

        Returns:
            ECCPublicKey: An ECC public key.

        Raises:
            ValueError: if the key could not be deserialized.
        """
        try:
            key = ECC.import_key(data, curve_name=curve)
            if key.has_private():
                raise ValueError("The key is not a private key")
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                "passphrase is missing or incorrect."
            ) from e


class SignerContext(base.BaseSignerContext):
    def __init__(self, ctx: typing.Any) -> None:
        self._ctx = ctx

    def sign(self, msghash: base.BaseHash) -> bytes:
        return self._ctx.sign(msghash)


class VerifierContext(base.BaseVerifierContext):
    def __init__(self, ctx: typing.Any) -> None:
        self._ctx = ctx

    def verify(self, msghash: base.BaseHash, signature: bytes) -> None:
        try:
            self._ctx.verify(msghash, signature)
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
