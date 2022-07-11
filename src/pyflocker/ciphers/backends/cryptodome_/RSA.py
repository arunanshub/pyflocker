from __future__ import annotations

import typing

from Cryptodome.PublicKey import RSA

from ... import base, exc
from ..asymmetric import OAEP, PSS
from .asymmetric import PROTECTION_SCHEMES, get_padding_algorithm


class RSAPrivateKey(base.BaseRSAPrivateKey):
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
        n: int | None,
        e: int = 65537,
        _key: RSA.RsaKey | None = None,
    ) -> None:
        if _key is not None:
            self._key = _key
        else:
            if not isinstance(n, int):  # pragma: no cover
                raise TypeError("n must be an integer value")
            self._key = RSA.generate(n, e=e)

    @property
    def p(self) -> int:
        return self._key.p

    @property
    def q(self) -> int:
        return self._key.q

    @property
    def d(self) -> int:
        return self._key.d

    @property
    def n(self) -> int:
        return self._key.n

    @property
    def e(self) -> int:
        return self._key.e

    @property
    def key_size(self) -> int:
        return self._key.size_in_bits()

    def decryptor(
        self,
        padding: base.BaseAsymmetricPadding | None = None,
    ) -> DecryptorContext:
        if padding is None:  # pragma: no cover
            padding = OAEP()
        return DecryptorContext(
            get_padding_algorithm(padding, self._key, padding),
        )

    def signer(
        self,
        padding: base.BaseAsymmetricPadding | None = None,
    ) -> SignerContext:
        if padding is None:  # pragma: no cover
            padding = PSS()
        return SignerContext(
            get_padding_algorithm(padding, self._key, padding),
        )

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self._key.publickey())

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
            format: PKCS1 or PKCS8 (defaults to PKCS8).
            passphrase:
                a bytes object to use for encrypting the private key. If
                ``passphrase`` is None, the private key will be exported in the
                clear!

        Keyword Arguments:
            protection:
                The protection scheme to use. Supplying a value for protection
                has meaning only if the ``format`` is PKCS8. If ``None`` is
                provided ``scryptAndAES256-CBC`` is used as the protection
                scheme.

        Returns:
            Serialized key as a bytes object.

        Raises:
            ValueError:
                If the encoding or format is incorrect or,
                if DER is used with PKCS1 or,
                protection value is supplied with PKCS1 format.
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
            kwargs["pkcs"] = 8
            cls._set_pkcs8_passphrase_args(passphrase, protection, kwargs)
        elif format == "PKCS1":
            kwargs["pkcs"] = 1
            cls._set_pkcs1_passphrase_args(passphrase, protection, kwargs)
        else:
            raise ValueError(f"Invalid format for PEM: {format!r}")

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
            kwargs["pkcs"] = 8
            cls._set_pkcs8_passphrase_args(passphrase, protection, kwargs)
        elif format == "PKCS1":
            kwargs["pkcs"] = 1
            cls._set_pkcs1_passphrase_args(passphrase, protection, kwargs)
        else:
            raise ValueError(f"Invalid format for DER: {format!r}")

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

    @staticmethod
    def _validate_pkcs1_args(
        encoding: str,
        protection: str | None,
    ) -> None:
        if protection is not None:  # pragma: no cover
            raise ValueError("protection is meaningful only for PKCS8")
        if encoding == "DER":
            raise ValueError("cannot use DER with PKCS1 format")

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: bytes | None = None,
    ) -> RSAPrivateKey:
        try:
            key = RSA.import_key(data, passphrase)  # type: ignore
            if not key.has_private():
                raise ValueError("The key is not a private key")
        except ValueError as e:
            raise ValueError(f"Failed to load key: {e!s}") from e
        return cls(None, _key=key)


class RSAPublicKey(base.BaseRSAPublicKey):
    # Encodings supported by this key.
    _ENCODINGS = {
        "PEM": "PEM",
        "DER": "DER",
        "OpenSSH": "OpenSSH",
    }

    # Formats supported by this key.
    _FORMATS = {
        "SubjectPublicKeyInfo": "SubjectPublicKeyInfo",
        "OpenSSH": "OpenSSH",
    }

    def __init__(self, key: RSA.RsaKey) -> None:
        self._key = key

    @property
    def n(self) -> int:
        return self._key.n

    @property
    def e(self) -> int:
        return self._key.e

    @property
    def key_size(self) -> int:
        return self._key.size_in_bits()

    def encryptor(
        self,
        padding: base.BaseAsymmetricPadding | None = None,
    ) -> EncryptorContext:
        if padding is None:  # pragma: no cover
            padding = OAEP()
        return EncryptorContext(
            get_padding_algorithm(padding, self._key, padding),
        )

    def verifier(
        self,
        padding: base.BaseAsymmetricPadding | None = None,
    ) -> VerifierContext:
        if padding is None:  # pragma: no cover
            padding = PSS()
        return VerifierContext(
            get_padding_algorithm(padding, self._key, padding),
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "SubjectPublicKeyInfo",
    ) -> bytes:
        """Serialize the public key.

        Args:
            encoding: PEM, DER or OpenSSH (defaults to PEM).
            format: The supported formats are:

                - SubjectPublicKeyInfo
                - OpenSSH

                Note:
                    ``format`` argument is not actually used by Cryptodome. It
                    is here to maintain compatibility with pyca/cryptography
                    backend counterpart.

        Returns:
            The serialized public key as bytes object.

        Raises:
            ValueError:
                if the encoding or format is not supported or invalid,
                or OpenSSH encoding is not used with OpenSSH format.
        """
        try:
            encoding, format = self._ENCODINGS[encoding], self._FORMATS[format]
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e}") from e

        kwargs: dict[str, typing.Any] = {}
        if encoding == "OpenSSH":
            self._set_openssh_args(format, kwargs)
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
    def _set_openssh_args(format: str, kwargs: dict) -> None:
        if format == "OpenSSH":
            kwargs["format"] = "OpenSSH"
            return
        raise ValueError(f"Invalid format for OpenSSH: {format!r}")

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

    @classmethod
    def load(cls, data: bytes) -> RSAPublicKey:
        try:
            key = RSA.import_key(data)
            if key.has_private():
                raise ValueError("The key is not a private key")
        except ValueError as e:
            raise ValueError(f"Failed to load key: {e!s}") from e
        return cls(key)


class EncryptorContext(base.BaseEncryptorContext):
    def __init__(self, ctx: typing.Any) -> None:
        self._ctx = ctx

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._ctx.encrypt(plaintext)


class DecryptorContext(base.BaseDecryptorContext):
    def __init__(self, ctx: typing.Any) -> None:
        self._ctx = ctx

    def decrypt(self, plaintext: bytes) -> bytes:
        try:
            return self._ctx.decrypt(plaintext)
        except ValueError as e:
            raise exc.DecryptionError from e


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


def generate(bits: int, e: int = 65537) -> RSAPrivateKey:
    """
    Generate a private key with given key modulus ``bits`` and public exponent
    ``e`` (default 65537). Recommended size of ``bits`` > 1024.

    Args:
        bits: The bit length of the RSA key.
        e: The public exponent value. Default is 65537.

    Returns:
        The RSA private key.
    """
    return RSAPrivateKey(bits, e)


def load_public_key(data: bytes) -> RSAPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Returns:
        The RSA public key.
    """
    return RSAPublicKey.load(data)


def load_private_key(
    data: bytes,
    passphrase: bytes | None = None,
) -> RSAPrivateKey:
    """Loads the private key and returns a Key interface.

    If the private key is not encrypted duting the serialization,
    ``passphrase`` must be ``None``, otherwise it must be a ``bytes`` object.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase that is used to encrypt the private key. ``None``
            if the private key is not encrypted.

    Returns:
        The RSA private key.
    """
    return RSAPrivateKey.load(data, passphrase)
