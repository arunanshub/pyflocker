from __future__ import annotations

import typing

from cryptography.hazmat.primitives import serialization as serial
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    ParameterFormat,
    PrivateFormat,
    PublicFormat,
)

from pyflocker.ciphers import base


class DHParameters(base.BaseDHParameters):
    _ENCODINGS = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }

    _FORMATS = {
        "PKCS3": ParameterFormat.PKCS3,
    }

    _LOADERS = {
        b"-----BEGIN DH PARAMETERS": serial.load_pem_parameters,
        b"0": serial.load_der_parameters,
    }

    def __init__(
        self,
        key_size: int | None,
        generator: int = 2,
        _params: dh.DHParameters | None = None,
    ) -> None:
        if _params is not None:
            self._params = _params
        else:
            if not isinstance(key_size, int):  # pragma: no cover
                msg = "key_size must be an integer"
                raise TypeError(msg)
            self._params = dh.generate_parameters(generator, key_size)

        numbers = self._params.parameter_numbers()
        self._g = numbers.g
        self._p = numbers.p
        self._q = numbers.q

    @property
    def g(self) -> int:
        return self._g

    @property
    def p(self) -> int:
        return self._p

    @property
    def q(self) -> int | None:
        return self._q

    def private_key(self) -> DHPrivateKey:
        return DHPrivateKey(self._params.generate_private_key())

    def serialize(self, encoding: str = "PEM", format: str = "PKCS3") -> bytes:
        """Serialize the DH parameters.

        Args:
            encoding:
                The encoding can be ``PEM`` or ``DER``. Defaults to ``PEM``.
            format: The format. Defaults to ``PKCS3``.

        Returns:
            The parameters encoded as bytes object.

        Raises:
            ValueError: if the encoding of format is invalid.
        """
        try:
            encd = self._ENCODINGS[encoding]
            fmt = self._FORMATS[format]
        except KeyError as e:
            msg = f"The encoding or format is invalid: {e.args[0]!r}"
            raise ValueError(msg) from e

        try:
            return self._params.parameter_bytes(encd, fmt)
        except ValueError as e:
            msg = f"Failed to serialize key: {e!s}"
            raise ValueError(msg) from e

    @classmethod
    def load(cls, data: bytes) -> DHParameters:
        data = memoryview(data).tobytes()
        loader = cls._get_loader(data)
        try:
            params = loader(data)
            if not isinstance(params, dh.DHParameters):
                msg = "Data is not a DH parameter."
                raise ValueError(msg)
        except ValueError as e:
            msg = f"Failed to load key: {e!s}"
            raise ValueError(msg) from e

        return cls(None, _params=params)

    @classmethod
    def _get_loader(cls, data: bytes) -> typing.Callable:
        """
        Returns a loader function depending on the initial bytes of the
        parameter.
        """
        try:
            return cls._LOADERS[next(filter(data.startswith, cls._LOADERS))]
        except StopIteration:
            msg = "Invalid format."
            raise ValueError(msg) from None

    @classmethod
    def load_from_parameters(
        cls,
        p: int,
        g: int = 2,
        q: int | None = None,
    ) -> DHParameters:
        param_nos = dh.DHParameterNumbers(p, g, q)
        return cls(None, _params=param_nos.parameters())


class DHPrivateKey(base.BaseDHPrivateKey):
    _ENCODINGS = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }
    _FORMATS = {
        "PKCS8": PrivateFormat.PKCS8,
    }

    _LOADERS = {
        b"-----": serial.load_pem_private_key,
        b"0": serial.load_der_private_key,
    }

    def __init__(self, key: dh.DHPrivateKey) -> None:
        if not isinstance(key, dh.DHPrivateKey):  # pragma: no cover
            msg = "The key is not a DH private key."
            raise ValueError(msg)
        self._key = key

        numbers = key.private_numbers()
        self._x = numbers.x

    def parameters(self) -> DHParameters:
        return DHParameters(None, _params=self._key.parameters())

    @property
    def key_size(self) -> int:
        return self._key.key_size

    def public_key(self) -> DHPublicKey:
        return DHPublicKey(self._key.public_key())

    def exchange(
        self,
        peer_public_key: bytes | DHPublicKey | base.BaseDHPublicKey,
    ) -> bytes:
        if isinstance(peer_public_key, bytes):
            return self._key.exchange(DHPublicKey.load(peer_public_key)._key)
        # optimizing case: key is made from this Backend
        if isinstance(peer_public_key, DHPublicKey):
            return self._key.exchange(peer_public_key._key)
        return self._key.exchange(  # pragma: no cover
            DHPublicKey.load(
                peer_public_key.serialize("PEM", "SubjectPublicKeyInfo"),
            )._key
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
            msg = f"The encoding or format is invalid: {e.args[0]!r}"
            raise ValueError(msg) from e

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
            msg = f"Failed to serialize key: {e!s}"
            raise ValueError(msg) from e

    @property
    def x(self) -> int:
        return self._x

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: bytes | None = None,
    ) -> DHPrivateKey:
        data = memoryview(data).tobytes()
        loader = cls._get_loader(data)

        if passphrase is not None:
            passphrase = memoryview(passphrase).tobytes()

        try:
            key = loader(data, passphrase)
            if not isinstance(key, dh.DHPrivateKey):
                msg = "Key is not a DH private key."
                raise ValueError(msg)
        except (ValueError, TypeError) as e:
            msg = f"Failed to load key: {e!s}"
            raise ValueError(msg) from e

        return cls(key)

    @classmethod
    def _get_loader(cls, data: bytes) -> typing.Callable:
        """
        Returns a loader function depending on the initial bytes of the key.
        """
        try:
            return cls._LOADERS[next(filter(data.startswith, cls._LOADERS))]
        except StopIteration:
            msg = "Invalid format"
            raise ValueError(msg) from None


class DHPublicKey(base.BaseDHPublicKey):
    _ENCODINGS = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }

    _FORMATS = {
        "SubjectPublicKeyInfo": PublicFormat.SubjectPublicKeyInfo,
    }

    _LOADERS = {
        b"-----": serial.load_pem_public_key,
        b"0": serial.load_der_public_key,
    }

    def __init__(self, key: dh.DHPublicKey) -> None:
        if not isinstance(key, dh.DHPublicKey):  # pragma: no cover
            msg = "The key is not a DH public key."
            raise ValueError(msg)
        self._key = key
        self._y = key.public_numbers().y

    def parameters(self) -> DHParameters:
        return DHParameters(None, _params=self._key.parameters())

    @property
    def key_size(self) -> int:
        return self._key.key_size

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "SubjectPublicKeyInfo",
    ) -> bytes:
        """Serialize the public key.

        Args:
            encoding: The encoding to use. It can be ``PEM`` or ``DER``.
            format: The format can be ``SubjectPublicKeyInfo`` only.

        Returns:
            The public key as bytes object.

        Raises:
            ValueError: if the encoding or format is invalid.
        """
        try:
            encd = self._ENCODINGS[encoding]
            fmt = self._FORMATS[format]
        except KeyError as e:
            msg = f"Invalid encoding or format: {e.args[0]!r}"
            raise ValueError(msg) from e

        try:
            return self._key.public_bytes(encd, fmt)
        except ValueError as e:
            msg = f"Failed to serialize key: {e!s}"
            raise ValueError(msg) from e

    @property
    def y(self) -> int:
        return self._y

    @classmethod
    def load(cls, data: bytes) -> DHPublicKey:
        data = memoryview(data).tobytes()
        loader = cls._get_loader(data)
        try:
            key = loader(data)
            if not isinstance(key, dh.DHPublicKey):
                msg = "Key is not a DH public key."
                raise ValueError(msg)
        except ValueError as e:
            msg = f"Failed to load key: {e!s}"
            raise ValueError(msg) from e

        return cls(key)

    @classmethod
    def _get_loader(cls, data: bytes) -> typing.Callable:
        """
        Returns a loader function depending on the initial bytes of the key.
        """
        try:
            return cls._LOADERS[next(filter(data.startswith, cls._LOADERS))]
        except StopIteration:
            msg = "Invalid format."
            raise ValueError(msg) from None


def generate(key_size: int, g: int = 2) -> DHParameters:
    """
    Generate DHE parameter with prime number's bit size ``bits`` and
    generator ``g`` (default 2). Recommended size of ``bits`` > 1024.

    Args:
        key_size: The bit length of the prime modulus.
        g: The value to use as a generator value. Default is 2.

    Returns:
        A DH key exchange paramenter object.
    """
    return DHParameters(key_size, g)


def load_from_parameters(
    p: int,
    g: int = 2,
    q: int | None = None,
) -> DHParameters:
    """Create a DH Parameter object from the given parameters.

    Args:
        p: The prime modulus `p` as ``int``.
        g: The generator.
        q: `p` subgroup order value.

    Returns:
        A DH key exchange paramenter object.
    """
    return DHParameters.load_from_parameters(p, g, q)


def load_parameters(data: bytes) -> DHParameters:
    """Deserialize the DH parameters and load a parameter object.

    Args:
        data: Serialized DH Parameter.

    Returns:
        A parameter object.
    """
    return DHParameters.load(data)


def load_public_key(data: bytes) -> DHPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data: The public key (a bytes-like object) to deserialize.

    Returns:
        A public key object.
    """
    return DHPublicKey.load(data)


def load_private_key(
    data: bytes,
    passphrase: bytes | None = None,
) -> DHPrivateKey:
    """Loads the private key and returns a private key object.

    If the private key was not encrypted duting the serialization,
    ``passphrase`` must be ``None``, otherwise it must be a ``bytes-like``
    object.

    Args:
        data: The private key (a bytes-like object) to deserialize.
        passphrase:
            The passphrase (in bytes) that was used to encrypt the private
            key. ``None`` if the key was not encrypted.

    Returns:
        A private key object.
    """
    return DHPrivateKey.load(data, passphrase)
