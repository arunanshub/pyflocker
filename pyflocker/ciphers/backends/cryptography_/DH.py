from __future__ import annotations

import typing

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    ParameterFormat,
    PrivateFormat,
    PublicFormat,
)

from ... import base


class DHParameters(base.BaseDHParameters):
    _encodings = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }
    _formats = {
        "PKCS3": ParameterFormat.PKCS3,
    }

    def __init__(
        self,
        key_size: typing.Optional[int],
        generator: int = 2,
        **kwargs,
    ):
        if kwargs:
            params = kwargs.pop("parameter")
            if not isinstance(params, dh.DHParameters):  # pragma: no cover
                raise TypeError("The parameter is not a DH parameter object.")
            self._params = params
        else:
            if not isinstance(key_size, int):  # pragma: no cover
                raise TypeError("key_size must be an integer")
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
    def q(self) -> typing.Optional[int]:
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
            return self._params.parameter_bytes(
                self._encodings[encoding],
                self._formats[format],
            )
        except KeyError as e:
            raise ValueError(
                f"Invalid encoding or format: {e.args[0]!r}"
            ) from e

    @classmethod
    def load(cls, data: bytes) -> DHParameters:
        formats = {
            b"-----BEGIN DH PARAMETERS": ser.load_pem_parameters,
            b"0": ser.load_der_parameters,
        }

        try:
            loader = formats[next(filter(data.startswith, formats))]
        except StopIteration:
            raise ValueError("Invalid format.") from None

        try:
            params = loader(data)
            if not isinstance(params, dh.DHParameters):  # pragma: no cover
                raise ValueError("Invalid parameter format.")
            return cls(None, parameter=params)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. The parameter format is invalid. "
                f"Backend error message:\n{e}",
            ) from e

    @classmethod
    def load_from_parameters(
        cls,
        p: int,
        g: int = 2,
        q: typing.Optional[int] = None,
    ) -> DHParameters:
        param_nos = dh.DHParameterNumbers(p, g, q)
        return cls(None, parameter=param_nos.parameters())


class DHPrivateKey(base.BaseDHPrivateKey):
    _encodings = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }
    _formats = {
        "PKCS8": PrivateFormat.PKCS8,
    }

    def __init__(self, key):
        if not isinstance(key, dh.DHPrivateKey):  # pragma: no cover
            raise ValueError("The key is not a DH private key.")
        self._key = key

        numbers = key.private_numbers()
        self._x = numbers.x

    def parameters(self) -> DHParameters:
        return DHParameters(None, parameter=self._key.parameters())

    @property
    def key_size(self) -> int:
        return self._key.key_size

    def public_key(self) -> DHPublicKey:
        return DHPublicKey(self._key.public_key())

    def exchange(
        self,
        peer_public_key: typing.Union[
            bytes,
            DHPublicKey,
            base.BaseDHPublicKey,
        ],
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
        passphrase: typing.Optional[bytes] = None,
    ) -> bytes:
        protection: ser.KeySerializationEncryption
        if passphrase is None:
            protection = ser.NoEncryption()
        else:
            protection = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes()
            )

        try:
            return self._key.private_bytes(
                self._encodings[encoding],
                self._formats[format],
                protection,
            )
        except KeyError as e:
            raise ValueError(
                f"Invalid encoding or format: {e.args[0]!r}"
            ) from e

    @property
    def x(self) -> int:
        return self._x

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: typing.Optional[bytes] = None,
    ) -> DHPrivateKey:
        formats = {
            b"-----": ser.load_pem_private_key,
            b"0": ser.load_der_private_key,
        }

        try:
            loader = formats[next(filter(data.startswith, formats))]
        except StopIteration:
            raise ValueError("Invalid format.") from None

        # type check
        if passphrase is not None:
            passphrase = memoryview(passphrase).tobytes()

        try:
            key = loader(memoryview(data).tobytes(), passphrase)
            if not isinstance(key, dh.DHPrivateKey):
                raise ValueError(
                    "Cannot deserialize key. This key is not a DH private key"
                )
            return cls(key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                f"passphrase is incorrect. Backend error message:\n{e}"
            ) from e
        except TypeError as e:
            raise ValueError(
                "The key is encrypted but the passphrase is not given or the"
                " key is not encrypted but the passphrase is given."
                f" Cannot deserialize the key. Backend error message:\n{e}"
            ) from e


class DHPublicKey(base.BaseDHPublicKey):
    _encodings = {
        "PEM": Encoding.PEM,
        "DER": Encoding.DER,
    }
    _formats = {
        "SubjectPublicKeyInfo": PublicFormat.SubjectPublicKeyInfo,
    }

    def __init__(self, key):
        if not isinstance(key, dh.DHPublicKey):  # pragma: no cover
            raise ValueError("The key is not a DH public key.")
        self._key = key
        self._y = key.public_numbers().y

    def parameters(self) -> DHParameters:
        return DHParameters(None, parameter=self._key.parameters())

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
            return self._key.public_bytes(
                self._encodings[encoding],
                self._formats[format],
            )
        except KeyError as e:
            raise ValueError(
                f"Invalid encoding or format: {e.args[0]!r}"
            ) from e

    @property
    def y(self) -> int:
        return self._y

    @classmethod
    def load(cls, data: bytes) -> DHPublicKey:
        formats = {
            b"-----": ser.load_pem_public_key,
            b"0": ser.load_der_public_key,
        }

        try:
            loader = formats[next(filter(data.startswith, formats))]
        except StopIteration:
            raise ValueError("Invalid format.") from None

        try:
            key = loader(memoryview(data))
            if not isinstance(key, dh.DHPublicKey):
                raise ValueError(
                    "Cannot deserialize key. This key is not a DH public key"
                )
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Incorrect key format. Backend error"
                f" message:\n{e}",
            ) from e


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
    q: typing.Optional[int] = None,
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
    passphrase: typing.Optional[bytes] = None,
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
