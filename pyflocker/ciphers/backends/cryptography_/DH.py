from __future__ import annotations

import typing

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import dh

from ... import base
from .asymmetric import (
    ENCODINGS,
    PARAMETER_FORMATS,
    PRIVATE_FORMATS,
    PUBLIC_FORMATS,
)


class DHParameters:
    def __init__(
        self,
        key_size: typing.Optional[int],
        generator: int = 2,
        **kwargs,
    ):
        if kwargs:
            params = kwargs.pop("parameter")
            if not isinstance(params, dh.DHParameters):
                raise ValueError("The parameter is not a DH parameter object.")
            self._params = params
        else:
            if key_size is None:
                raise TypeError("key_size must be an integer")
            self._params = dh.generate_parameters(generator, key_size)

        numbers = self._params.parameter_numbers()
        self._g = numbers.g
        self._p = numbers.p
        self._q = numbers.q

    @property
    def g(self) -> int:
        """The generator value."""
        return self._g

    @property
    def p(self) -> int:
        """The prime modulus value."""
        return self._p

    @property
    def q(self) -> typing.Optional[int]:
        """The p subgroup order value."""
        self._q

    def private_key(self) -> DHPrivateKey:
        """Create a DH private key from the parameters.

        Returns:
            A private key object.
        """
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
                ENCODINGS[encoding],
                PARAMETER_FORMATS[format],
            )
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e.args[0]}") from e

    @classmethod
    def load(cls, data: bytes) -> DHParameters:
        """Deserialize the encoded DH parameters.

        Args:
            data:
                The parameters as an encoded bytes object.

        Returns:
            DHParameters: DH parameter object.
        """
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
            if not isinstance(params, dh.DHParameters):
                raise ValueError("Invalid parameter format.")
            return cls(None, parameter=params)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Either Key format is invalid or "
                "passphrase is missing or incorrect."
            ) from e

    @classmethod
    def load_from_parameters(
        cls,
        p: int,
        g: int = 2,
        q: typing.Optional[int] = None,
    ) -> DHParameters:
        """Generates a DH parameter group from the parameters.

        Args:
            p: The prime modulus value.
            g: The generator value. Must be 2 or 5. Default is 2.
            q: p subgroup order value. Defaults to ``None``.

        Returns:
            DHParameters object.
        """
        param_nos = dh.DHParameterNumbers(p, g, q)
        return cls(None, parameter=param_nos.parameters())


class DHPrivateKey(base.BasePrivateKey):
    def __init__(self, key):
        if not isinstance(key, dh.DHPrivateKey):
            raise ValueError("The key is not a DH private key.")
        self._key = key

        numbers = key.private_numbers()
        self._x = numbers.x

    def parameters(self) -> DHParameters:
        """Creates a new :any:`DHParameters` object from the key.

        Returns:
            The DH parameter object.
        """
        return DHParameters(None, parameter=self._key.parameters())

    @property
    def key_size(self) -> int:
        """Size of the key, in bytes."""
        return self._key.key_size

    def public_key(self) -> DHPublicKey:
        """Create a public key from the private key.

        Returns:
            A public key object.
        """
        return DHPublicKey(self._key.public_key())

    def exchange(
        self,
        peer_public_key: typing.Union[bytes, DHPublicKey],
    ) -> bytes:
        """Perform a key exchange.

        Args:
            peer_public_key:
                The peer public key can be a bytes or a :any:`DHPublicKey`
                object.

        Returns:
            A shared key.

        Raises:
            TypeError:
                if ``peer_public_key`` is not a bytes-like or
                :any:`DHPublicKey` object.
        """
        if isinstance(peer_public_key, DHPublicKey):
            return self._key.exchange(peer_public_key._key)
        return self._key.exchange(
            DHPublicKey.load(memoryview(peer_public_key).tobytes())._key
        )

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[bytes] = None,
    ) -> bytes:
        """Serialize the private key.

        Args:
            encoding (str):
                The encoding to use. Can be ``PEM`` or ``DER``.
                Defaults to ``PEM``.
            format (str): The format can be ``PKCS8`` only.
            passphrase (bytes):
                The passphrase to use to protect the private key.
                ``None`` if the private key is not encrypted.

        Returns:
            bytes: The private key as bytes object.

        Raises:
            ValueError: if the encoding or format is invalid.
            TypeError: if the passphrase is not a bytes-like object.
        """
        if passphrase is None:
            protection = ser.NoEncryption()
        else:
            protection = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes()
            )

        try:
            return self._key.private_bytes(
                ENCODINGS[encoding],
                PRIVATE_FORMATS[format],
                protection,
            )
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e.args[0]}") from e

    @property
    def x(self) -> int:
        return self._x

    @classmethod
    def load(
        cls,
        data: bytes,
        passphrase: typing.Optional[bytes] = None,
    ) -> DHPrivateKey:
        """Deserialize and load the the private key.

        Args:
            data: The serialized private key as ``bytes-like`` object.
            passphrase:
                The passphrase that was used to protect the private key. If key
                is not protected, passphrase is ``None``.

        Returns:
            A private key.

        Raises:
            ValueError: If the key could not be deserialized.
            TypeError: If passphrase is not a bytes-like object.
        """
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
            return cls(key)
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


class DHPublicKey(base.BasePublicKey):
    def __init__(self, key):
        if not isinstance(key, dh.DHPublicKey):
            raise ValueError("The key is not a DH public key.")
        self._key = key
        self._y = key.public_numbers().y

    def parameters(self) -> DHParameters:
        """Creates a new :any:`DHParameters` object from the key.

        Returns:
            The DH parameter object.
        """
        return DHParameters(None, parameter=self._key.parameters())

    @property
    def key_size(self) -> int:
        """Size of the key, in bytes."""
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
            KeyError: if the encoding or format is invalid.
        """
        try:
            return self._key.public_bytes(
                ENCODINGS[encoding],
                PUBLIC_FORMATS[format],
            )
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e.args}") from e

    @property
    def y(self) -> int:
        return self._y

    @classmethod
    def load(cls, data: bytes) -> DHPublicKey:
        """Deserialize and load the public key.

        Args:
            data: The serialized public key as ``bytes-like`` object.

        Returns:
            A public key object.

        Raises:
            ValueError: If the key could not be deserialized.
        """
        formats = {
            b"-----": ser.load_pem_public_key,
            b"0": ser.load_der_public_key,
        }

        try:
            loader = formats[next(filter(data.startswith, formats))]
        except IndexError:
            raise ValueError("Invalid format.") from None

        try:
            return cls(key=loader(memoryview(data)))
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Incorrect key format.",
            ) from e


def generate(key_size: int, g: int = 2) -> DHParameters:
    """
    Generate DHE parameter with prime number's bit size ``bits`` and
    generator ``g`` (default 2). Recommended size of ``bits`` > 1024.

    Args:
        key_size: The bit length of the prime modulus.
        g: The value to use as a generator value. Default is 2.

    Returns:
        DHParameters: A DH key exchange paramenter object.
    """
    return DHParameters(key_size, g)


def load_from_parameters(
    p: int,
    g: int = 2,
    q: typing.Optional[int] = None,
) -> DHParameters:
    """Create a DH Parameter object from the given parameters.

    Args:
        p: The prime modulus ``p`` as ``int``.
        g: The generator.
        q: ``p`` subgroup order value.

    Returns:
        DHParameters: A DH key exchange paramenter object.
    """
    return DHParameters.load_from_parameters(p, g, q)


def load_parameters(data: bytes) -> DHParameters:
    """Deserialize the DH parameters and load a parameter object.

    Args:
        data: Serialized DH Parameter.

    Returns:
        DHParameters: A parameter object.
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
