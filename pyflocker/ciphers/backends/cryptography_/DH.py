from __future__ import annotations

import sys
import typing

if sys.version_info >= (3, 9):
    from functools import cache as _cache
else:
    from functools import lru_cache

    def _cache(func):
        return lru_cache(maxsize=None)(func)


from cryptography.hazmat.backends import default_backend as defb
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
    def __init__(self, key_size: int, generator: int = 2, **kwargs):
        if kwargs:
            params = kwargs.pop("parameter")
            if not isinstance(params, dh.DHParameters):
                raise ValueError("The parameter is not a DH parameter object.")
            self._params = params
        else:
            self._params = dh.generate_parameters(
                generator,
                key_size,
                defb(),
            )

    def private_key(self) -> DHPrivateKey:
        """Create a DH private key from the parameters.

        Returns:
            DHPrivateKey: A private key object.
        """
        return DHPrivateKey(self._params.generate_private_key())

    def serialize(self, encoding: str = "PEM", format: str = "PKCS3"):
        """Serialize the DH parameters.

        Args:
            encoding (str):
                The encoding can be ``PEM`` or ``DER``. Defaults to ``PEM``.
            format (str): The format. Defaults to ``PKCS3``.

        Returns:
            bytes: The parameters encoded as bytes object.

        Raises:
            ValueError: if the encoding of format is invalid.
        """
        try:
            return self._params.parameter_bytes(
                ENCODINGS[encoding],
                PARAMETER_FORMATS[format],
            )
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e.args}") from e

    def _numbers(self):
        return self._params.parameter_numbers()

    @property
    @_cache
    def g(self) -> int:
        """The generator value."""
        return self._numbers().g

    @property
    @_cache
    def p(self) -> int:
        """The prime modulus value."""
        return self._numbers().p

    @property
    def q(self) -> int:
        """The p subgroup order value."""
        return self._numbers().q

    @classmethod
    def load(cls, data: typing.ByteString) -> DHParameters:
        """Load the :any:`DHParameters` from the encoded format.

        Args:
            data (bytes, bytearray):
                The parameters as an encoded bytes object.

        Returns:
            DHParameters: DH parameter object.
        """
        fmts = {
            b"-----BEGIN DH PARAMETERS": ser.load_pem_parameters,
            b"0": ser.load_der_parameters,
        }

        try:
            loader = fmts[[*filter(data.startswith, fmts)][0]]
        except IndexError:
            raise ValueError("Invalid format.") from None
        try:
            params = loader(data, defb())
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
    ):
        """Generates a DH parameter group from the parameters.

        Args:
            p (int): The prime modulus value.
            g (int): The generator value. Must be 2 or 5. Default is 2.
            q (int): p subgroup order value. Defaults to ``None``.

        Returns:
            DHParameters: DHParameters object.
        """
        param_nos = dh.DHParameterNumbers(p, g, q)
        return cls(None, parameter=param_nos.parameters(defb()))


class _DHKey:
    def parameters(self) -> DHParameters:
        """Creates a new :any:`DHParameters` object from the key.

        Returns:
            DHParameters: The DH parameter object.
        """
        return DHParameters(None, parameter=self._key.parameters())

    @property
    def key_size(self) -> int:
        """Size of the key, in bytes."""
        return self._key.key_size


class DHPrivateKey(_DHKey, base.BasePrivateKey):
    def __init__(self, key):
        if not isinstance(key, dh.DHPrivateKey):
            raise ValueError("The key is not a DH private key.")
        self._key = key

    def public_key(self) -> DHPublicKey:
        """Create a public key from the private key.

        Returns:
            DHPublicKey: A public key object.
        """
        return DHPublicKey(self._key.public_key())

    def exchange(self, peer_public_key: typing.ByteString) -> bytes:
        """Perform a key exchange.

        Args:
            peer_public_key (bytes, bytearray):
                The peer public key can be a bytes or a :any:`DHPublicKey`
                object.

        Returns:
            bytes: A shared key.

        Raises:
            TypeError: if ``peer_public_key`` is not a bytes-like object.
        """
        if not isinstance(peer_public_key, (bytes, bytearray, memoryview)):
            raise TypeError("peer_public_key must be a bytes-like object.")
        peer_public_key = DHPublicKey.load(peer_public_key)
        return self._key.exchange(peer_public_key._key)

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "PKCS8",
        passphrase: typing.Optional[typing.ByteString] = None,
    ):
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
            prot = ser.NoEncryption()
        else:
            if not isinstance(passphrase, (bytes, bytearray, memoryview)):
                raise TypeError("passphrase must be a bytes-like object.")
            prot = ser.BestAvailableEncryption(passphrase)

        try:
            return self._key.private_bytes(
                ENCODINGS[encoding],
                PRIVATE_FORMATS[format],
                prot,
            )
        except KeyError as e:
            raise ValueError(f"Invalid encoding or format: {e.args}") from e

    @property
    @_cache
    def x(self) -> int:
        return self._key.private_numbers().x

    @classmethod
    def load(
        cls,
        data: typing.ByteString,
        passphrase: typing.Optional[typing.ByteString] = None,
    ) -> DHPrivateKey:
        """Deserialize and load the the private key.

        Args:
            data (bytes): The serialized private key as ``bytes-like`` object.
            passphrase (bytes, bytearray):
                The passphrase that was used to protect the private key.
                If key is not protected, passphrase is ``None``.

        Returns:
            DHPrivateKey: A private key.

        Raises:
            ValueError: If the key could not be deserialized.
            TypeError: If passphrase is not a bytes-like object.
        """
        fmts = {
            b"-----": ser.load_pem_private_key,
            b"0": ser.load_der_private_key,
        }

        try:
            loader = fmts[[*filter(data.startswith, fmts)][0]]
        except IndexError:
            raise ValueError("Invalid format.") from None

        # type check
        if passphrase is not None:
            if not isinstance(passphrase, (bytes, bytearray, memoryview)):
                raise TypeError("passphrase must be a bytes-like object.")

        try:
            key = loader(
                memoryview(data),
                passphrase,
                defb(),
            )
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


class DHPublicKey(_DHKey, base.BasePublicKey):
    def __init__(self, key):
        if not isinstance(key, dh.DHPublicKey):
            raise ValueError("The key is not a DH public key.")
        self._key = key

    def serialize(
        self,
        encoding: str = "PEM",
        format: str = "SubjectPublicKeyInfo",
    ) -> bytes:
        """Serialize the public key.

        Args:
            encoding (str): The encoding to use. It can be ``PEM`` or ``DER``.
            format (str): The format can be ``SubjectPublicKeyInfo`` only.

        Returns:
            bytes: The public key as bytes object.

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
    @_cache
    def y(self):
        return self._key.public_numbers().y

    @classmethod
    def load(cls, data: typing.ByteString) -> DHPublicKey:
        """Deserialize and load the public key.

        Args:
            data (bytes): The serialized public key as ``bytes-like`` object.

        Returns:
            DHPublicKey: A public key object.

        Raises:
            ValueError: If the key could not be deserialized.
        """
        fmts = {
            b"-----": ser.load_pem_public_key,
            b"0": ser.load_der_public_key,
        }

        try:
            loader = fmts[[*filter(data.startswith, fmts)][0]]
        except IndexError:
            raise ValueError("Invalid format.") from None

        try:
            key = loader(memoryview(data), defb())
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Incorrect key format.",
            ) from e


def generate(
    key_size: int,
    g: int = 2,
) -> DHParameters:
    """
    Generate DHE parameter with prime number's bit size ``bits`` and
    generator ``g`` (default 2). Recommended size of ``bits`` > 1024.

    Args:
        key_size (int): The bit length of the prime modulus.
        g (int): The value to use as a generator value. Default is 2.

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
        p (int): The prime modulus ``p`` as ``int``.
        g (int): The generator.
        q (int): ``p`` subgroup order value.

    Returns:
        DHParameters: A DH key exchange paramenter object.
    """
    return DHParameters.load_from_parameters(p, g, q)


def load_parameters(data: typing.ByteString) -> DHParameters:
    """Deserialize the DH parameters and load a parameter object.

    Args:
        data (bytes): Serialized DH Parameter.

    Returns:
        DHParameters: A parameter object.
    """
    return DHParameters.load(data)


def load_public_key(data: typing.ByteString) -> DHPublicKey:
    """Loads the public key and returns a Key interface.

    Args:
        data (bytes, bytearray):
            The public key (a bytes-like object) to deserialize.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        DHPublicKey: A public key object.
    """
    return DHPublicKey.load(data)


def load_private_key(
    data: typing.ByteString,
    passphrase: typing.Optional[typing.ByteString] = None,
) -> DHPrivateKey:
    """Loads the private key and returns a private key object.

    If the private key was not encrypted duting the serialization,
    ``passphrase`` must be ``None``, otherwise it must be a ``bytes-like``
    object.

    Args:
        data (bytes, bytearray):
            The private key (a bytes-like object) to deserialize.
        passphrase (bytes, bytearray):
            The passphrase (in bytes) that was used to encrypt the
            private key.`None` if the key was not encrypted.

    Keyword Arguments:
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be a value from :any:`Backends`.

    Returns:
        DHPrivateKey: A private key object.
    """
    return DHPrivateKey.load(data, passphrase)
