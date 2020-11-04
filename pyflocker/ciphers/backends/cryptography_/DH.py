from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization as ser

from .. import base
from ._serialization import (
    private_format,
    public_format,
    encodings,
    parameter_format,
)


class DHParameters:
    def __init__(self, key_size=None, generator=2, **kwargs):
        if kwargs:
            params = kwargs.pop("parameter")
            if not isinstance(params, dh.DHParameters):
                raise ValueError("The parameter is not a DH parameter object.")
            self._params = params
        else:
            if key_size is None:
                raise ValueError("key_size is not provided")
            self._params = dh.generate_parameters(
                generator,
                key_size,
                defb(),
            )

    def private_key(self):
        """Create a DH private key from the parameters.

        Returns:
            :any:`DHPrivateKey`: A `DHPrivateKey` object.
        """
        return DHPrivateKey(self._params.generate_private_key())

    def serialize(self, encoding="PEM", format="PKCS3"):
        """Serialize the DH parameters.

        Args:
            encoding (str): The encoding can be `PEM` or `DER`.
                Defaults to `PEM`.

            format (str): the format. Defaults to `PKCS3`.

        Returns:
            bytes: The parameters encoded as bytes object.

        Raises:
            KeyError: if the encoding of format is invalid.
        """
        return self._params.parameter_bytes(
            encodings[encoding],
            parameter_format[format],
        )

    @property
    def g(self):
        """The generator value.

        Returns:
            int: generator value.
        """
        return self._params.parameter_numbers().g

    @property
    def p(self):
        """The prime modulus value.

        Returns:
            int: the prime modulus value.
        """
        return self._params.parameter_numbers().p

    @property
    def q(self):
        """The p subgroup order value.

        Returns:
            int: p subgroup order value.
        """
        return self._params.parameter_numbers().q

    @classmethod
    def load(cls, data):
        """Load the :any:`DHParameters` from the encoded format.

        Args:
            data (bytes, bytearray):
                The parameters as an encoded bytes object.

        Returns:
            :any:`DHParameters`: `DHParameters` object.
        """
        if data.startswith(b"-----BEGIN DH PARAMETERS"):
            param = ser.load_pem_parameters(memoryview(data), defb())

        elif data[0] == 0x30:
            param = ser.load_der_parameters(memoryview(data), defb())

        else:
            raise ValueError("incorrect parameter format")
        return cls(parameter=param)

    @classmethod
    def load_from_parameters(cls, p, g=2, q=None):
        """Generates a DH parameter group from the parameters.

        Args:
            p (int): The prime modulus value.
            g (int): The generator value. Must be 2 or 5. Default is 2.
            q (int): p subgroup order value. Defaults to `None`.

        Returns:
            :any:`DHParameters`: DHParameters object.
        """
        param_nos = dh.DHParameterNumbers(p, g, q)
        return cls(parameter=param_nos.parameters(defb()))


class _DHKey:
    def parameters(self):
        """Creates a new :any:`DHParameters` object from the key.

        Returns:
            :any:`DHParameters`: The DH parameter object.
        """
        return DHParameters(parameter=self._key.parameters())

    @property
    def key_size(self):
        """Size of the key, in bytes.

        Returns:
            int: key size, in bytes.
        """
        return self._key.key_size


class DHPrivateKey(_DHKey, base.BasePrivateKey):
    def __init__(self, key):
        if not isinstance(key, dh.DHPrivateKey):
            raise ValueError("The key is not a DH private key.")
        self._key = key

    def public_key(self):
        """Create a public key from the private key.

        Returns:
            :any:`DHPublicKey`: `DHPublicKey` object.
        """
        return DHPublicKey(self._key.public_key())

    def exchange(self, peer_public_key):
        """Perform a key exchange.

        Args:
            peer_public_key (bytes, :any:`DHPublicKey`):
                The peer public key can be a bytes or a :any:`DHPublicKey`
                object.

        Returns:
            bytes: A shared key.
        """
        if isinstance(peer_public_key, (bytes, bytearray, memoryview)):
            peer_public_key = DHPublicKey.load(peer_public_key)

        return self._key.exchange(peer_public_key._key)

    def serialize(self, encoding="PEM", format="PKCS8", passphrase=None):
        """Serialize the private key.

        Args:
            encoding (str): The encoding to use.
            format (str): The format can be `PKCS8` only.
            passphrase (bytes):
                The passphrase to use to protect the private key

        Returns:
            bytes: The private key as bytes object.

        Raises:
            KeyError: if the encoding or format is invalid.
        """
        if passphrase is None:
            prot = ser.NoEncryption()

        else:
            prot = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes(),
            )
        return self._key.private_bytes(
            encodings[encoding],
            private_format[format],
            prot,
        )

    @property
    def x(self):
        return self._key.private_numbers().x

    @classmethod
    def load(cls, data, passphrase=None):
        """Deserialize and load the the private key.

        Args:
            data (bytes): The serialized private key as `bytes` object.
            passphrase (bytes, bytearray):
                The passphrase that was used to protect the private key.
                If key is not protected, passphrase is `None`.

        Returns:
            :any:`DHPrivateKey`: A `DHPrivateKey` object.

        Raises:
            ValueError: If the key could not be deserialized.
        """
        if data.startswith(b"-----"):
            loader = ser.load_pem_private_key

        elif data[0] == 0x30:
            loader = ser.load_der_private_key

        else:
            raise ValueError("incorrect key format")

        # type check
        if passphrase is not None:
            passphrase = memoryview(passphrase)

        try:
            key = loader(
                memoryview(data),
                passphrase,
                defb(),
            )
            return cls(key=key)
        except (ValueError, TypeError) as e:
            raise ValueError(
                "Cannot deserialize key. "
                "Either Key format is invalid or "
                "password is missing or incorrect.",
            ) from e


class DHPublicKey(_DHKey, base.BasePublicKey):
    def __init__(self, key):
        if not isinstance(key, dh.DHPublicKey):
            raise ValueError("The key is not a DH public key.")
        self._key = key

    def serialize(self, encoding="PEM", format="SubjectPublicKeyInfo"):
        """Serialize the public key.

        Args:
            encoding (str): The encoding to use. It can be `PEM` or `DER`.
            format (str): The format can be `SubjectPublicKeyInfo` only.

        Returns:
            bytes: The public key as bytes object.

        Raises:
            KeyError: if the encoding or format is invalid.
        """
        return self._key.public_bytes(
            encodings[encoding],
            public_format[format],
        )

    @property
    def y(self):
        return self._key.public_numbers().y

    @classmethod
    def load(cls, data):
        """Deserialize and load the public key.

        Args:
            data (bytes): The serialized public key as `bytes` object.

        Returns:
            :any:`DHPublicKey`: A `DHPublicKey` object.

        Raises:
            ValueError: If the key could not be deserialized.
        """
        if data.startswith(b"-----"):
            loader = ser.load_pem_public_key

        elif data[0] == 0x30:
            loader = ser.load_der_public_key

        else:
            raise ValueError("incorrect key format")

        try:
            key = loader(memoryview(data), defb())
            return cls(key=key)
        except ValueError as e:
            raise ValueError(
                "Cannot deserialize key. Incorrect key format.",
            ) from e
