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
            self._params = kwargs.pop('parameter')
        else:
            if key_size is None:
                raise ValueError('key_size is not provided')
            self._params = dh.generate_parameters(
                generator,
                key_size,
                defb(),
            )

    def private_key(self):
        return DHPrivateKey(self._params.generate_private_key())

    def serialize(self, encoding='PEM', format='PKCS3'):
        return self._params.parameter_bytes(
            encodings[encoding],
            parameter_format[format],
        )

    @property
    def g(self):
        return self._params.parameter_numbers().g

    @property
    def p(self):
        return self._params.parameter_numbers().p

    @property
    def q(self):
        return self._params.parameter_numbers().q

    @classmethod
    def load(cls, data):
        if data.startswith(b'-----BEGIN DH PARAMETERS'):
            param = ser.load_pem_parameters(memoryview(data), defb())

        elif data[0] == 0x30:
            param = ser.load_der_parameters(memoryview(data), defb())

        else:
            raise ValueError('incorrect parameter format')
        return cls(parameter=param)

    @classmethod
    def load_from_parameters(cls, p, g=2, q=None):
        param_nos = dh.DHParameterNumbers(p, g, q)
        return cls(parameter=param_nos.parameters(defb()))


class _DHKey:
    def parameters(self):
        return DHParameters(parameter=self._key.parameters())

    @property
    def key_size(self):
        return self._key.key_size


class DHPrivateKey(_DHKey, base.BasePrivateKey):
    def __init__(self, key):
        self._key = key

    def public_key(self):
        return DHPublicKey(self._key.public_key())

    def exchange(self, peer_public_key):
        if isinstance(peer_public_key, (bytes, bytearray, memoryview)):
            peer_public_key = DHPublicKey.load(peer_public_key)

        return self._key.exchange(peer_public_key._key)

    def serialize(self, encoding='PEM', format='PKCS8', passphrase=None):
        if passphrase is None:
            prot = ser.NoEncryption()

        else:
            prot = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes(), )
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
        if data.startswith(b'-----'):
            loader = ser.load_pem_private_key

        elif data[0] == 0x30:
            loader = ser.load_der_private_key

        else:
            raise ValueError('incorrect key format')

        # type check
        if passphrase is not None:
            passphrase = memoryview(passphrase)

        try:
            return cls(key=loader(
                memoryview(data),
                passphrase,
                defb(),
            ), )
        except (ValueError, TypeError) as e:
            raise ValueError(
                'Cannot deserialize key. '
                'Either Key format is invalid or '
                'password is missing or incorrect.', ) from e


class DHPublicKey(_DHKey, base.BasePublicKey):
    def __init__(self, key):
        self._key = key

    def serialize(self, encoding='PEM', format='SubjectPublicKeyInfo'):
        return self._key.public_bytes(
            encodings[encoding],
            public_format[format],
        )

    @property
    def y(self):
        return self._key.public_numbers().y

    @classmethod
    def load(cls, data):
        if data.startswith(b'-----'):
            loader = ser.load_pem_public_key

        elif data[0] == 0x30:
            loader = ser.load_der_public_key

        else:
            raise ValueError('incorrect key format')

        try:
            return cls(key=loader(data, defb()))
        except ValueError as e:
            raise ValueError(
                'Cannot deserialize key. '
                'Incorrect key format.', ) from e
