from functools import partial

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.asymmetric import rsa, padding as pads, utils

from .._asymmetric import OAEP, MGF1, PSS
from ._hashes import hashes
from ._serialization import encodings, private_format, public_format

padding = {
    OAEP: pads.OAEP,
    MGF1: pads.MGF1,
    PSS: pads.PSS,
}

_supported_encodings = frozenset((
    'PEM',
    'DER',
    'OpenSSH',
))


class RSAPrivateKey:
    def __init__(self, n=None, e=65537, **kwargs):
        if kwargs:
            # we have the key made beforehand
            # or from some classmethod
            self._key = kwargs.pop('key')
        else:
            if n is None:
                raise ValueError('modulus not provided')
            self._key = rsa.generate_private_key(e, n, defb())

        # numbers
        nos = self._key.private_numbers()
        self._p = nos.p
        self._q = nos.q

    @property
    def p(self):
        return self._p

    @property
    def q(self):
        return self._q

    def public_key(self):
        return RSAPublicKey(self._key.public_key())

    def decryptor(self, padding=OAEP()):
        return RSADecryptionCtx(self._key, padding)

    def signer(self, padding=PSS()):
        return RSASignerCtx(self._key, padding)

    def serialize(self, encoding='PEM', format='PKCS8', passphrase=None):
        if encoding not in _supported_encodings ^ {'OpenSSH'}:
            raise TypeError('Encoding must be PEM or DER')

        encd = encodings[encoding]
        fmt = private_format[format]
        if passphrase is None:
            prot = ser.NoEncryption()
        else:
            prot = ser.BestAvailableEncryption(
                memoryview(passphrase).tobytes())
        return self._key.private_bytes(encd, fmt, prot)

    @classmethod
    def load(cls, data, password=None):
        if data.startswith(b'-----BEGIN OPENSSH PRIVATE KEY'):
            key = ser.load_ssh_private_key(data, password)

        if data.startswith(b'-----'):
            key = ser.load_pem_private_key(data, password, defb())

        if data[0] == 0x30:
            key = ser.load_der_private_key(data, password, defb())

        return cls(key=key)


class RSAPublicKey:
    def __init__(self, key):
        self._key = key

    def encryptor(self, padding=OAEP()):
        return RSAEncryptionCtx(self._key, padding)

    def verifier(self, padding=PSS()):
        return RSAVerifierCtx(self._key, padding)

    def serialize(self, encoding='PEM', format='SubjectPublicKeyInfo'):
        encd = encodings[encoding]
        fmt = public_format[format]
        return self._key.public_bytes(encd, fmt)

    @classmethod
    def load(cls, data):
        if data.startswith(b'ssh-rsa '):
            key = ser.load_ssh_public_key(data, defb())

        if data.startswith(b'-----'):
            key = ser.load_pem_public_key(data, defb())

        if data[0] == 0x30:
            key = ser.load_der_public_key(data, defb())

        return cls(key=key)


def _get_padding(pad):
    _pad = padding[pad.__class__]
    _mgf = padding[pad.mgf.__class__](hashes[pad.mgf.hash]())
    return _pad, _mgf


class Context:
    def __init__(self, key, padding):
        pad, mgf = _get_padding(padding)
        try:
            self._encrypt = partial(key.encrypt,
                                    padding=pad(mgf, hashes[padding.hash](),
                                                padding.label))
        except AttributeError:
            self._decrypt = partial(key.decrypt,
                                    padding=pad(
                                        mgf,
                                        hashes[padding.hash](),
                                        padding.label,
                                    ))


class RSAEncryptionCtx(Context):
    def encrypt(self, plaintext):
        return self._encrypt(plaintext)


class RSADecryptionCtx(Context):
    def decrypt(self, ciphertext):
        return self._decrypt(ciphertext)


class SigVerContext:
    def __init__(self, key, padding):
        pad, mgf = _get_padding(padding)
        salt_len = (padding.salt_len
                    if padding.salt_len is not None else pad.MAX_LENGTH)

        try:
            self._sign = partial(key.sign, padding=pad(
                mgf,
                salt_len,
            ))
        except AttributeError:
            self._verify = partial(key.verify, padding=pad(
                mgf,
                salt_len,
            ))


class RSASignerCtx(SigVerContext):
    def sign(self, msghash):
        return self._sign(msghash.digest(),
                          algorithm=utils.Prehashed(hashes[msghash._name]()))


class RSAVerifierCtx(SigVerContext):
    def verify(self, msghash, signature):
        return self._verify(signature,
                            msghash.digest(),
                            algorithm=utils.Prehashed(hashes[msghash._name]()))
