from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from ._serialization import encodings, formats, protection_schemes

_sig_encodings = {
    'binary': 'binary',
    'der': 'der',
}

_sig_modes = {
    'fips-186-3': 'fips-186-3',
    'deterministic-rfc6979': 'deterministic-rfc6979',
}

curves = {k: k for k in ECC._curves}


class _ECCKey:
    @classmethod
    def load(cls, data, passphrase=None):
        """Loads the private/public key and returns a Key interface.

        For a private key,`password` must be a `bytes` object if the
        key was encrypted while serialization, otherwise `None`.
        """
        return cls(key=ECC.import_key(data, passphrase))


class ECCPrivateKey(_ECCKey):
    def __init__(self, curve=None, **kwargs):
        if kwargs:
            self._key = kwargs.pop('curve')
            return
        self._key = ECC.generate(curve=curves[curve])

    def public_key(self):
        """Returns public key from the private key"""
        return ECCPublicKey(self._key.public_key())

    def serialize(
        self,
        encoding='PEM',
        format='PKCS8',
        passphrase=None,
        *,
        protection=None,
    ):
        """Serialize the private key.

        - `encoding` can be PEM or DER (defaults to PEM).
        - The `format` can be:
            - PKCS8 (default)
            - PKCS1

        - `passphrase` must be a bytes object.
          If `passphrase` is None, the private key will be exported
          in the clear!
        - `protection` ...
        """
        if encoding not in encodings.keys() ^ {'OpenSSH'}:
            raise TypeError('encoding must be PEM or DER')

        if format not in formats:
            raise KeyError('invalid format')

        if passphrase is not None and protection is None:
            # use a curated encryption choice and not DES-EDE3-CBC
            prot = dict(protection='PBKDF2WithHMAC-SHA1AndAES256-CBC')

        if format == 'PKCS1':
            if protection is not None:
                raise TypeError('protection is meaningful only for PKCS8')
            prot = {}

        return self._key.export_key(
            format=encodings[encoding],
            use_pkcs8=(True if format == 'PKCS8' else False),
            passphrase=(memoryview(passphrase).tobytes()
                        if passphrase is not None else None),
            **prot,
        )

    def signer(self, *, mode='fips-186-3', encoding='binary'):
        """Returns a signer context."""
        return ECCSignerCtx(self._key, mode=mode, encoding=encoding)

    def exchange(self, peer_public_key):
        raise NotImplementedError(
            'key exchange is currently not supported by the backend.')


class ECCPublicKey(_ECCKey):
    def __init__(self, key):
        self._key = key

    def serialize(self, encoding='PEM', *, compress=False):
        """Serialize the public key.

        - `encoding` can be PEM or DER (defaults to PEM).
       """
        return self._key.export_key(
            format=encodings[encoding],
            compress=compress,
        )

    def verifier(self, *, mode='fips-186-3', encoding='binary'):
        """Returns a verifier context using the given 1algorithm`"""
        return ECCVerifierCtx(self._key, mode=mode, encoding=encoding)


class SigVerContext:
    def __init__(self, key, *, mode='fips-186-3', encoding='der'):
        self._sig = DSS.new(
            key,
            mode=_sig_modes[mode],
            encoding=_sig_encodings[encoding],
        )


class ECCSignerCtx(SigVerContext):
    def sign(self, msghash):
        """Return the signature of the message hash.
        
        `mhash` must be an instance of `BaseHash` and must be
        generated with the same backend as of the ECC key.

        Refer to `Hash.new` function's documentation.
        """
        return self._sig.sign(msghash._hasher)


class ECCVerifierCtx(SigVerContext):
    def verify(self, msghash, signature):
        """Verifies the signature of the message hash.

        `mhash` must be an instance of `BaseHash` and must be
        generated with the same backend as of the ECC key.
        Refer to `Hash.new` function's documentation.
 
        `signature` must be a `bytes` or `bytes-like` object.
        """
        # confusingly, PyCryptodome returns False;
        # better raise errors than returning
        self._sig.verify(msghash._hasher, signature)
