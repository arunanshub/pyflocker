from cryptography.hazmat.primitives import hashes as h
from cryptography.hazmat.backends import default_backend as defb

from .. import base

hashes = {
    'sha1': h.SHA1,
    'sha224': h.SHA224,
    'sha256': h.SHA256,
    'sha384': h.SHA384,
    'sha512': h.SHA512,
    'sha3_224': h.SHA3_224,
    'sha3_256': h.SHA3_256,
    'sha3_384': h.SHA3_384,
    'sha3_512': h.SHA3_512,
    'sha512_224': h.SHA512_224,
    'sha512_256': h.SHA512_256,
}

_arbitrary_digest_size_hashes = {
    'shake128': h.SHAKE128,
    'shake256': h.SHAKE256,
    'blake2b': h.BLAKE2b,
    'blake2s': h.BLAKE2s,
}

_block_sizes = {
    'sha3_224': 114,
    'sha3_256': 136,
    'sha3_384': 104,
    'sha3_512': 72,
    'shake128': 168,
    'shake256': 136,
}

hashes.update(_arbitrary_digest_size_hashes)

# the ASN.1 Object IDs
_oids = {
    'sha224': '2.16.840.1.101.3.4.2.4',
    'sha256': '2.16.840.1.101.3.4.2.1',
    'sha384': '2.16.840.1.101.3.4.2.2',
    'sha512': '2.16.840.1.101.3.4.2.3',
    'sha512_224': '2.16.840.1.101.3.4.2.5',
    'sha512_256': '2.16.840.1.101.3.4.2.6',
    'sha3_224': '2.16.840.1.101.3.4.2.7',
    'sha3_256': '2.16.840.1.101.3.4.2.8',
    'sha3_384': '2.16.840.1.101.3.4.2.9',
    'sha3_512': '2.16.840.1.101.3.4.2.10',
    'shake128': '2.16.840.1.101.3.4.2.11',
    'shake256': '2.16.840.1.101.3.4.2.12',
}


class Hash(base.BaseHash):
    def __init__(self, name, data=b'', *, digest_size=None):
        if name in _arbitrary_digest_size_hashes:
            if digest_size is None:
                raise ValueError('value of digest-size is required')
            self._hasher = h.Hash(hashes[name](digest_size), defb())
        else:
            self._hasher = h.Hash(hashes[name](), defb())
        self._hasher.update(data)
        self._digest = None

        self._name = name

    @property
    def digest_size(self):
        return self._hasher.algorithm.digest_size

    @property
    def block_size(self):
        """Block size of the underlying hash algorithm."""
        try:
            return self._hasher.algorithm.block_size
        except AttributeError:
            try:
                return _block_sizes[self.name]
            except KeyError:
                pass  # raise below
            raise AttributeError(f'Hash algorithm {self.name} does not have '
                                 'block_size parameter.') from None

    @property
    def name(self):
        return self._name

    @property
    def oid(self):
        """ASN.1 Object ID of the hash algorithm."""
        if self.name in _oids:
            return _oids[self.name]

        # for BLAKE
        if self.name == 'blake2b':
            if self.digest_size not in (20, 32, 48, 64):
                raise AttributeError('oid is avaliable only for '
                                     'digest sizes 20, 32, 48 and 64')
            return '1.3.6.1.4.1.1722.12.2.1.' + str(self.digest_size)

        if self.name == 'blake2s':
            if self.digest_size not in (16, 20, 28, 32):
                raise AttributeError('oid is avaliable only for '
                                     'digest sizes 16, 20, 28 and 32')
            return '1.3.6.1.4.1.1722.12.2.2.' + str(self.digest_size)

    @base.before_finalized
    def update(self, data):
        self._hasher.update(data)

    @base.before_finalized
    def copy(self):
        hashobj = Hash(self.name, digest_size=self.digest_size)
        hashobj._hasher = self._hasher.copy()
        return hashobj

    @base.finalizer(allow=True)
    def digest(self):
        if self._digest is None:
            self._digest = self._hasher.finalize()
        return self._digest

    def new(self, data=b'', *, digest_size=None):
        return type(self)(
            self.name,
            data,
            digest_size=digest_size or self.digest_size,
        )
