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

hashes.update(_arbitrary_digest_size_hashes)


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

    @base.before_finalized
    def update(self, data):
        self._hasher.update(data)

    @base.finalizer(allow=True)
    def digest(self):
        if self._digest is None:
            self._digest = self._hasher.finalize()
        return self._digest
