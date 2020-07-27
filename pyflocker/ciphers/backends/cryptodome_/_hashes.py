try:
    from Cryptodome.Hash import (
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        BLAKE2b,
        BLAKE2s,
        SHAKE128,
        SHAKE256,
    )
except ModuleNotFoundError:
    from Crypto.Hash import (
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        BLAKE2b,
        BLAKE2s,
        SHAKE128,
        SHAKE256,
    )

from .. import base

hashes = {
    'sha224': SHA224.new,
    'sha256': SHA256.new,
    'sha384': SHA384.new,
    'sha512': SHA512.new,
    'sha512_224': lambda data=b'': SHA512.new(data, '224'),
    'sha512_256': lambda data=b'': SHA512.new(data, '256'),
    'sha3_224': SHA3_224.new,
    'sha3_256': SHA3_256.new,
    'sha3_384': SHA3_384.new,
    'sha3_512': SHA3_512.new,
}

_arbitrary_digest_size_hashes = {
    'blake2b': BLAKE2b.new,
    'blake2s': BLAKE2s.new,
    'shake128': SHAKE128.new,
    'shake256': SHAKE256.new,
}

_xofs = {
    'shake128': SHAKE128.new,
    'shake256': SHAKE256.new,
}

hashes.update(_arbitrary_digest_size_hashes)
hashes.update(_xofs)


class Hash(base.BaseHash):
    def __init__(self, name, data=b'', *, digest_size=None):
        self._digest_size = digest_size
        _hash = hashes[name]

        if name in _arbitrary_digest_size_hashes.keys() ^ _xofs.keys():
            if digest_size is None:
                raise ValueError('value of digest-size is required')
            else:
                self._hasher = _hash(data=data, digest_bytes=digest_size)
        else:
            self._hasher = _hash(data)
        self._name = name

    @base.before_finalized
    def update(self, data):
        self._hasher.update(data)

    @base.finalizer(allow=True)
    def digest(self):
        if self._name in _xofs:
            return self._hasher.read(self._digest_size)
        return self._hasher.digest()
