import typing
from types import MappingProxyType

from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives import hashes as h

from ... import base, exc

HASHES = MappingProxyType(
    {
        "sha1": h.SHA1,
        "sha224": h.SHA224,
        "sha256": h.SHA256,
        "sha384": h.SHA384,
        "sha512": h.SHA512,
        "sha3_224": h.SHA3_224,
        "sha3_256": h.SHA3_256,
        "sha3_384": h.SHA3_384,
        "sha3_512": h.SHA3_512,
        "sha512_224": h.SHA512_224,
        "sha512_256": h.SHA512_256,
        "shake128": h.SHAKE128,
        "shake256": h.SHAKE256,
        "blake2b": h.BLAKE2b,
        "blake2s": h.BLAKE2s,
    }
)

VAR_DIGEST_SIZE = frozenset(
    (
        "shake128",
        "shake256",
        "blake2b",
        "blake2s",
    )
)


# the ASN.1 Object IDs
OIDS = MappingProxyType(
    {
        "sha224": "2.16.840.1.101.3.4.2.4",
        "sha256": "2.16.840.1.101.3.4.2.1",
        "sha384": "2.16.840.1.101.3.4.2.2",
        "sha512": "2.16.840.1.101.3.4.2.3",
        "sha512_224": "2.16.840.1.101.3.4.2.5",
        "sha512_256": "2.16.840.1.101.3.4.2.6",
        "sha3_224": "2.16.840.1.101.3.4.2.7",
        "sha3_256": "2.16.840.1.101.3.4.2.8",
        "sha3_384": "2.16.840.1.101.3.4.2.9",
        "sha3_512": "2.16.840.1.101.3.4.2.10",
        "shake128": "2.16.840.1.101.3.4.2.11",
        "shake256": "2.16.840.1.101.3.4.2.12",
    }
)

del MappingProxyType


class Hash(base.BaseHash):
    __slots__ = "_name", "_digest", "_ctx", "_digest_size", "_block_size"

    def __init__(self, name, data=b"", *, digest_size=None):
        self._name = name
        self._digest = None
        self._ctx = self._construct_hash(name, data, digest_size)

        # get values directly from the algorithm object
        algo = self._ctx.algorithm
        self._digest_size = algo.digest_size
        self._block_size = getattr(algo, "block_size", None)

    @staticmethod
    def _construct_hash(name, data=b"", digest_size=None):
        if name in VAR_DIGEST_SIZE:
            if digest_size is None:  # pragma: no cover
                raise ValueError("value of digest-size is required")
            hash_ = h.Hash(HASHES[name](digest_size), defb())
        else:
            hash_ = h.Hash(HASHES[name](), defb())
        hash_.update(data)
        return hash_

    @property
    def digest_size(self):
        return self._digest_size

    @property
    def block_size(self):
        if self._block_size is None:
            return NotImplemented
        return self._block_size

    @property
    def name(self):
        return self._name

    @property
    def oid(self):
        """ASN.1 Object ID of the hash algorithm."""
        if self.name in OIDS:
            return OIDS[self.name]

        # for BLAKE
        if self.name == "blake2b":
            if self.digest_size != 64:
                raise AttributeError(  # pragma: no cover
                    "oid is avaliable only when digest size == 64"
                )
            return "1.3.6.1.4.1.1722.12.2.1." + str(self.digest_size)

        if self.name == "blake2s":
            if self.digest_size != 32:
                raise AttributeError(  # pragma: no cover
                    "oid is avaliable only when digest size == 32"
                )
            return "1.3.6.1.4.1.1722.12.2.2." + str(self.digest_size)

    def update(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._ctx.update(data)

    def copy(self):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        hashobj = type(self)(self.name, digest_size=self.digest_size)
        hashobj._ctx = self._ctx.copy()
        return hashobj

    def digest(self):
        if self._ctx is None:
            return self._digest

        ctx, self._ctx = self._ctx, None
        self._digest = ctx.finalize()
        return self._digest

    def new(self, data=b"", *, digest_size=None):
        """Create a fresh hash object.

        See also:
            :py:func:`new` for more information.
        """
        return type(self)(
            self.name,
            data,
            digest_size=digest_size or self.digest_size,
        )


def algorithms_available() -> typing.Set[str]:
    """Return the names of the available hash algorithms.

    Returns:
        set[str]: Names of hash algorithms.
    """
    return set(HASHES)


def new(
    name: str,
    data: typing.ByteString = b"",
    *,
    digest_size: typing.Optional[int] = None,
) -> Hash:
    """Instantiate an hash object with given parameters.

    Args:
        name (str):
            Name of the hash algorithm. It must be compatible with
            ``hashlib.new``.
        data (bytes, bytearray, memoryview):
            Initial data to pass to the hash algorithm.
        digest_size (int): An integer value.

    Returns:
        Hash: Hash object.
    """

    return Hash(name, data, digest_size=digest_size)


def _get_hash_algorithm(hashfunc):
    """
    Get the cryptography backend specific ``hash algorithm`` object from
    the given hash ``hashfunc``.
    """
    return new(
        hashfunc.name,
        digest_size=hashfunc.digest_size,
    )._ctx.algorithm
