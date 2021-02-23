import typing
from types import MappingProxyType

from Cryptodome.Hash import (
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHAKE128,
    SHAKE256,
    BLAKE2b,
    BLAKE2s,
)

from ... import base, exc

HASHES = MappingProxyType(
    {
        "sha224": SHA224.new,
        "sha256": SHA256.new,
        "sha384": SHA384.new,
        "sha512": SHA512.new,
        "sha512_224": lambda data=b"": SHA512.new(data, "224"),
        "sha512_256": lambda data=b"": SHA512.new(data, "256"),
        "sha3_224": SHA3_224.new,
        "sha3_256": SHA3_256.new,
        "sha3_384": SHA3_384.new,
        "sha3_512": SHA3_512.new,
        "blake2b": BLAKE2b.new,
        "blake2s": BLAKE2s.new,
        "shake128": SHAKE128.new,
        "shake256": SHAKE256.new,
    }
)

VAR_DIGEST_SIZE = frozenset(
    (
        "blake2b",
        "blake2s",
        "shake128",
        "shake256",
    )
)

XOFS = frozenset(
    (
        "shake128",
        "shake256",
    )
)

del MappingProxyType


class Hash(base.BaseHash):
    __slots__ = (
        "_name",
        "_digest",
        "_ctx",
        "_digest_size",
        "_block_size",
        "_oid",
    )

    def __init__(self, name, data=b"", *, digest_size=None):
        self._ctx = self._construct_hash(name, data, digest_size)
        self._name = name

        self._digest_size = (
            getattr(self._ctx, "digest_size", None) or digest_size
        )
        self._block_size = getattr(self._ctx, "block_size", None)
        self._oid = getattr(self._ctx, "oid", None)
        self._digest = None

    @staticmethod
    def _construct_hash(name, data=b"", digest_size=None):
        hash_ = HASHES[name]

        if digest_size is None and name in VAR_DIGEST_SIZE:  # pragma: no cover
            raise ValueError("value of digest-size is required")

        if name in VAR_DIGEST_SIZE ^ XOFS:
            return hash_(data=data, digest_bytes=digest_size)
        return hash_(data)

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
        if self._oid is not None:
            return self._oid

        base_msg = "oid is avaliable only for digest sizes "
        # for BLAKE-2b/2s
        if self.name == "blake2b":  # pragma: no cover
            msg = base_msg + "20, 32, 48 and 64"
        elif self.name == "blake2s":  # pragma: no cover
            msg = base_msg + "16, 20, 28 and 32"
        else:  # pragma: no cover
            msg = f"oid attribute is not available for hash {self.name}"
        raise AttributeError(msg)

    def update(self, data):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._ctx.update(data)

    def copy(self):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        try:
            hash_ = self._ctx.copy()
            hashobj = type(self)(self.name, digest_size=self.digest_size)
            hashobj._ctx = hash_
            return hashobj
        except AttributeError as e:
            raise AttributeError(
                f"Hash {self.name} does not support copying."
            ) from e

    def digest(self):
        if self._ctx is None:
            return self._digest

        ctx, self._ctx = self._ctx, None
        if self.name in XOFS:
            self._digest = ctx.read(self._digest_size)
        else:
            self._digest = ctx.digest()
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
