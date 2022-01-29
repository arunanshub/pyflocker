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
    KangarooTwelve,
    cSHAKE128,
    cSHAKE256,
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
        # Blakes
        "blake2b": BLAKE2b.new,
        "blake2s": BLAKE2s.new,
        # XOFS
        "shake128": SHAKE128.new,
        "shake256": SHAKE256.new,
        "cshake128": cSHAKE128.new,
        "cshake256": cSHAKE256.new,
        "kangarootwelve": KangarooTwelve.new,
    }
)

#: Names of hash functions that support variable digest sizes.
VAR_DIGEST_SIZE = frozenset(
    {
        "blake2b",
        "blake2s",
        "shake128",
        "shake256",
        "cshake128",
        "cshake256",
        "kangarootwelve",
    }
)

#: Names of extendable-output functions.
XOFS = frozenset(
    {
        "shake128",
        "shake256",
        "cshake128",
        "cshake256",
        "kangarootwelve",
    }
)

#: Names of extendable-output functions that support customization string.
XOFS_WITH_CUSTOM = frozenset(
    {
        "cshake128",
        "cshake256",
        "kangarootwelve",
    }
)


class Hash(base.BaseHash):
    __slots__ = (
        "_name",
        "_digest",
        "_ctx",
        "_digest_size",
        "_block_size",
        "_oid",
    )

    def __init__(
        self,
        name: str,
        data: bytes = b"",
        digest_size: typing.Optional[int] = None,
        *,
        custom: typing.Optional[bytes] = None,  # cshakes, kangarootwelve
        key: typing.Optional[bytes] = None,  # for blakes
        _copy: typing.Any = None,
    ):
        if _copy is not None:
            self._ctx = _copy
        else:
            self._ctx = self._create_ctx(
                name,
                data,
                digest_size,
                custom=custom,
                key=key,
            )

        self._name = name
        self._digest_size = getattr(self._ctx, "digest_size", digest_size)
        self._block_size = getattr(self._ctx, "block_size", NotImplemented)
        self._oid = getattr(self._ctx, "oid", NotImplemented)

    @property
    def digest_size(self):
        return self._digest_size

    @property
    def block_size(self):
        return self._block_size

    @property
    def name(self):
        return self._name

    @property
    def oid(self) -> str:
        """The ASN.1 Object ID."""
        if self._oid is NotImplemented:
            raise ValueError(f"OID not available for {self.name!r}")
        return self._oid  # type: ignore

    def update(self, data: bytes):
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._ctx.update(data)

    def digest(self):
        if self._ctx is None:
            return self._digest
        ctx, self._ctx = self._ctx, None

        if self.name in XOFS:
            digest = ctx.read(self.digest_size)  # type: ignore
        else:
            digest = ctx.digest()  # type: ignore

        self._digest = digest
        return digest

    def copy(self):
        if self._ctx is None:
            raise exc.AlreadyFinalized

        try:
            hashobj = self._ctx.copy()  # type: ignore
        except AttributeError as e:
            raise ValueError(f"copying not supported by {self.name!r}") from e

        return type(self)(
            self.name,
            digest_size=self.digest_size,
            _copy=hashobj,
        )

    def new(
        self,
        data: bytes = b"",
        digest_size: typing.Optional[int] = None,
        *,
        custom: typing.Optional[bytes] = None,
        key: typing.Optional[bytes] = None,
    ) -> "Hash":
        return type(self)(
            self.name,
            data,
            digest_size=digest_size,
            custom=custom,
            key=key,
        )

    @staticmethod
    def _create_ctx(
        name: str,
        data: typing.Optional[bytes] = None,
        digest_size: typing.Optional[int] = None,
        *,
        custom: typing.Optional[bytes] = None,  # cshakes, kangarootwelve
        key: typing.Optional[bytes] = None,  # for blakes
    ):
        """
        Creates a Cryptodome based hash function object.
        """
        hashfunc = HASHES[name]
        if name in VAR_DIGEST_SIZE:
            if digest_size is None:
                raise ValueError("digest_size is required")
            if name in XOFS:
                if name in XOFS_WITH_CUSTOM:
                    hashobj = hashfunc(data, custom)  # type: ignore
                else:
                    hashobj = hashfunc(data)  # type: ignore
            # BLAKE2b, BLAKE2s...
            else:
                kwargs = dict(key=key) if key is not None else {}
                hashobj = hashfunc(
                    data=data,  # type: ignore
                    digest_bytes=digest_size,  # type: ignore
                    **kwargs,
                )
        else:
            hashobj = hashfunc(data)  # type: ignore

        return hashobj


def algorithms_available() -> typing.Set[str]:
    """Return the names of the available hash algorithms.

    Returns:
        Names of hash algorithms.
    """
    return set(HASHES)


def new(
    name: str,
    data: bytes = b"",
    digest_size: typing.Optional[int] = None,
    *,
    custom: typing.Optional[bytes] = None,  # cshakes, kangarootwelve
    key: typing.Optional[bytes] = None,  # for blakes
) -> Hash:
    """
    Instantiate a hash object.

    Args:
        name: The name of the hash function.
        data: The initial chunk of message to feed to hash.
        digest_size:
            The length of the digest size. Must be supplied if the hash
            function supports it.

    Keyword Args:
        custom:
            A customization string. Can be supplied for hash functions
            that support domain separation.
        key:
            A key that is used to compute the MAC. Can be supplied for hash
            functions that support working as cryptographic MAC.

    Raises:
        KeyError: If ``name`` is not a hash function name.
        ValueError: If ``digest_size`` is required but not provided.
    """

    return Hash(name, data, digest_size=digest_size, custom=custom, key=key)
