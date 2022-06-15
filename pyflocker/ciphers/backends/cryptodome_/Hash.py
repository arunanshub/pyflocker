from __future__ import annotations

import typing

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
    TupleHash128,
    TupleHash256,
    cSHAKE128,
    cSHAKE256,
)

from ... import base, exc

HASHES = {
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
    # TupleHashes: similar to Blakes' API
    "tuplehash128": TupleHash128.new,
    "tuplehash256": TupleHash256.new,
    # XOFS
    "shake128": SHAKE128.new,
    "shake256": SHAKE256.new,
    "cshake128": cSHAKE128.new,
    "cshake256": cSHAKE256.new,
    "kangarootwelve": KangarooTwelve.new,
}


# Names of hash functions that support variable digest sizes.
VAR_DIGEST_SIZE = frozenset(
    {
        "blake2b",
        "blake2s",
        "shake128",
        "shake256",
        "cshake128",
        "cshake256",
        "kangarootwelve",
        "tuplehash128",
        "tuplehash256",
    }
)

# Names of extendable-output functions. This is only for separation of APIs.
# Cryptodome uses `read(int)` for XOFs and the usual `digest()` for other
# hashes.
XOFS = frozenset(
    {
        "shake128",
        "shake256",
        "cshake128",
        "cshake256",
        "kangarootwelve",
    }
)

# Names of hash functions that support customization string. Basically it means
# we get the `custom=...` param.
SUPPORTS_CUSTOM = frozenset(
    {
        "cshake128",
        "cshake256",
        "kangarootwelve",
        "tuplehash128",
        "tuplehash256",
    }
)


# Names of hash functions that support key. This essentially turns them into a
# MAC. Here it is used as a way to separate the API.
SUPPORTS_KEY = frozenset(
    {
        "blake2b",
        "blake2s",
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
        data: bytes | None = None,
        digest_size: int | None = None,
        *,
        custom: bytes | None = None,  # cshakes, kangarootwelve
        key: bytes | None = None,  # for blakes
        _copy: typing.Any = None,
    ) -> None:
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
        self._digest = b""

    @property
    def digest_size(self) -> int:
        return self._digest_size  # type: ignore

    @property
    def block_size(self) -> int:
        return self._block_size

    @property
    def name(self) -> str:
        return self._name

    def update(self, data: bytes) -> None:
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._ctx.update(data)

    def digest(self) -> bytes:
        if self._ctx is None:
            return self._digest
        ctx, self._ctx = self._ctx, None

        if self.name in XOFS:
            digest = ctx.read(self.digest_size)
        else:
            digest = ctx.digest()

        self._digest = digest
        return digest

    def copy(self) -> Hash:
        if self._ctx is None:
            raise exc.AlreadyFinalized

        try:
            hashobj = self._ctx.copy()
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
        digest_size: int | None = None,
        *,
        custom: bytes | None = None,
        key: bytes | None = None,
    ) -> Hash:
        return type(self)(
            self.name,
            data,
            digest_size=self.digest_size
            if digest_size is None
            else digest_size,
            custom=custom,
            key=key,
        )

    @staticmethod
    def _create_ctx(
        name: str,
        data: bytes | None = None,
        digest_size: int | None = None,
        *,
        custom: bytes | None = None,  # cshakes, kangarootwelve
        key: bytes | None = None,  # for blakes
    ) -> typing.Any:
        """
        Creates a Cryptodome based hash function object.
        """
        hashfunc = HASHES[name]

        digest_size_kwargs = {}
        if name in VAR_DIGEST_SIZE:
            if digest_size is None:
                raise ValueError("digest_size is required")
            # XOFs have the `read()` API, which is frustrating!
            if name not in XOFS:
                digest_size_kwargs = {"digest_bytes": digest_size}

        custom_kwargs = {}
        if name in SUPPORTS_CUSTOM and custom is not None:
            custom_kwargs = {"custom": custom}

        key_kwargs = {}
        if name in SUPPORTS_KEY and key is not None:
            key_kwargs = {"key": key}

        hashobj = hashfunc(  # type: ignore
            **digest_size_kwargs,
            **custom_kwargs,
            **key_kwargs,
        )

        # `tuplehash*`'s internal hash state can change even if empty byte
        # string is fed. `None` is a protection against that.
        if data is not None:
            hashobj.update(data)

        return hashobj


def algorithms_available() -> set[str]:
    """Return the names of the available hash algorithms.

    Returns:
        Names of hash algorithms.
    """
    return set(HASHES)


def new(
    name: str,
    data: bytes | None = b"",
    digest_size: int | None = None,
    *,
    custom: bytes | None = None,  # cshakes, kangarootwelve
    key: bytes | None = None,  # for blakes
) -> Hash:
    """
    Instantiate a hash object.

    Args:
        name: The name of the hash function.
        data:
            The initial chunk of message to feed to hash. Note that for
            ``TupleHash`` variants, even an empty byte string changes its
            internal state.
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
