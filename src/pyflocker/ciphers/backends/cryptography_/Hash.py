from __future__ import annotations

import typing
from types import MappingProxyType

from cryptography.hazmat.primitives import hashes

from ... import base, exc

HASHES = MappingProxyType(
    {
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
        "sha3_224": hashes.SHA3_224,
        "sha3_256": hashes.SHA3_256,
        "sha3_384": hashes.SHA3_384,
        "sha3_512": hashes.SHA3_512,
        "sha512_224": hashes.SHA512_224,
        "sha512_256": hashes.SHA512_256,
        "blake2b": hashes.BLAKE2b,
        "blake2s": hashes.BLAKE2s,
        # XOFS
        "shake128": hashes.SHAKE128,
        "shake256": hashes.SHAKE256,
    }
)

# Names of hash functions that support variable digest sizes. They are here
# to distinguish between constructors who need extra param `digest_size`.
VAR_DIGEST_SIZE = frozenset(
    {
        "shake128",
        "shake256",
        "blake2b",
        "blake2s",
    }
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
        "blake2b": "1.3.6.1.4.1.1722.12.2.1.64",
        "blake2s": "1.3.6.1.4.1.1722.12.2.2.32",
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
        *,
        digest_size: int | None = None,
        _copy: hashes.Hash | None = None,
    ) -> None:
        self._ctx: hashes.Hash | None
        self._digest: bytes

        if _copy is not None:
            self._ctx = _copy
        else:
            self._ctx = self._create_ctx(name, data, digest_size=digest_size)

        self._name = name
        self._digest_size = getattr(
            self._ctx.algorithm,
            "digest_size",
            digest_size,
        )
        self._block_size = (
            getattr(
                self._ctx.algorithm,
                "block_size",
                NotImplemented,
            )
            or NotImplemented
        )
        self._oid = OIDS.get(name, NotImplemented)

    @property
    def digest_size(self) -> int:
        return self._digest_size  # type: ignore

    @property
    def block_size(self) -> int:
        return self._block_size

    @property
    def name(self) -> str:
        return self._name

    @property
    def oid(self) -> str:  # pragma: no cover
        """The ASN.1 Object ID."""
        if self._oid is NotImplemented:
            raise AttributeError(f"OID not available for {self.name!r}")

        if self.name in ("blake2b", "blake2s") and self.digest_size not in (
            32,
            64,
        ):
            raise AttributeError(
                f"OID not available for {self.name!r} with digest size"
                f" {self.digest_size}"
            )

        return self._oid

    def update(self, data: bytes) -> None:
        if self._ctx is None:
            raise exc.AlreadyFinalized
        self._ctx.update(data)

    def digest(self) -> bytes:
        if self._ctx is None:
            return self._digest
        ctx, self._ctx = self._ctx, None
        self._digest = ctx.finalize()
        return self._digest

    def copy(self) -> Hash:
        if self._ctx is None:
            raise exc.AlreadyFinalized

        return type(self)(
            self.name,
            digest_size=self.digest_size,
            _copy=self._ctx.copy(),
        )

    def new(
        self,
        data: bytes | None = None,
        *,
        digest_size: int | None = None,
    ) -> Hash:
        return type(self)(
            self.name,
            data,
            digest_size=self.digest_size
            if digest_size is None
            else digest_size,
        )

    @staticmethod
    def _create_ctx(
        name: str,
        data: bytes | None = None,
        *,
        digest_size: int | None = None,
    ) -> hashes.Hash:
        """
        Creates a pyca/cryptography based hash function object.
        """
        hashfunc = HASHES[name]

        digest_size_kwargs = {}
        if name in VAR_DIGEST_SIZE:
            if digest_size is None:
                raise ValueError("digest_size is required")
            digest_size_kwargs = {"digest_size": digest_size}

        hashobj = hashes.Hash(hashfunc(**digest_size_kwargs))

        if data is not None:
            hashobj.update(data)

        return hashobj


def algorithms_available() -> set[str]:
    """Return the names of the available hash algorithms."""
    return set(HASHES)


def new(
    name: str,
    data: bytes = b"",
    *,
    digest_size: int | None = None,
    **kwargs: typing.Any,  # only for compatibility with Cryptodome
) -> Hash:
    """
    Instantiate a hash object.

    Args:
        name: The name of the hash function.
        data: The initial chunk of message to feed to hash.

    Keyword Arguments:
        digest_size:
            The length of the digest size. Must be supplied if the hash
            function supports it.

    Raises:
        KeyError: If ``name`` is not a hash function name.
        ValueError: If ``digest_size`` is required but not provided.
    """
    extra_params = {"custom", "key"}
    for key in extra_params:
        if kwargs.get(key) is None:
            kwargs.pop(key, None)

    # at this point, kwargs should be empty, otherwise we ge `TypeError`
    return Hash(name, data, digest_size=digest_size, **kwargs)


def _get_hash_algorithm(hashfunc: base.BaseHash) -> hashes.HashAlgorithm:
    """
    Get the cryptography backend specific ``hash algorithm`` object from the
    given hash ``hashfunc``.
    """
    return new(  # pragma: no cover
        hashfunc.name,
        digest_size=hashfunc.digest_size,
    )._ctx.algorithm  # type: ignore
