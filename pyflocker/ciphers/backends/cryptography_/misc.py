"""
Miscellaneous Tools: Tools that are not common to symmetric or asymmetric.
"""

import typing

from cryptography.hazmat.backends import default_backend as defb
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as algo
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ...base import BaseHash
from .Hash import HASHES as _hashes
from .Hash import _get_hash_algorithm


def derive_hkdf_key(
    master_key: typing.ByteString,
    dklen: int,
    hashalgo: typing.Union[str, BaseHash],
    salt: typing.ByteString,
    cipher_ctx: typing.ByteString = b"enc-key",
    auth_ctx: typing.ByteString = b"auth-key",
) -> typing.Tuple[bytes, bytes]:
    """Derive key materials for HMAC from given master key.

    Args:
        master_key (bytes): The key used to derive the keys from.
        dklen (int): Desired lenth of the derived key.
        hashalgo (str, BaseHash): The name of the hash algorithm.
        salt (bytes): The salt to use.
        cipher_ctx (bytes): Context for cipher.
        auth_ctx (bytes): Context for HMAC.

    Returns:
        tuple[bytes, bytes]: A pair of *cipher key* and *MAC key*.
    """
    if isinstance(hashalgo, str):
        hash_ = _hashes[hashalgo]()
    elif isinstance(hashalgo, BaseHash):
        hash_ = _get_hash_algorithm(hashalgo)
    else:
        raise TypeError(
            "hashalgo must be a str or an object implementing BaseHash."
        )

    key = HKDF(
        hash_,
        dklen,
        salt,
        cipher_ctx,
        defb(),
    ).derive(master_key)

    hkey = HKDF(
        hash_,
        hash_.digest_size,
        salt,
        auth_ctx,
        defb(),
    ).derive(master_key)
    return key, hkey


def derive_poly1305_key(
    ckey: typing.ByteString, nonce: typing.ByteString
) -> bytes:
    """Generate a poly1305 key.

    Args:
        ckey (bytes): The key used for the cipher
        nonce (bytes): The nonce used for the cipher. It must be 12 bytes.

    Returns:
        bytes: A Poly1305 key.

    Raises:
        ValueError: If the length of nonce is not equal to 8 or 12 bytes.
    """
    if len(nonce) not in (8, 12):
        raise ValueError("Poly1305 key must be 16 bytes long.")

    if len(nonce) == 8:
        nonce = bytes(4) + nonce

    crp = Cipher(
        algo.ChaCha20(ckey, bytes(4) + nonce),
        None,
        defb(),
    ).encryptor()
    return crp.update(bytes(32))
