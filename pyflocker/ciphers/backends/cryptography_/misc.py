"""
Miscellaneous Tools: Tools that are not common to symmetric or asymmetric.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as algo
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ...base import BaseHash
from .Hash import _get_hash_algorithm


def derive_hkdf_key(
    master_key: bytes,
    dklen: int,
    hashalgo: BaseHash,
    salt: bytes,
    cipher_ctx: bytes = b"enc-key",
    auth_ctx: bytes = b"auth-key",
) -> tuple[bytes, bytes]:
    """Derive key materials for HMAC from given master key.

    Args:
        master_key: The key used to derive the keys from.
        dklen: Desired lenth of the derived key.
        hashalgo: The name of the hash algorithm.
        salt: The salt to use.
        cipher_ctx: Context for cipher.
        auth_ctx: Context for HMAC.

    Returns:
        A pair of *cipher key* and *MAC key*.
    """
    if not isinstance(hashalgo, BaseHash):
        raise TypeError("hashalgo must be an object implementing BaseHash")

    hash_ = _get_hash_algorithm(hashalgo)
    key = HKDF(hash_, dklen, salt, cipher_ctx).derive(master_key)
    hkey = HKDF(hash_, hash_.digest_size, salt, auth_ctx).derive(master_key)
    return key, hkey


def derive_poly1305_key(ckey: bytes, nonce: bytes) -> bytes:
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

    crp = Cipher(algo.ChaCha20(ckey, bytes(4) + nonce), None).encryptor()
    return crp.update(bytes(32))
