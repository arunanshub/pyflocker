import cryptography.exceptions as bkx
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend as defb

from ... import base, exc
from .Hash import hashes as _hashes


def derive_key(master_key, dklen, hashalgo, salt):
    """Derive key materials for HMAC from given master key."""
    key = HKDF(
        _hashes[hashalgo](),
        dklen,
        salt,
        b"enc-key",
        defb(),
    ).derive(master_key)

    hash_ = _hashes[hashalgo]()
    hkey = HKDF(
        hash_,
        hash_.digest_size,
        salt,
        b"auth-key",
        defb(),
    ).derive(master_key)
    return key, hkey
