from types import MappingProxyType

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms as algo,
    modes,
)
from cryptography.hazmat.backends import default_backend as defb


from ... import base
from ...modes import Modes as _m
from ..symmetric import HMACWrapper, FileCipherWrapper
from .misc import derive_hkdf_key
from .symmetric import NonAEADCipherTemplate

supported = MappingProxyType(
    {
        _m.MODE_CFB: modes.CFB,
        _m.MODE_CTR: modes.CTR,
        _m.MODE_OFB: modes.OFB,
    }
)

del MappingProxyType


def new(
    encrypting,
    key,
    mode,
    iv_or_nonce,
    *,
    file=None,
    use_hmac=False,
    digestmod="sha256",
):
    if file is not None:
        use_hmac = True

    if use_hmac:
        crp = _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod)
    else:
        crp = Camellia(encrypting, key, mode, iv_or_nonce)

    if file:
        crp = FileCipherWrapper(crp, file)

    return crp


def _wrap_hmac(encrypting, key, mode, iv_or_nonce, digestmod):
    ckey, hkey = derive_hkdf_key(key, len(key), digestmod, iv_or_nonce)
    crp = HMACWrapper(
        Camellia(encrypting, ckey, mode, iv_or_nonce),
        hkey,
        iv_or_nonce,
        digestmod,
    )
    return crp


class Camellia(NonAEADCipherTemplate):
    def __init__(self, encrypting, key, mode, iv_or_nonce):
        cipher = Cipher(
            algo.Camellia(key),
            supported[mode](iv_or_nonce),
            defb(),
        )

        self._ctx = cipher.encryptor() if encrypting else cipher.decryptor()
        self._encrypting = encrypting
