from __future__ import annotations

import typing

from Cryptodome.Cipher import ChaCha20 as _ChaCha20
from Cryptodome.Cipher import ChaCha20_Poly1305 as _ChaCha20_Poly1305

from ..symmetric import FileCipherWrapper
from .symmetric import AEADCipherTemplate, NonAEADCipherTemplate

if typing.TYPE_CHECKING:
    import io


class ChaCha20(NonAEADCipherTemplate):
    """ChaCha20 Cipher class.

    This class alone does not provide any authentication. For AEAD purposes,
    wrap ``ChaCha20`` object with a class that implements ``BaseAEADCipher`` or
    use ``ChaCha20Poly1305``.
    """

    def __init__(self, encrypting: bool, key: bytes, nonce: bytes):
        self._cipher = _ChaCha20.new(key=key, nonce=nonce)
        self._encrypting = encrypting
        self._update_func = (  # type: ignore
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )


class ChaCha20Poly1305(AEADCipherTemplate):
    """ChaCha20Poly1305 Cipher class."""

    def __init__(self, encrypting: bool, key: bytes, nonce: bytes):
        self._cipher = _ChaCha20_Poly1305.new(key=key, nonce=nonce)
        self._encrypting = encrypting
        self._update_func = (  # type: ignore
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )
        self._tag = None
        self._updated = False


def new(
    encrypting: bool,
    key: bytes,
    nonce: bytes,
    *,
    use_poly1305: bool = True,
    file: io.BufferedIOBase | None = None,
) -> ChaCha20 | ChaCha20Poly1305 | FileCipherWrapper:
    """Instantiate a new ChaCha20-Poly1305 cipher wrapper object.

    Args:
        encrypting: True is encryption and False is decryption.
        key: The key for the cipher.
        nonce:
            The Nonce for the cipher. It must not be repeated with the same
            key.

    Keyword Arguments:
        use_poly1305: Whether to use Poly1305 MAC with ChaCha20 cipher.
        file: The source file to read from.

    Returns:
        ChaCha20(-Poly1305) cipher wrapper object.

    Note:
        Any other error that is raised is from the backend itself.
    """
    crp: typing.Any

    if file is not None:
        use_poly1305 = True

    if use_poly1305:
        crp = ChaCha20Poly1305(encrypting, key, nonce)
    else:
        crp = ChaCha20(encrypting, key, nonce)

    if file:
        crp = FileCipherWrapper(crp, file)

    return crp
