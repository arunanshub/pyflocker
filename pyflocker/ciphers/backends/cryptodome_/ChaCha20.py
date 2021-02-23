import typing

from Cryptodome.Cipher import ChaCha20 as _ChaCha20
from Cryptodome.Cipher import ChaCha20_Poly1305 as _ChaCha20_Poly1305

from ..symmetric import FileCipherWrapper
from .symmetric import AEADCipherTemplate, NonAEADCipherTemplate


class ChaCha20(NonAEADCipherTemplate):
    """ChaCha20 Cipher class.

    This class alone does not provide any authentication. For AEAD purposes,
    wrap `ChaCha20` object with a class that implements `BaseAEADCipher` or
    use `ChaCha20Poly1305`.
    """

    def __init__(self, encrypting, key, nonce):
        self._cipher = _ChaCha20.new(key=key, nonce=nonce)
        self._encrypting = encrypting
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )


class ChaCha20Poly1305(AEADCipherTemplate):
    """ChaCha20Poly1305 Cipher class."""

    def __init__(self, encrypting, key, nonce):
        self._cipher = _ChaCha20_Poly1305.new(key=key, nonce=nonce)
        self._encrypting = encrypting
        self._update_func = (
            self._cipher.encrypt if encrypting else self._cipher.decrypt
        )
        self._updated = False


def new(
    encrypting: bool,
    key: typing.ByteString,
    nonce: typing.ByteString,
    *,
    use_poly1305: bool = True,
    file: typing.Optional[typing.BinaryIO] = None,
) -> typing.Union[ChaCha20, ChaCha20Poly1305, FileCipherWrapper]:
    """Instantiate a new ChaCha20-Poly1305 cipher wrapper object.

    Args:
        encrypting (bool):
            True is encryption and False is decryption.
        key (bytes, bytearray, memoryview):
            The key for the cipher.
        nonce (bytes, bytearray, memoryview):
            The Nonce for the cipher.
            It must not be repeated with the same key.

    Keyword Arguments:
        use_poly1305 (bool): Whether to use Poly1305 MAC with ChaCha20 cipher.
        file (filelike): The source file to read from.

    Returns:
        Union[ChaCha20, ChaCha20Poly1305, FileCipherWrapper]:
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
