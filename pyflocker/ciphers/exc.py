"""Exceptions raised by the ciphers are defined here."""


class DecryptionError(Exception):
    """
    Can be raised in two cases:

    - AEAD ciphers failed to verify the decryption.
    - Asymmetric ciphers (RSA) failed to decrypt the data.
    """


class SignatureError(Exception):
    """Raised when the signature is invalid."""


class FinalizationError(Exception):
    """
    Base exception class for all finalization and context
    destruction related errors.
    """


class UnsupportedAlgorithm(Exception):
    """Raised if the backend does not support the algorithm."""


class AlreadyFinalized(FinalizationError):
    """The context was already destroyed."""


class NotFinalized(FinalizationError):
    """The context has not been destroyed yet."""


NotYetFinalized = NotFinalized
