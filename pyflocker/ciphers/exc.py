"""Exceptions raised by the ciphers are defined here."""


class DecryptionError(Exception):
    pass


class SignatureError(Exception):
    pass


class FinalizationError(Exception):
    pass


class AlreadyFinalized(FinalizationError):
    pass


class NotFinalized(FinalizationError):
    pass
