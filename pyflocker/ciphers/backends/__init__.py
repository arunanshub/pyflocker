"""Backend of `pyflocker`."""

from enum import Enum
from importlib import import_module

from .. import base, exc


class Backends(Enum):
    """Contains all the backend names supported by `pyflocker`.
    """
    CRYPTODOME = ".cryptodome_"
    CRYPTOGRAPHY = ".cryptography_"
    # Crypto is Cryptodome (for ver. >= 3)
    CRYPTO = CRYPTODOME


def load_backend(bknd=None):
    """Loads backend.
    Backend must be an attribute of `Backends`.
    If `None` is supplied, loads whichever backenf is available.
    If both are available, loads `Cryptodome`.
    """
    if bknd is not None:
        if bknd not in list(Backends):
            raise NotImplementedError
        return import_module(bknd.value,
            __package__)

    # try to find backend automatically
    try:
        try:
            return import_module(
                Backends.CRYPTODOME.value,
                __package__)
        except ModuleNotFoundError:
            return import_module(
                Backends.CRYPTOGRAPHY.value,
                __package__)
    except ModuleNotFoundError:
        raise ModuleNotFoundError("no backends found") from None

