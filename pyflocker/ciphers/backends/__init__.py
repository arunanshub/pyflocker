"""Backend of `pyflocker`."""

from enum import Enum
from importlib import import_module

from .. import base, exc, Modes


class Backends(Enum):
    """Contains all the backend names supported by `pyflocker`.
    """
    CRYPTODOME = ".cryptodome_"
    CRYPTOGRAPHY = ".cryptography_"
    # Crypto is Cryptodome (for ver. >= 3)
    CRYPTO = CRYPTODOME


def load_cipher(name, bknd=None):
    """Loads the cipher module from backend.
    Generally used by interfaces to load the implemented cipher counterpart.
    """
    bknd = load_backend(bknd)
    try:
        return import_module(f".{name}", bknd.__package__)
    except ModuleNotFoundError:
        raise NotImplementedError(f"cipher {name} unsupported by this backend")


def load_backend(bknd=None):
    """Loads backend package.
    Backend must be an attribute of `Backends`.
    If `None` is supplied, loads whichever backenf is available.
    If both are available, loads `Cryptodome`.

    If no backends are available, `ModuleNotFoundError` is raised.
    """
    if bknd is not None:
        if bknd not in list(Backends):
            raise NotImplementedError
        return import_module(bknd.value, __package__)

    failed = []
    for each in list(Backends):
        try:
            return import_module(each.value, __package__)
        except ModuleNotFoundError:
            failed.append(each)
    if failed == list(Backends):
        raise ModuleNotFoundError(
            "Pyflocker needs atleast one backend among " +
            ", ".join(each.name.capitalize()
                      for each in failed) + " but none were found")
