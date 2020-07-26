"""Backend of `pyflocker`."""

from enum import Enum
from importlib import import_module

from .. import base, exc, Modes

_default_backend = None


class Backends(Enum):
    """Contains all the backend names supported by `pyflocker`."""
    CRYPTODOME = ".cryptodome_"
    CRYPTOGRAPHY = ".cryptography_"
    # Crypto is Cryptodome (for ver. >= 3)
    CRYPTO = CRYPTODOME


def set_default_backend(backend):
    """Set global backend for all pyflocker.

    Please note that if the backend is not found, then the
    global backend will have no effect, and other backends
    will be searched instead.

    Args:
        backend:
            The backend to use. It must be an attribute of
            `Backends`.

    Returns:
        None

    Raises:
        `TypeError` if the backend is not recognized or is invalid.
    """
    if not isinstance(backend, Backends):
        raise TypeError(f"invalid backend type: {backend}")
    global _default_backend
    _default_backend = backend


def load_cipher(name, bknd=None):
    """Loads the cipher module from backend.
    Generally used by interfaces to load the implemented cipher's
    counterpart.

    Args:
        name:
            Name of the cipher module to load.
        bknd:
            The backend to fetch the cipher from. If backend is None,
            any available backend will be used.

    Returns:
        The cipher module from the backend.

    Raises:
        NotImplementedError: If the cipher is not supported by backend.
    """
    bknd = load_backend(bknd)
    try:
        return import_module(f".{name}", bknd.__package__)
    except ModuleNotFoundError:
        raise NotImplementedError(f"cipher {name} unsupported by this backend")


def load_backend(bknd=None):
    """Loads backend package.
    Backend must be an attribute of `Backends`.
    If `None` is supplied, loads whichever backend is available.
    If both are available, loads `Cryptodome`.

    Args:
        bknd:
            The name of the backend to load. If `bknd` is None and
            the default backend is set via `set_default_backend`,
            that is loaded instead, and if default backend was not
            set, any available backend is loaded.

    Raises:
        NotImplementedError:
            If the backend is invalid.
        ModuleNotFoundError:
            if no backends are available if bknd is None or the given
            backend is not supported.
    """
    if bknd is not None:
        if bknd not in list(Backends):
            raise NotImplementedError(f"The backend {bknd} is not supported.")
        return import_module(bknd.value, __package__)

    # only if user has set a global backend
    if _default_backend is not None:
        try:
            return import_module(_default_backend.value, __package__)
        # don't raise error here; fall back to searching other backend
        except ModuleNotFoundError:
            pass

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
