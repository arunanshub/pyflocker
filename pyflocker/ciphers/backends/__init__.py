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
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use. It must be an attribute of :any:`Backends`.

    Returns:
        None

    Raises:
        TypeError: if the backend is not recognized or is invalid.
    """
    if not isinstance(backend, Backends):
        raise TypeError(f"invalid backend type: {backend}")
    global _default_backend
    _default_backend = backend


def load_algorithm(name, backend=None):
    """Loads the algorithm module from backend.
    Generally used by interfaces to load the implemented counterpart.

    Args:
        name (str):
            Name of the cipher module to load.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to fetch the cipher from. If backend is None,
            any available backend will be used.

    Returns:
        module: The algorithm module from the backend.

    Raises:
        UnsupportedAlgorithm: If the algorithm is not supported by backend.
    """
    bknd = load_backend(backend)
    try:
        return import_module(f".{name}", bknd.__package__)
    except ModuleNotFoundError as e:
        raise exc.UnsupportedAlgorithm(
            f"{name} unsupported by backend "
            f"{bknd.BACKEND_NAME.name.title()}."
        ) from e


def load_backend(bknd=None):
    """Loads backend package.
    Backend must be an attribute of `Backends`.
    If `None` is supplied, loads whichever backend is available.
    If both are available, loads `Cryptodome`.

    Args:
        bknd (:class:`pyflocker.ciphers.backends.Backends`):
            The name of the backend to load. If `bknd` is None and
            the default backend is set via :func:`set_default_backend`,
            that is loaded instead, and if default backend was not
            set, any available backend is loaded.

    Raises:
        NotImplementedError:
            If the backend is invalid or unsupported.
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
            "Pyflocker needs atleast one backend among "
            ", ".join(each.name.capitalize() for each in failed)
            + " but none were found",  # noqa: W503
        )
