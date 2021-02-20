import enum
import typing
from importlib import import_module

from .. import exc

_DEFAULT_BACKEND = None


class Backends(enum.Enum):
    """The backends of PyFLocker."""

    CRYPTOGRAPHY = "cryptography"
    CRYPTODOME = "cryptodome"


def load_algorithm(
    name: str, backend: typing.Optional[Backends] = None
) -> typing.types.ModuleType:
    """Load a specific algorithm from the given ``backend``.

    Args:
        name (str): The name of the algorithm.
        backend (:class:`Backends`): The backend to use.

    Returns:
        module: Algorithm module from the required backend.

    Raises:
        UnsupportedAlgorithm:
            This is raised if the algorithm is not found in the backend.
    """
    _backend = load_backend(backend)
    try:
        return import_module(f".{name}", _backend.__name__)
    except ImportError as e:
        raise exc.UnsupportedAlgorithm(
            f"{name} is not implemented by backend {backend}."
        ) from e


def load_backend(backend: Backends = None) -> typing.types.ModuleType:
    """Load a backend.

    Args:
        backend (:class:`Backends`): An attribute from :class:`Backends` class.

    Returns:
        module: The backend module.
    """
    # Rules:
    # 1. if default is present and backend is None: return default
    # 2. if backend is given:
    # 2.1. don't set default
    # 2.2. load that particular backend or raise
    # otherwise find a backend or raise
    # once the backend is found, set it as default
    global _DEFAULT_BACKEND

    if backend is None:
        if _DEFAULT_BACKEND is None:
            _DEFAULT_BACKEND = _find_backend()
        return _DEFAULT_BACKEND

    # backend is not None
    if not isinstance(backend, Backends):
        raise TypeError("argument backend must be of type Backends.")

    if _DEFAULT_BACKEND is None:
        _DEFAULT_BACKEND = _import_helper(backend)
        return _DEFAULT_BACKEND

    return _import_helper(backend)


def _import_helper(backend):
    return import_module(f".{backend.name.lower()}_", __spec__.parent)


def _find_backend():
    errors = 0

    for i in list(Backends):
        try:
            return _import_helper(i)
        except ImportError:
            errors += 1

    if errors == len(Backends):
        raise ImportError("No backends found.")
