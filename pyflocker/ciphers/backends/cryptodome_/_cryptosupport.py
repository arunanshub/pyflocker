"""Mitigates the Cryptodome/Crypto problem."""

from importlib import import_module as _import


def __getattr__(name):
    try:
        import Cryptodome as Crypto
    except ModuleNotFoundError:
        import Crypto
        if not Crypto.version_info[0] >= 3:
            raise
    return getattr(Crypto, name)
