"""PyFLocker
Wrappers for cryptographic primitives to add support for encrypting
files and file streams.

PyFlocker supports `Cryptodome` and `cryptography` as
its underlying backend.


Parts of PyFLocker
~~~~~~~~~~~~~~~~~~

At large, PyFLocker is divided into two parts:
    - `pyflocker.ciphers`
    - `pyflocker.locker`

Read the documentation of these modules to know more.
"""

from . import ciphers

from .ciphers import Backends, base, exc


__version__ = '0.2.1'

version_info = (0, 2, 1)

