"""The `ciphers` package
This package provides:

    - wrappers for cryptographic primitives to add support for
      encrypting/decrypting files and file streams
    - base classes to implement new wrappers
      (available in `pyflocker.ciphers.base`)


The Design Principle
~~~~~~~~~~~~~~~~~~~~

This package was designed with the prime idea that the ciphers' interfaces
and their backend specific implementation counterpart must be kept separate,
hence this package is divided into two main parts:

    - `ciphers.interfaces` : to provide the frontend to the implemented 
                             ciphers.
    - `ciphers.backends` : to provide the implementation counterparts of
                           ciphers.


The Backend's Organization
~~~~~~~~~~~~~~~~~~~~~~~~~~

The backend has been designed in such a way that each cipher is kept separate
in its own module, and each backend has its own separate package.
For example, the AES cipher implemented with Crypto(dome) is kept in
`backends.cryptodome_.AES`.

Read their documentation to learn more.
"""


from .backends import load_cipher, Backends

# load interfaces
from .interfaces import AES, Camellia
