"""The `ciphers` package

Parts of the package
~~~~~~~~~~~~~~~~~~~~

- interfaces : Provides seamless interface to various ciphers
               implemented (and supported) by backend.

- modes : Contains the modes that are supported by the
          ciphers (in `Modes` class). Additionally, the
          modes are categorized according to their type.

- backends : Provides the implementation counterpart of ciphers.
             Each backend has its own package.

- base : Base class and utility tools to wrap new ciphers.

- exc : Exceptions raised by `pyflocker`.
"""

# import the modes class
from .modes import Modes, aead, special

# import loader and backend class
from .backends import load_cipher, Backends

# import interfaces
from .interfaces import AES, Camellia, ChaCha20, RSA
from .interfaces import Hash, DH, ECC

# other imports which have specific interface
from .backends._asymmetric import OAEP, PSS, MGF1
