# PyFLocker

![Upload Python Package](https://github.com/arunanshub/pyflocker/workflows/Upload%20Python%20Package/badge.svg)
![Build](https://github.com/arunanshub/pyflocker/workflows/Build/badge.svg)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Python Versions](https://img.shields.io/pypi/pyversions/PyFLocker?label=Python%20Versions)](https://pypi.org/project/PyFLocker)
[![Documentation Status](https://readthedocs.org/projects/pyflocker/badge/?version=latest)](https://pyflocker.readthedocs.io/en/latest/?badge=latest)

Python Cryptographic (File Locking) Library

> Lock as in Lock and Key.

# Installation

Use `pip` or `pip3` to install PyFLocker

    pip install pyflocker

or

    pip3 install pyflocker

# Introduction

PyFLocker aims to be a highly stable and easy of use cryptographic library.
Before you read on, check if you agree to at least one of these points:

- [`PyCryptodome(x)`][pycrypto] and [`pyca/cryptography`][pyca] have
  **very different** public interfaces, which makes remembering all the imports
  very difficult, and leaves you reading docs under deadline.

- The interface of `pyca/cryptography` is very difficult to use, let alone
  remember the import:

  ```python
  from cryptography.hazmat.primitives.ciphers.algorithms import AES
  from cryptography.hazmat.primitives.ciphers import Modes
  ...
  from cryptography.hazmat.backends import default_backend
  # and so on...
  ```

- You wish that only if `pyca/cryptography` would have been as easy to use as
  `Pycryptodome(x)`, it would have made life more easy.

- You sometimes think that the file encryption script you wrote were somehow
  faster and played with both backends very well, but you weren't sure what to do.

  - And all the other solutions (and nonsolutions!) on the internet just confuses
    you more!

PyFLocker uses well established libraries as its backends and expands upon them.
This gives you the ultimate ability to cherry-pick the primitives from a specific
backend without having to worry about backend itself, as PyFLocker handles it
for you.

You can find more information in the [documentation][docs].

# Features

## Not a "Yet Another Cryptographic Library"

PyFLocker provides you a seamless interface to both the backends, and switching
is very easy:

```python
import os
from pyflocker.ciphers import AES, RSA, ECC
from pyflocker.ciphers.backends import Backends

key, nonce = os.urandom(32), os.urandom(16)

# Multiple backends - same API
enc = AES.new(True, key, AES.MODE_EAX, nonce, backend=Backends.CRYPTOGRAPHY)
rpriv = RSA.new(2048, backend=Backends.CRYPTODOME)
epriv = ECC.new("x25519", backend=Backend.CRYPTOGRAPHY)
```

Backend loading is done internally, and if a backend is explicitly specified,
that is used as the default.

## Ease of Use

PyFLocker provides reasonable defaults wherever possible:

```python
from pyflocker.ciphers import RSA
priv = RSA.generate(2048)
with open("private_key.pem", "xb") as f:
    key = priv.serialize(password=b"random-chimp-event")
    f.write(key)
```

Don't believe me, try to do the [same operation with `pyca/cryptography`][pyca_vs_self],
or just any other initialization.

In short, the API is very stable, clear and easy on developer's mind.

## Writing into file or file-like objects

This is often a related problem when it comes to encryption, but think no more!

```python
import os
from pyflocker.ciphers import AES
from pyflocker.ciphers.backends import Backends

key, nonce = os.urandom(32), os.urandom(16)
f1 = open("MySecretData.txt", "rb")
f2 = open("MySecretData.txt.enc", "xb")
enc = AES.new(
    True,
    key,
    AES.MODE_EAX,
    nonce,
    backend=Backends.CRYPTOGRAPHY,
    file=f1,
)
enc.update_into(f2)
tag = enc.calculate_tag()
```

You can also use `BytesIO` in place of file objects.

### Directly encrypting files

Just want to encrypt your file with AES, and even with various available modes?

```python
from pyflocker.locker import locker
from pyflocker.ciphers import AES

password = b"no not this"
locker(
    "./MySuperSecretFile.txt",
    password,
    aes_mode=AES.MODE_CTR,  # default is AES-GCM-256
)
# file stored as MySuperSecretFile.txt.pyflk
```

Find more examples [here][examples].

# License

[MIT](https://choosealicense.com/licenses/mit/)

[docs]: https://pyflocker.readthedocs.io/en/latest/index.html
[examples]: https://pyflocker.readthedocs.io/en/latest/examples.html
[pycrypto]: https://github.com/Legrandin/pycryptodome
[pyca]: https://github.com/pyca/cryptography
[pyca_vs_self]: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html#key-serialization
