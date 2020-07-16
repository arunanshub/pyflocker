# PyFLocker

#### Python Cryptographic (File Locking) Library

# Installation

Use `pip` or `pip3` to install PyFLocker

    pip install pyflocker

or

    pip3 install pyflocker

# Introduction

PyFLocker aims to be your last cryptographic library you will need for both portability and ease of use.
Before you read on, check if you agree to at least one of these points:

-   [PyCryptodome(x)][pycrypto] and [pyca/cryptography][pyca] have **very different** public interfaces,
    which makes remembering all the imports very difficult, and leaves you reading docs under deadline.
-   Although pycryptodome(x) is easy to use, it is not as fast as pyca/cryptography.
-   The interface of pyca/cryptography is very difficult to use, let alone remember the import:
    ```python
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers import Modes
    ...
    from cryptography.hazmat.backends import default_backend
    # and so on...
    ```
-   You wish that only if pyca/cryptography would have been as easy to use as Pycryptodome(x), it would
    have made life more easy.
-   You sometimes think that the file locking script you wrote were faster somehow and played with both
    backends very well, but you weren't sure what to do.
	-   And all the other solutions (and nonsolutions!) on the internet just confuses you more!

Look no more, you have arrived at the right destination!

* * *

PS: At least, those were my points which irritated me when I first used those libraries :)

# Usage Overview

## Not a "Yet Another Cryptographic Library"

PyFLocker provides you a seamless interface to both the backends, and switching is very easy:

```python
from pyflocker.ciphers import AES, Backends
enc = AES.new(True, key, AES.MODE_GCM, nonce, backend=Backends.CRYPTOGRAPHY)
```

Want only a single backend throughout your code?

```python
from pyflocker import set_default_backend, Backends
set_default_backend(Backends.CRYPTODOME)
```

* * *

# Ease of Use

PyFLocker provides reasonable defaults wherever possible:

```python
from pyflocker.ciphers import RSA
priv = RSA.generate(2048)
with open('private_key.pem', 'xb') as f:
    f.write(priv.serialize())
```

Don't believe me, try to do the same operation with [pyca/cryptography][pyca_vs_self],
or just any other initialization.

In short, the interface is very fluid and easy on developer's mind.

* * *

# Writing into file or file like objects

This is often a related problem when it comes to encryption, but think no more!

```python
from pyflocker.ciphers import AES, Backends
# ... (key, nonce) already made
f1 = open('MySecretData.txt', 'rb')
f2 = open('MySecretData.txt.enc', 'xb')
enc = AES.new(True, key, AES.MODE_EAX, nonce,
              backend=Backends.CRYPTOGRAPHY, file=f1)
enc.update_into(f2)
tag = enc.calculate_tag()
```

You can also use `BytesIO` in place of file objects.

## Directly encrypting files

Just want to encrypt your file with AES, and even with various available modes?

```python
from pyflocker.locker import locker
from pyflocker.ciphers import AES

passwd = b'no not this'
locker('./MySuperSecretFile.txt', passwd, aes_mode=AES.MODE_CFB)  # default is AES-GCM-256
# file stored as MySuperSecretFile.txt.pyflk
```

* * *

# Base classes and tools for wrapping more backends

You can even wrap other tools and ciphers, if you are so inclined...

```python
from pyflocker.ciphers import base

@base.cipher
class MyCustomCipher(base.Cipher):
    def update(self, data):
        ...
    
    def update_into(self):
        ...
 
    def authenticate(self, data):
        ...
 
    def calculate_tag(self, data):
        ...

    def finalize(self):
        ...
    
    @base.finalizer(allow=True)
    def my_other_finalizer(self):
        ...
```

# License

[MIT](https://choosealicense.com/licenses/mit/)

[pycrypto]: <https://github.com/Legrandin/pycryptodome>

[pyca]: <https://github.com/pyca/cryptography>

[pyca_vs_self]: <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/?highlight=RSA#key-serialization>
