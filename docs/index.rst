.. pyflocker documentation master file, created by
   sphinx-quickstart on Sat Jan 23 12:07:58 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to PyFLocker's documentation!
=====================================

Installation
------------

Use ``pip`` or ``pip3`` to install PyFLocker

.. code-block:: bash

    pip install pyflocker

or

.. code-block:: bash

    pip3 install pyflocker


Introduction
------------

PyFLocker aims to be a highly portable and easy of use cryptographic library.
Before you read on, check if you agree to at least one of these points:

- `PyCryptodome(x)`_ and `pyca/cryptography`_ have **very different** public
  interfaces, which makes remembering all the imports very difficult, and leaves
  you reading docs under deadline.

- The interface of pyca/cryptography is very difficult to use, let alone remember
  the import:

  .. code-block:: python

       from cryptography.hazmat.primitives.ciphers.algorithms import AES
       from cryptography.hazmat.primitives.ciphers import Modes
       ...
       from cryptography.hazmat.backends import default_backend
       # and so on...

- You wish that only if pyca/cryptography would have been as easy to use as
  Pycryptodome(x), it would have made life more easy.

- You sometimes think that the file locking script you wrote were faster somehow
  and played with both backends very well, but you weren't sure what to do.

  - And all the other solutions (and nonsolutions!) on the internet just confuses
    you more!

PyFLocker uses well established libraries as its backends and expands upon them.
This gives you the ultimate ability to cherry-pick the primitives from a specific
backend without having to worry about backend itself, as PyFLocker handles it
for you.

Features
--------

Not a "Yet Another Cryptographic Library"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PyFLocker provides you a seamless interface to both the backends, and switching
is very easy:

.. code-block:: python

    import os
    from pyflocker.ciphers import AES, RSA, ECC
    from pyflocker.ciphers.backends import Backends

    key, nonce = os.urandom(32), os.urandom(16)

    # Multiple backends - same API
    enc = AES.new(True, key, AES.MODE_EAX, nonce, backend=Backends.CRYPTOGRAPHY)
    rpriv = RSA.new(2048, backend=Backends.CRYPTODOME)
    epriv = ECC.new("x25519", backend=Backend.CRYPTOGRAPHY)

Backend loading is done internally, and if a backend is explicitly specified,
that is used as the default.

Ease of Use
~~~~~~~~~~~

PyFLocker provides reasonable defaults wherever possible:

.. code-block:: python

    from pyflocker.ciphers import RSA
    priv = RSA.generate(2048)
    with open("private_key.pem", "xb") as f:
        key = priv.serialize(password=b"random-chimp-event")
        f.write(key)

Don't believe me, try to do the `same operation with pyca/cryptography`__,
or just any other initialization.

__ https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html#key-serialization

In short, the API is very stable, clear and easy on developer's mind.

Writing into file or file like objects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is often a related problem when it comes to encryption, but think no more!

.. code-block:: python

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

You can also use ``BytesIO`` in place of file objects.

Directly encrypting files
+++++++++++++++++++++++++

Just want to encrypt your file with AES, and even with various available modes?

.. code-block:: python

    from pyflocker.locker import locker
    from pyflocker.ciphers import AES

    password = b"no not this"
    locker(
        "./MySuperSecretFile.txt",
        password,
        aes_mode=AES.MODE_CTR,  # default is AES-GCM-256
    )
    # file stored as MySuperSecretFile.txt.pyflk


.. _`PyCryptodome(x)`: https://github.com/Legrandin/pycryptodome
.. _`pyca/cryptography`: https://github.com/pyca/cryptography


.. toctree::
   :maxdepth: 4
   :caption: Contents:

   pyflocker
   examples

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
