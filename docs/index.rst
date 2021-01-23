.. pyflocker documentation master file, created by
   sphinx-quickstart on Sat Jan 23 12:07:58 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to pyflocker's documentation!
=====================================

Installation
++++++++++++

Use ``pip`` or ``pip3`` to install PyFLocker

.. code-block:: bash

    pip install pyflocker

or

.. code-block:: bash

    pip3 install pyflocker


Introduction
++++++++++++

PyFLocker aims to be a highly portable and easy of use cryptographic library.
Before you read on, check if you agree to at least one of these points:

- `PyCryptodome(x)`_ and `pyca/cryptography`_ have **very different** public interfaces,
  which makes remembering all the imports very difficult, and leaves you reading docs under deadline.
- Although pycryptodome(x) is easy to use, it is not as fast as pyca/cryptography.
- The interface of pyca/cryptography is very difficult to use, let alone remember the import:

  .. code-block:: python

       from cryptography.hazmat.primitives.ciphers.algorithms import AES
       from cryptography.hazmat.primitives.ciphers import Modes
       ...
       from cryptography.hazmat.backends import default_backend
       # and so on...

- You wish that only if pyca/cryptography would have been as easy to use as Pycryptodome(x), it would
  have made life more easy.
- You sometimes think that the file locking script you wrote were faster somehow and played with both
  backends very well, but you weren't sure what to do.

  - And all the other solutions (and nonsolutions!) on the internet just confuses you more!

Look no more, you have arrived at the right destination!

-------

PS: At least, those were my points which irritated me when I first used those libraries :)

Usage Overview
++++++++++++++

How is it different?
--------------------

``PyFLocker`` takes a very different approach. Instead of writing the cryptographic
primitives from scratch, ``PyFLocker`` uses well established libraries as its
backends and expands upon them.

This gives you the ultimate ability to cherry-pick the primitives from a specific
backend without having to worry about backend's interface, as ``PyFLocker`` handles
it for you. And you, as a developer, have to focus on a single API, and the rest
is handled internally.

Read on to know more!

-------

Not a "Yet Another Cryptographic Library"
-----------------------------------------

PyFLocker provides you a seamless interface to both the backends, and switching is very easy:

.. code-block:: python

    from pyflocker.ciphers import AES, Backends
    enc = AES.new(True, key, AES.MODE_GCM, nonce, backend=Backends.CRYPTOGRAPHY)

Want only a single backend throughout your code?

.. code-block:: python

    from pyflocker import set_default_backend, Backends
    set_default_backend(Backends.CRYPTODOME)


-------

Ease of Use
-----------

PyFLocker provides reasonable defaults wherever possible:

.. code-block:: python

    from pyflocker.ciphers import RSA
    priv = RSA.generate(2048)
    with open('private_key.pem', 'xb') as f:
        f.write(priv.serialize())

Don't believe me, try to do the `same operation with pyca/cryptography`__,
or just any other initialization.

__ https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html#key-serialization

In short, the interface is very fluid and easy on developer's mind.

-------

Writing into file or file like objects
--------------------------------------

This is often a related problem when it comes to encryption, but think no more!

.. code-block:: python

    from pyflocker.ciphers import AES, Backends
    # ... (key, nonce) already made
    f1 = open('MySecretData.txt', 'rb')
    f2 = open('MySecretData.txt.enc', 'xb')
    enc = AES.new(True, key, AES.MODE_EAX, nonce,
        backend=Backends.CRYPTOGRAPHY, file=f1)
    enc.update_into(f2)
    tag = enc.calculate_tag()

You can also use ``BytesIO`` in place of file objects.

Directly encrypting files
~~~~~~~~~~~~~~~~~~~~~~~~~

Just want to encrypt your file with AES, and even with various available modes?

.. code-block:: python

    from pyflocker.locker import locker
    from pyflocker.ciphers import AES

    passwd = b'no not this'
    locker('./MySuperSecretFile.txt', passwd, aes_mode=AES.MODE_CFB)  # default is AES-GCM-256
    # file stored as MySuperSecretFile.txt.pyflk


.. _`PyCryptodome(x)`: https://github.com/Legrandin/pycryptodome
.. _`pyca/cryptography`: https://github.com/pyca/cryptography


.. toctree::
   :maxdepth: 4
   :caption: Contents:

   pyflocker


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
