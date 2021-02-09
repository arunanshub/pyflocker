Examples
========

The following have been adapted from `Pycryptodome's documentation <https://www.pycryptodome.org/en/latest/src/examples.html>`_.

Encrypt data with AES
~~~~~~~~~~~~~~~~~~~~~

The following code generates a new 32 byte key and encrypts a piece of data.
We use the `GCM mode`_ because it allows the receiver to detect any
unauthorized modification (similarly, we could have used other `authenticated
encryption modes`_ like `EAX`_, `CCM`_ or `SIV`_)

.. code-block:: python

    import os
    from pyflocker.ciphers import AES

    data = b"baba booey; fafa fooey; le fishe; monke"
    key, nonce = os.urandom(32), os.urandom(16)
    
    cipher = AES.new(True, key, AES.MODE_GCM, nonce)
    ciphertext = cipher.update(data)
    cipher.finalize()
    tag = cipher.calculate_tag()

    print("Plaintext:", data)
    print("Ciphertext:", ciphertext)
    print("Tag:", tag)

We can also use other symmetric ciphers like `Camellia`_ and `ChaCha20`_.

Encrypt files and file-like objects with symmetric cipher
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code creates a symmetric cipher (here Camellia cipher) and reads
data from a file and writes the encrypted data into another file.

.. code-block:: python

    from pyflocker.ciphers import Camellia
    from pyflocker.ciphers.modes import Modes

    infile = open("somedata.bin", "rb")
    outfile = open("encrypted.bin", "wb")
    key, nonce = os.urandom(32), os.urandom(16)

    cipher = Camellia.new(True, key, Modes.MODE_CTR, nonce, file=infile)
    cipher.update_into(outfile)
    
    print("Tag:", cipher.calculate_tag())

Similarly, we can also use `AES`_ and `ChaCha20`_.

.. important::

    Only those modes that are not defined in ``pyflocker.ciphers.modes.special``
    support file encryption/decryption.

Quick file encryption and decryption
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code demonstrates the use of :any:`pyflocker.locker` for
encrypting and decrypting files

.. code-block:: python

    from pyflocker import locker
    password = b"my-super-secret-password"
    locker.locker("top-secret-file.txt", password)

You can use a different AES mode too.

.. code-block:: python

    from pyflocker import locker
    from pyflocker.ciphers import AES
    password = b"my-super-secret-password"
    locker.locker("top-secret-file.txt", password, aes_mode=AES.MODE_CFB8)

.. important::

    Only those modes that are not defined in ``pyflocker.ciphers.modes.special``
    support file encryption/decryption.

.. _GCM mode: https://en.wikipedia.org/wiki/GCM_mode
.. _CCM: https://en.wikipedia.org/wiki/CCM_mode
.. _EAX: https://en.wikipedia.org/wiki/EAX_mode
.. _SIV: https://tools.ietf.org/html/rfc5297
.. .. _scrypt: http://it.wikipedia.org/wiki/Scrypt
.. .. _OAEP: http://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
.. _authenticated encryption modes: https://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
.. _Camellia: https://en.wikipedia.org/wiki/Camellia_%28cipher%29
.. _ChaCha20: https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
.. _AES: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
