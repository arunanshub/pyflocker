Examples
========

The following have been adapted from `Pycryptodome's documentation <https://www.pycryptodome.org/en/latest/src/examples.html>`_.

Encrypt data with AES
---------------------

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
---------------------------------------------------------

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
------------------------------------

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

Creating, Serializing and Loading an asymmetric key
---------------------------------------------------

Here, we will use RSA_ as an example.

Creation
~~~~~~~~

.. code-block:: python

    from pyflocker.ciphers import RSA
    private = RSA.generate(2048)
    public = RSA.public_key()

Serialization
~~~~~~~~~~~~~

By default, RSA uses ``PKCS8`` format with ``PEM`` encoding, but you can
use different parameters.

.. code-block:: python

    passphrase = b"no not this"

    # Serialize the private key
    with open("private.pem", "wb") as file:
        file.write(private.serialize(passphrase=passphrase))

    # Serialize the public key
    with open("public.pem", "wb") as file:
        file.write(public.serialize())

Loading the keys
~~~~~~~~~~~~~~~~

.. code-block:: python

    # Load the private key
    with open("private.pem", "rb") as file:
        private = RSA.load_private_key(file.read(), passphrase)

    # Load the public key
    with open("public.pem", "rb") as file:
        public = RSA.load_public_key(file.read())

Encryption and Decryption with RSA
----------------------------------

The following code encrypts a piece of data for a receiver we have the RSA
public key of. The RSA public key is stored in a file called ``receiver.pem``.

Since we want to be able to encrypt an arbitrary amount of data, we use a
hybrid encryption scheme. We use RSA with PKCS#1 OAEP_ for asymmetric
encryption of an AES session key. The session key can then be used to encrypt
all the actual data.

Here, we will use the CTR_ mode with HMAC_ to allow detection of unauthorized
modifications. You can use any mode.

First, we will create a file to read data from:

.. code-block:: python

    data = b"""\
    Hello world this is a text that will be encrypted.
    Add some more of your own here.
    """

    with open("somedata.txt", "wb") as file:
        file.write(data)

Encryption
~~~~~~~~~~

Next, we will read the data from ``somedata.txt`` and encrypt it.

.. code-block:: python

    import os
    from pyflocker.ciphers import AES, RSA, OAEP

    # Load the receiver's public key.
    with open("receiver.pem", "rb") as file:
        public = RSA.load_public_key(file.read())

    # Create an AES cipher with session key:
    # This will be used to encrypt an arbitrary amount of data.
    session_key, nonce = os.urandom(32), os.urandom(16)
    cipher_aes = AES.new(
        True,
        session_key,
        AES.MODE_CTR,
        nonce,
        use_hmac=True,
    )

    # Use the public key to encrypt the session key.
    cipher_rsa = public.encryptor(OAEP())
    enc_session_key = cipher_rsa.encrypt(session_key)

    with open("somedata.txt", "rb") as file:
        ciphertext = cipher_aes.update(file.read())

    # Calculate the cipher tag
    cipher_aes.finalize()
    tag = cipher_aes.calculate_tag()

    with open("encrypted.bin", "wb") as file:
        file.write(
            enc_session_key,
            nonce,
            tag,
            ciphertext,
        )

Decryption
~~~~~~~~~~

Decryption process is the inverse of encryption. The receiver will decrypt the
encrypted session key and use it to decrypt the encrypted file (here
``encrypted.bin``)

.. code-block:: python

    from pyflocker.ciphers import AES, RSA, OAEP

    # The receiver loads their private key.
    with open("private.pem", "rb") as file:
        private = RSA.load_private_key(file.read())

    # Read the encrypted file and separate the parts.
    with open("encrypted.bin", "rb") as file:
        (
            enc_session_key,
            nonce,
            tag,
            ciphertext,
        ) = [file.read(n) for n in (private.n.bit_length() // 8, 16, 16, -1)]

    # Decrypt the session key and create a cipher.
    dec = private.decryptor(OAEP())
    session_key = dec.decrypt(enc_session_key)

    cipher_aes = AES.new(
        False,
        session_key,
        AES.MODE_CTR,
        nonce,
        use_hmac=True,
    )

    # Decrypt the ciphertext and verify the decryption.
    plaintext = cipher_aes.update(ciphertext)
    cipher_aes.finalize(tag)

    print(plaintext)

.. _GCM mode: https://en.wikipedia.org/wiki/GCM_mode
.. _CCM: https://en.wikipedia.org/wiki/CCM_mode
.. _EAX: https://en.wikipedia.org/wiki/EAX_mode
.. _SIV: https://tools.ietf.org/html/rfc5297
.. .. _scrypt: http://it.wikipedia.org/wiki/Scrypt
.. _OAEP: http://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
.. _authenticated encryption modes: https://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
.. _Camellia: https://en.wikipedia.org/wiki/Camellia_%28cipher%29
.. _ChaCha20: https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
.. _AES: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
.. _RSA: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
.. _CTR:
.. _HMAC: https://en.wikipedia.org/wiki/HMAC
