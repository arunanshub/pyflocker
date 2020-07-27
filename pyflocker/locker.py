"""Locker -- Utility tools for encrypting files.

This module provides functions to encrypt and decrypt
files using AES encryption.
"""

import os
import struct

from hashlib import pbkdf2_hmac
from functools import partial

from .ciphers import AES, exc, Modes, aead, special

HEADER_FORMAT = struct.Struct('>I 32s 32s 6x 32s 6x 16s')

MAGIC = 0xc8e52e4b


def locker(file,
           password,
           locking=None,
           remove=True,
           *,
           ext=None,
           newfile=None,
           **kwargs):
    """Encrypts or decrypts files with AES algorithm.

    See `lockerf` function for more details.

    Args:
        file:
            The actual location of the file.
        password:
            Password to use to encrypt the file. See `lockerf`
        locking:
            Whether the file is being locked (encrypted) or not.

            If `locking` is True, the file is encrypted no matter what
            the extension is.
            If `locking` is False, the file is decrypted no matter what
            the extension is.

            If `locking` is None (the default), it is guessed from the file
            extension and the file header instead.

            If locking is provided, argument `ext` is ignored.
        remove:
            Whether to remove the file after encryption/decryption. Default
            is True.

    Kwargs:
        ext:
            The extension to be used for the encrypted file. If None,
            the default value `.pyflk` is used.
        newfile:
            The name of the file to be written upon. It must not be
            already present. If None is provided (default), the name
            of the `file` plus the extension is used.

        All other kwargs are passed to `lockerf` function.
    """
    # checks
    if newfile and ext:
        raise ValueError('newfile and ext are mutually exclusive')

    # default extension if not provided
    ext = ext or '.pyflk'

    # guess locking if not provided
    if locking is None:
        locking = not file.endswith(ext)

    # make newfile name if not provided
    if newfile is None:
        if locking:
            newfile = file + ext
        else:
            newfile = os.path.splitext(file)[0]

    try:
        with open(file, 'rb') as infile, open(newfile, 'xb') as outfile:
            lockerf(infile, outfile, password, locking, **kwargs)
    except exc.DecryptionError:
        # remove invalid file
        os.remove(newfile)
        raise
    else:
        # remove the original file
        if remove:
            os.remove(file)


def lockerf(infile,
            outfile,
            password,
            locking,
            *,
            kdf=None,
            aes_mode=None,
            blocksize=16364,
            metadata=None,
            dklen=32,
            backend=None,
            **kwargs):
    """Utility tool for encrypting files.

    This function reads from `infile` in blocks, specified by `blocksize`,
    encrypts or decrypts the data and writes to `outfile`. By design of
    the cipher wrapper for R/W to files, no intermideate copy of data is
    made during operation.

    Operation details
    ~~~~~~~~~~~~~~~~~

    1. Password derivation
    ~~~~~~~~~~~~~~~~~~~~~~
    The `password` is first derived into a key with PBKDF2-HMAC with
    32 byte salt, 50000 iterations, 'sha256' as the hash algorithm,
    although they can be modified by keeping `kdf` as None, and passing
    the modified values through `kwargs`, except `password` and `salt`

    If you want to use a different KDF, pass it to `kdf` and pass the
    remaining arguments through `kwargs`

    2. Cipher creation
    ~~~~~~~~~~~~~~~~~~
    The cipher is created with 12 byte nonce if mode is GCM else 16 byte
    nonce. The nonce is stored as a part of HEADER for identifying the
    file, along with other required values.

    2.1 Authentication
    ~~~~~~~~~~~~~~~~~~
    Before the operation begins, the authentication data is passed to the
    cipher. The authentication bits are: (salt, metadata) in that order.

    N.B. If the cipher mode does not support authentication, HMAC is used.
    refer to the documentation of `base.Cipher`.

    3. Finalization
    ~~~~~~~~~~~~~~~
    After completion of the entire operation, the tag created by the auth-
    enticatior of the cipher is written to the file as a part of HEADER.
    If the file is being decrypted, it is read from the HEADER for verify-
    ing the file integrity and correct decryption.

    Args:
        infile:
            The file or file-like object to read from.
        outfile:
            The file or file-like object to write into.
        password:
            The password to use for encrypting the files.
        locking:
            Whether the infile is being encrypted: True; or decrypted: False.

    Kwargs:
        kdf:
            The key derivation function to use for deriving keys.
            `hashlib.pbkdf2_hmac` is used with 50000 iterations and
            `sha256` as the hash algorithm.

            Keeping the `kdf` as None, you can adjust the KDF's parameters
            by passing it to kwargs.
        aes_mode:
            The AES mode to use for encryption/decryption.
            The mode can be any attribute from `Modes`, except those
            which are defined is `pyflocker.ciphers.modes.special`.
            Defaults to AES-GCM.
        blocksize:
            The amount of data to read from `infile` in each iteration.
            Defalts to 16384.
        metadata:
            The metadata to write to the file. It must be up-to 32 bytes.
        dklen:
            The desired key length (in bytes) for passing to the cipher.
            It specifies the strength of AES cipher. Defaults to 32.
        backend:
            The backend to use to instantiate the AES cipher from.
            If None is specified (the default), any available backend
            will be used.

        If `kdf` is None, the default KDF's (PBKDF2-HMAC) parameters can
        be adjusted by passing extra keyword arguments.

    Returns:
        None

    Raises:
        `DecryptionError` if password was invalid or the file was tampered
        with.
        `NotImplementedError` if the mode is not supported.
    """

    if os.path.samefile(infile.fileno(), outfile.fileno()):
        raise ValueError("infile and outfile cannot be the same")

    # set defaults
    if aes_mode in special:
        # for one rounds:
        # we need gradual encryption ability
        raise NotImplementedError

    aes_mode = aes_mode or Modes.MODE_GCM
    if metadata is None:
        metadata = b"CREATED BY: PYFLOCKER"
    else:
        if len(metadata) < 32:
            raise ValueError("maximum metadata length exceeded")

    # header extract if decrypting,
    # else create values.
    salt, tag, rand = _fetch_header(infile, aes_mode, locking, MAGIC, metadata)

    # password -> key
    if kdf is None:
        # defaults to PBKDF2-HMAC

        # set defaults here.
        _kdf_args = dict(iterations=50000,
                         hash_name='sha256',
                         dklen=_key_length(dklen))

        # update the values with kwargs
        # (could have some user supplied values)
        _kdf_args.update(kwargs)

        kwargs = _kdf_args
        kdf = partial(pbkdf2_hmac)

    # if kdf given, it is assumed that all the required
    # arguments except `password, salt` are supplied
    # through kwargs
    key = kdf(password=password, salt=salt, **kwargs)

    # init. cipher
    crp = AES.new(locking,
                  key,
                  aes_mode or Modes.MODE_GCM,
                  rand,
                  file=infile,
                  backend=backend)

    # authenticate header portion
    crp.authenticate(salt + metadata)

    if locking:
        header = HEADER_FORMAT.pack(
            MAGIC,
            # these parts are unique
            metadata,
            salt,
            tag,
            rand)
        outfile.write(header)

    # write
    crp.update_into(outfile, tag, blocksize)

    if locking:
        # tag position
        outfile.seek(74)
        outfile.write(crp.calculate_tag())


def _key_length(n):
    if n in (128, 192, 256):
        return n // 8
    elif n in (16, 24, 32):
        return n
    else:
        raise ValueError("invalid key length")


def _fetch_header(infile, mode, locking, magic, meta):
    """Extracts header values. If encrypting file,
    creates the values"""

    if locking:
        # different for GCM
        if mode == Modes.MODE_GCM:
            rand = os.urandom(12)
        else:
            rand = os.urandom(16)
        salt = os.urandom(32)
        tag = bytes(32)
    else:
        header = infile.read(HEADER_FORMAT.size)
        try:
            m, c, salt, tag, rand = HEADER_FORMAT.unpack_from(header, 0)
        except struct.error:
            raise TypeError("Invalid file header format. "
                            "The file is not compatible with "
                            "PyFlocker.")
        # header check
        if m != magic or meta != c[:-(32 - len(meta))]:
            raise TypeError("invalid file header format. "
                            "The file is not compatible with "
                            "PyFLocker")

        # get the tag and random part
        if mode in aead:
            # tag is 16 bytes
            tag = tag[:16]
        if mode == Modes.MODE_GCM:
            # GCM uses 12 byte nonce
            rand = rand[:-4]

    return salt, tag, rand
