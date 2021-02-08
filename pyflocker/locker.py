"""Locker -- Utility tools for encrypting files.

This module provides functions to encrypt and decrypt
files using AES encryption.
"""

import os
import struct
from collections import namedtuple
from functools import partial
from hashlib import pbkdf2_hmac

from .ciphers import AES, exc
from .ciphers.modes import Modes, aead, special

# magic - mode - nonce - tag - metadata - salt
HEADER_FORMAT = struct.Struct(">I H 16s 32s 32s 32s")

MAGIC = 0xC8E52E4A

PBKDF2_HMAC = partial(pbkdf2_hmac, hash_name="sha256", iterations=150000)

METADATA = b"CREATED BY: PyFLocker"

_Header = namedtuple("_Header", "magic mode nonce tag metadata salt")


def locker(
    file,
    password,
    encrypting=None,
    remove=True,
    *,
    ext=None,
    newfile=None,
    **kwargs,
):
    """Encrypts or decrypts files with AES algorithm.

    See also:
        :func:`lockerf` function for more details.

    Args:
        file (str):
            The actual location of the file.
        password (bytes, bytesarray, memoryview):
            Password to use to encrypt/decrypt the file. See ``lockerf``.
        encrypting (bool):
            Whether the file is being locked (encrypted) or not.

            If `encrypting` is True, the file is encrypted no matter what
            the extension is.
            If `encrypting` is False, the file is decrypted no matter what
            the extension is.

            If `encrypting` is None (the default), it is guessed from the file
            extension and the file header instead.

            If encrypting is provided, argument `ext` is ignored.
        remove (bool):
            Whether to remove the file after encryption/decryption. Default
            is True.

    Keyword Arguments:
        ext (str):
            The extension to be used for the encrypted file. If None,
            the default value `.pyflk` is used.
        newfile (str):
            The name of the file to be written upon. It must not be
            already present. If None is provided (default), the name
            of the `file` plus the extension is used.

    All other kwargs are passed to `lockerf` function.
    """
    # checks
    if newfile and ext:
        raise ValueError("newfile and ext are mutually exclusive")

    # default extension if not provided
    ext = ext or ".pyflk"

    # guess encrypting if not provided
    if encrypting is None:
        encrypting = not file.endswith(ext)

    # make newfile name if not provided
    if newfile is None:
        if encrypting:
            newfile = file + ext
        else:
            newfile = os.path.splitext(file)[0]

    try:
        with open(file, "rb") as infile, open(newfile, "xb") as outfile:
            lockerf(infile, outfile, password, encrypting, **kwargs)
    except (TypeError, exc.DecryptionError):
        # remove invalid file
        os.remove(newfile)
        raise
    else:
        # remove the original file
        if remove:
            os.remove(file)


def lockerf(
    infile,
    outfile,
    password,
    encrypting,
    *,
    kdf=PBKDF2_HMAC,
    aes_mode=Modes.MODE_GCM,
    blocksize=16364,
    metadata=METADATA,
    dklen=32,
    backend=None,
):
    """Utility tool for encrypting files.

    This function reads from `infile` in blocks, specified by `blocksize`,
    encrypts or decrypts the data and writes to `outfile`. By design of
    the cipher wrapper for R/W to files, no intermediate copy of data is
    made during operation.

    Operation details:

    1. Password derivation

       The ``password`` is first derived into a key with PBKDF2-HMAC with
       32 byte salt, 50000 iterations, ``sha256`` as the hash algorithm,
       although they can be modified by keeping ``kdf`` as None, and passing
       the modified values through ``kwargs``, except ``password`` and
       ``salt``.

       If you want to use a different KDF, pass it to ``kdf`` and pass the
       remaining arguments through ``kwargs``.

    2. Cipher creation

       The cipher is created with 12 byte nonce if mode is GCM else 16
       byte nonce. The nonce is stored as a part of HEADER for identifying
       the file, along with other required values.

       1. Authentication

          Before the operation begins, the authentication data is passed
          to the cipher. The authentication bits are: (salt, metadata)
          in that order.

    3. Finalization

       After completion of the entire operation, the tag created by the
       authenticatior of the cipher is written to the file as a part of
       ``HEADER``. If the file is being decrypted, it is read from the
       ``HEADER`` for verifying the file integrity and correct decryption.

    Note:
        If the cipher mode does not support authentication, HMAC is used.
        refer to the documentation of :class:`pyflocker.ciphers.base.Cipher`.

    Args:
        infile (filelike):
            The file or file-like object to read from.
        outfile (filelike):
            The file or file-like object to write into.
        password (bytes, bytearray, memoryview):
            The password to use for encrypting the files.
        encrypting (bool):
            Whether the infile is being encrypted: True; or decrypted: False.

    Keyword Arguments:
        kdf (function):
            The key derivation function to use for deriving keys.
            :func:`hashlib.pbkdf2_hmac` is used with 150000 iterations and
            ``sha256`` as the hash algorithm.

            If a custom ``kdf`` is used, the ``kdf`` must accept 3 arguments,
            ``password``, ``salt`` and ``dklen``. It is assumed that the
            other required values are already passed to it. You can use a
            partial function (``functools.partial``) for that purpose.
        aes_mode (:class:`pyflocker.ciphers.modes.Modes`):
            The AES mode to use for encryption/decryption.
            The mode can be any attribute from :any:`Modes` except those
            which are defined in :obj:`pyflocker.ciphers.modes.special`.
            Defaults to :any:`Modes.MODE_GCM`.

            Specifying this value while decrypting has no effect.
        blocksize (int):
            The amount of data to read from ``infile`` in each iteration.
            Defalts to 16384.
        metadata (bytes, bytearray, memoryview):
            The metadata to write to the file. It must be up-to 32 bytes.
        dklen (int):
            The desired key length (in bytes) for passing to the cipher.
            It specifies the strength of AES cipher. Defaults to 32.
        backend (:class:`pyflocker.ciphers.backends.Backends`):
            The backend to use to instantiate the AES cipher from.
            If None is specified (the default), any available backend
            will be used.

    Returns:
        None

    Raises:
        DecryptionError: if password was invalid or the file was tampered
            with.
        NotImplementedError: if the mode is not supported.
    """
    if os.path.samefile(infile.fileno(), outfile.fileno()):
        raise ValueError("infile and outfile cannot be the same")

    # set defaults
    if aes_mode in special:
        raise NotImplementedError(f"{aes_mode} is not supported.")

    if len(metadata) > 32:
        raise ValueError("maximum metadata length exceeded (limit: 32).")

    if not encrypting:
        header = _get_header(infile.read(HEADER_FORMAT.size), metadata)
    else:
        salt = os.urandom(32)
        nonce = os.urandom(12) if aes_mode == AES.MODE_GCM else os.urandom(16)
        header = _Header(MAGIC, aes_mode.value, nonce, b"", metadata, salt)
        outfile.write(HEADER_FORMAT.pack(*header))

    cipher = AES.new(
        encrypting,
        kdf(
            password=password,
            salt=header.salt,
            dklen=_check_key_length(dklen),
        ),
        Modes(header.mode),
        header.nonce,
        file=infile,
        backend=backend,
    )
    cipher.authenticate(
        struct.pack(
            ">I 32s 32s 16s",
            header.magic,  # XXX: MAGIC works just fine; good to be an idiot
            header.salt,
            header.metadata,
            header.nonce,
        )
    )
    cipher.update_into(outfile, blocksize=blocksize, tag=header.tag)

    if encrypting:
        outfile.seek(struct.calcsize(">I H 16s"))
        outfile.write(cipher.calculate_tag())


def extract_header_from_file(path, metadata=METADATA):
    with open(path, "rb") as file:
        return _get_header(file.read(HEADER_FORMAT.size), metadata)


def _check_key_length(n):
    if n in (128, 192, 256):
        return n // 8
    elif n in (16, 24, 32):
        return n
    else:
        raise ValueError("invalid key length")


def _get_header(data, metadata=METADATA):
    try:
        (
            magic,
            mode,
            nonce,
            tag,
            metadata_h,
            salt,
        ) = HEADER_FORMAT.unpack(data)
    except struct.error:
        raise TypeError("The file format is invalid (Header mismatch).")

    if magic != MAGIC or metadata != metadata_h[: len(metadata) - 32]:
        raise TypeError(
            "The file format is invalid (Metadata/magic number mismatch)."
        )

    if mode == Modes.MODE_GCM.value:
        nonce = nonce[:12]
    if Modes(mode) in aead:
        tag = tag[:16]
    return _Header(magic, mode, nonce, tag, metadata, salt)
