"""Locker -- Utility tools for encrypting files.

This module provides functions to encrypt and decrypt
files using AES encryption.
"""

from .ciphers import AES, exc, Modes, aead, special
from hashlib import pbkdf2_hmac
from functools import partial
import struct
import os

HEADER_FORMAT = struct.Struct('>I 32s 32s 6x 32s 6x 16s')

MAGIC = 0xc8e52e4b

_BUFFER = memoryview(bytearray(HEADER_FORMAT.size))


def locker(file,
           password,
           locking=None,
           remove=True,
           *,
           ext=None,
           newfile=None,
           **kwargs):
    """Same as `lockerf` but takes file path names as arguments.
    """
    # checks
    if newfile and ext:
        raise ValueError('newfile and ext are mutually exclusive')

    # default extension if not provided
    ext = ext or '.pyflk'

    # guess locking if not provided
    if locking is None:
        if not file.endswith(ext):
            locking = True
        else:
            locking = False

    # make newfile name if not provided
    if newfile is None:
        if locking:
            newfile = file + ext
        else:
            newfile = os.path.splitext(file)[0]

    try:
        with open(file, 'rb') as infile, open(newfile, 'wb') as outfile:
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

    # ToDo: documentation
    """

    if os.path.samefile(infile.fileno(), outfile.fileno()):
        raise ValueError("infile and outfile cannot be the same")

    # set defaults
    if (aes_mode == Modes.MODE_CTR or aes_mode in special):
        # for CTR:
        # cryptography accepts 16 byte nonce, but
        # cryptodome refuses: can't take risk?

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
                  hashed=True,
                  backend=backend)

    # authenticate header portion
    crp.authenticate(key + salt + rand)

    if locking:
        HEADER_FORMAT.pack_into(
            _BUFFER,
            0,
            MAGIC,
            # these parts are unique
            metadata,
            salt,
            tag,
            rand)
        outfile.write(_BUFFER)

    # write
    crp.update_into(outfile, tag)

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
        infile.readinto(_BUFFER)
        m, c, salt, tag, rand = HEADER_FORMAT.unpack_from(_BUFFER, 0)

        # header check
        if m != magic or meta != c[:-(32 - len(meta))]:
            raise TypeError("invalid file header format. "
                            "The file is not compatible with"
                            " PyFLocker")

        # get the tag and random part
        if mode in aead:
            # tag is 16 bytes
            tag = tag[:16]
        if mode == Modes.MODE_GCM:
            # GCM uses 12 byte nonce
            rand = rand[:-4]

    return salt, tag, rand
