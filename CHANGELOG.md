## v0.4.1 (2023-02-23)

### Refactor

- **pyflocker**: add type marker file for easier integration with type checkers

## v0.4.0 (2022-12-17)

### Feat

- **cryptography_/ECC**: load OpenSSH public keys
- **asymmetric**: add loaders for EdDSA algorithms
- **ECC**: load Raw encoded ECC private keys
- **interfaces/ECC**: add `curve` param to load SEC1/Raw curves
- **ECC**: add support for EdDSA curves
- **base**: add base classes for EdDSA signing/verifying
- **cryptography_/Hash**: handle case where arguments specific to cryptodome is supplied
- **asymmetric**: add `EdDSA` signature algorithm for EdDSA keys
- **Hash**: remove `OID` property
- **cryptography_/Camellia**: raise `UnsupportedMode` if mode is not supported
- **cryptodome_/AES**: raise more appropriate `UnsupportedMode` instead of `NotImplementedError`
- **exc**: add `UnsupportedMode` exception
- **AES,Camellia**: accept only `None` or `BaseHash` types for HMAC digestmod
- **misc**: accept only types implementing `BaseHash`
- **AES**: use `AuthenticationMixin` class; fix class hierarchy
- **AuthenticationMixin**: add mixin class to provide authentication functionality
- **base**: add base class for AEAD Oneshot ciphers
- **asymmetric**: raise `TypeError` if unknown padding/signing algorithm is provided
- **cryptography_/ECC**: implement abstract method `curve`
- **base,ECC**: add abstract methods (`curve`, `public_key`) to ECC base classes
- **cryptography_/ECC**: use proepr base classes for ECC; handle algorithms properly
- **cryptodome_/ECC**: use ECC base classes, signer/verifier context
- **asymmetric**: add factory functions for ECDH, ECDSA
- **ciphers**: allow import of ECDH, ECDSA from package
- **asymmetric**: add EC algorithms for signing and exchange
- **base**: add base class for EC keys, EC exchange/signing algorithms
- derive MGFs and padding functions from base class and add type hints
- **base**: add base class for asymmetric padding and MGFs
- **ciphers**: import `Backends` enum from `pyflocker.ciphers` directly
- **base**: add base class for DH parameters, private and public key
- **cryptography/DH**: get parameter numbers in __init__; add `key_size` property
- **RSA**: add `key_size` property
- **locker**: add `encrypt`, `decrypt`, `encryptf`, `decryptf`
- **base**: add RSA `load` and `serialize` as abstractmethod
- **cryptodome/RSA**: make public key serialization API compatible with pyca/cryptography
- **base,RSA**: adhere to new Signer/Verifier & Encryptor/Decryptor Context base classes
- **base,RSA**: add base class for RSA private and public key
- **modes**: enforce integer values for `Modes` enum
- **cryptodome**: add `TupleHash` variants and simplify hash creation
- **Hash**: add `custom` and `key` kwarg; add relevant docs
- **cryptodome**: add `kangaroo12`, `cshake` support

### Fix

- **symmetric**: use proper error message for `calculate_tag()`
- **cryptodome_/ECC**: fix error message for PEM and DER serialization
- **cryptography_/misc**: fix error message for `derive_poly1305_key`
- **cryptodome_/ECC**: add missing `curve=` argument
- **cryptography_/ChaCha20**: properly initialize `ChaCha20` cipher with conditionals
- **tests/base**: fix offset calculation for buffer
- **cryptography_/AES**: raise `ValueError` if tag not provided
- **backends/AES**: raise `NotImplementedError` if `mode` is unsupported
- **cryptodome_/ChaCha20**: add `_tag` attribute
- **cryptography_/Hash**: block size must not be `None`
- **locker**: convert `file` to str via `os.fspath`
- **locker**: use str to represent paths
- **cryptodome_/ECC**: add curve name param to ECC public key loader
- **cryptodome_/ECC**: fix encoding/format validation and error message
- **cryptodome_/ECC**: always encode exported key; implement abstract methods
- **cryptography_/ECC**: use defaults for `encoding` and `format` params
- **cryptography_/DH**: add missing return keyword; fix type hints
- **cryptography_/DH**: check type of the returned key when loading DH keys
- **cryptography_/DH**: catch `StopIteration` instead of `IndexError` upon calling `next()`
- **cryptodome_/RSA**: raise `SignatureError` from `ValueError` to show verification failure
- **cryptography_/asymmetric**: check if `salt_length` is `None`
- **cryptodome_/asymmetric**: pass a lambda func as MGF and raise `TypeError` if not `MGF1`
- **cryptodome_/RSA**: check if return value is `None` or not
- **cryptography/RSA**: convert memoryview object to bytes
- **Hash**: raise `AttributeError` instead of generic `ValueError`
- **Hash**: use `self.digest_size` if `digest_size` not provided
- **cryptography**: fix incorrect `blake2s` OID
- **cryptodome**: fix `TypeError` if key not supplied when hash is `blake*`
- **Hash**: use `self.name` for creating a new hash object

### Refactor

- **cryptography_/ECC**: rename `msghash` to `message` to EdDSA for signer/verifier
- use string literal in `typing.cast` type
- **Hash**: allow `data` param to be `None`
- **pyflocker/locker**: do not hardcode nonce length
- **cryptography_/ChaCha20**: remove obsolete `default_backend()`
- **cryptography_/ECC**: remove unused code; add documentation
- **cryptography_/DH**: simplify `serialize` and `load` code
- **cryptography_/RSA**: simplify `serialize` and `load` code
- **cryptodome_/RSA**: simplify `serialize` and `load` logic
- **cryptography_/DH**: shorten error to use backend error message
- fix type hints and format code
- **interfaces**: use `io.BufferedIOBase` as type hint for `file` param
- **cryptodome_/symmetric**: simplify conditional block
- **interfaces/AES**: manually add mode values instead of updating the global scope
- **mypy**: use `assert` to prevent mypy errors
- **mypy**: remove unused `type: ingore`s
- use modern type hint syntax
- **locker**: add `assert`s for mypy checks
- **cryptography_/RSA**: avoid mypy issues
- **type-hints**: fix mypy type conflicts
- add type hints everywhere
- **cryptography_/ECC**: adjust for extra param `curve`
- **RSA**: use factory functions for object creation
- **interfaces/ECC**: update type hints and remove ``edwards`` kwarg
- **cryptodome_/RSA**: extract PKCS#1 validator into its own function
- add `from __future__ import annotations` everywhere
- **cryptodome_/RSA**: store supported encodings and formats as class vars; simplify RSA Pubkey `load()`
- **interfaces/ECC**: remove calls to dict
- **cryptography_/asymmetric**: remove calls to dict
- **cryptography_/RSA**: remove calls within signature; access key's method directly
- **cryptography_/Hash**: remove call to dict; add default value to getattr
- **cryptography_/ECC**: rename constant to more explicit name; simplify type checking of `passphrase`
- **cryptography_/ChaCha20**: remove nested ifs
- **cryptography_/Camellia**: do not create new variable; return directly
- **cryptography_/AES**: remove nested ifs
- **misc**: check for errors first; remove deprecated call to `default_backend`
- **cryptodome_/RSA**: remove nested ifs; remove calls in signature; fix doc typo
- **cryptodome_/Hash**: get rid of calls to dict
- **cryptodome_/ECC**: get rid of calls to dict
- **cryptodome_/AES**: remove calls to dict; remove nested ifs
- **symmetric**: get rid of redundant nested ifs
- **exc**: get rid of redundant `pass` statements
- **cryptography_/RSA**: move supported encodings and formats into the classes
- **cryptography_/DH**: supported encodings and formats reside in their own classes
- **modes**: use uppercase for constant (`AEAD` and `SPECIAL`)
- **RSA**: eliminate superclasses used for fetching RSA numbers
- conditional import based on type checking
- **interfaces**: fix type hint for `Hash.new`
- **cryptography**: clean up code responsible for hash creation
- **cryptography**: simplify code of `Hash` module
- **base**: use type class instead of the object
- **__init__**: calculate `version_info` from `__version__`
