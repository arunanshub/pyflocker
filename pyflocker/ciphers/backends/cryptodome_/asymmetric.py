from __future__ import annotations

import typing
from typing import TYPE_CHECKING

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import DSS, pss

from .. import asymmetric

if TYPE_CHECKING:  # pragma: no cover
    from Cryptodome.PublicKey.ECC import EccKey
    from Cryptodome.PublicKey.RSA import RsaKey

    from ... import base


def get_OAEP(
    key: RsaKey,
    padding: base.BaseAsymmetricPadding,
) -> PKCS1_OAEP.PKCS1OAEP_Cipher:
    """Construct a Cryptodome specific OAEP object.

    Args:
        key: Public/Private key (from the Cryptodome backend).
        padding: An OAEP object.

    Returns:
        An OAEP encryptor/decryptor object depending on the key, from the
        Cryptodome backend.
    """
    if not isinstance(padding, asymmetric.OAEP):
        raise TypeError("padding must be an OAEP object")
    if not isinstance(padding.mgf, asymmetric.MGF1):
        raise TypeError("mgf must be an MGF1 instance")

    return PKCS1_OAEP.new(
        key,
        padding.hashfunc.new(),  # type: ignore
        lambda x, y: pss.MGF1(
            x,
            y,
            padding.mgf.hashfunc.new(),  # type: ignore
        ),
        padding.label or b"",
    )


def get_PSS(key: RsaKey, padding: base.BaseAsymmetricPadding) -> typing.Any:
    """Construct a Cryptodome specific PSS object.

    Args:
        key: Public/Private key (from the Cryptodome backend).
        padding: A PSS object.

    Returns:
        An PSS signer/verifier object, depending on the key.
    """
    if not isinstance(padding, asymmetric.PSS):
        raise TypeError("padding must be a PSS object")
    if not isinstance(padding.mgf, asymmetric.MGF1):
        raise TypeError("mgf must be an MGF1 instance")

    if padding.salt_length is None:
        return _SaltLengthMaximizer(key, padding)

    return pss.new(
        key,
        mask_func=lambda x, y: pss.MGF1(  # type: ignore
            x,
            y,
            padding.mgf.hashfunc.new(),  # type: ignore
        ),
        salt_bytes=padding.salt_length,
    )


def get_ECDSA(
    key: EccKey,
    algorithm: asymmetric.BaseEllepticCurveSignatureAlgorithm,
) -> DSS.FipsEcDsaSigScheme:
    """Construct a DSS object for signing/verification.

    Note that, unlike pyca/cryptography, Cryptodome uses ``mode`` and
    ``encoding`` explicitly for its operation.

    Args:
        key: An ECC key object from ``Cryptodome`` backend.
        algorithm: The algorithm to use.

    Returns: Signer/Verifier instance.
    """
    if not isinstance(algorithm, asymmetric.ECDSA):
        raise TypeError("algorithm must be an instance of ECDH")
    return DSS.new(key, mode="fips-186-3", encoding="der")  # type: ignore


class _SaltLengthMaximizer:
    """
    Custom sign/verify wrapper over PSS to preserve consistency:
    pyca/cryptography follows the OpenSSL quirk where the default
    salt length is maximized and doesn't match with the size of the
    digest applied to the message.
    """

    def __init__(self, key: RsaKey, padding: typing.Any) -> None:
        self._key = key
        self._padding = padding

    def _sign_or_verify(
        self,
        msghash: typing.Any,
        signature: typing.Optional[bytes] = None,
    ) -> typing.Any:
        salt_length = self._key.size_in_bytes() - msghash.digest_size - 2
        pss = get_PSS(
            self._key,
            type(self._padding)(self._padding.mgf, salt_length),
        )
        if signature is None:
            return pss.sign(msghash)
        return pss.verify(msghash, signature)

    def sign(self, msghash: typing.Any) -> bytes:
        if not self._key.has_private():
            raise TypeError("The key is not a private key.")
        return self._sign_or_verify(msghash)

    def verify(self, msghash: typing.Any, signature: bytes) -> None:
        return self._sign_or_verify(msghash, signature)


PADDINGS: typing.Dict[
    typing.Type[base.BaseAsymmetricPadding],
    typing.Callable,
] = {
    asymmetric.OAEP: get_OAEP,
    asymmetric.PSS: get_PSS,
}

EC_SIGNATURE_ALGORITHMS: typing.Dict[
    typing.Type[base.BaseEllepticCurveSignatureAlgorithm],
    typing.Callable,
] = {
    asymmetric.ECDSA: get_ECDSA,
}

# PKCS8 password derivation mechanisms
PROTECTION_SCHEMES = {
    "PBKDF2WithHMAC-SHA1AndAES128-CBC",
    "PBKDF2WithHMAC-SHA1AndAES192-CBC",
    "PBKDF2WithHMAC-SHA1AndAES256-CBC",
    "PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC",
    "scryptAndAES128-CBC",
    "scryptAndAES192-CBC",
    "scryptAndAES256-CBC",
}


def get_padding_algorithm(
    padding: base.BaseAsymmetricPadding,
    *args: typing.Any,
    **kwargs: typing.Any,
) -> typing.Any:
    return PADDINGS[type(padding)](*args, **kwargs)


def get_ec_signature_algorithm(
    algorithm: base.BaseEllepticCurveSignatureAlgorithm,
    *args: typing.Any,
    **kwargs: typing.Any,
) -> typing.Any:
    return EC_SIGNATURE_ALGORITHMS[type(algorithm)](*args, **kwargs)
