from __future__ import annotations

import typing

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import DSS, eddsa, pss

from .. import asymmetric

if typing.TYPE_CHECKING:  # pragma: no cover
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
    if not isinstance(padding, asymmetric.OAEP):  # pragma: no cover
        msg = "padding must be an OAEP object"
        raise TypeError(msg)
    if not isinstance(padding.mgf, asymmetric.MGF1):
        msg = "mgf must be an MGF1 instance"
        raise TypeError(msg)

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
    if not isinstance(padding, asymmetric.PSS):  # pragma: no cover
        msg = "padding must be a PSS object"
        raise TypeError(msg)
    if not isinstance(padding.mgf, asymmetric.MGF1):
        msg = "mgf must be an MGF1 instance"
        raise TypeError(msg)

    if padding.salt_length is None:
        return _SaltLengthMaximizer(key, padding)

    return pss.new(
        key,
        mask_func=lambda x, y: pss.MGF1(  # type: ignore
            x,
            y,
            padding.mgf.hashfunc.new(),
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
    if not isinstance(algorithm, asymmetric.ECDSA):  # pragma: no cover
        msg = "algorithm must be an instance of ECDSA"
        raise TypeError(msg)
    return DSS.new(key, mode="fips-186-3", encoding="der")  # type: ignore


def get_EdDSA(
    key: EccKey,
    algorithm: asymmetric.BaseEllepticCurveSignatureAlgorithm,
) -> eddsa.EdDSASigScheme:
    if not isinstance(algorithm, asymmetric.EdDSA):
        msg = "algorithm must be an instance of EdDSA"
        raise TypeError(msg)
    return eddsa.new(
        key,
        mode=algorithm.mode,
        context=algorithm.context,
    )


class _SaltLengthMaximizer:
    """
    Custom sign/verify wrapper over PSS to preserve consistency.
    pyca/cryptography follows the OpenSSL quirk where the default salt length
    is maximized and doesn't match with the size of the digest applied to the
    message.
    """

    def __init__(self, key: RsaKey, padding: typing.Any) -> None:
        self._key = key
        self._padding = padding

    def _sign_or_verify(
        self,
        msghash: typing.Any,
        signature: bytes | None = None,
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
            msg = "The key is not a private key."
            raise TypeError(msg)
        return self._sign_or_verify(msghash)

    def verify(self, msghash: typing.Any, signature: bytes) -> None:
        return self._sign_or_verify(msghash, signature)


PADDINGS: dict[type[base.BaseAsymmetricPadding], typing.Callable] = {
    asymmetric.OAEP: get_OAEP,
    asymmetric.PSS: get_PSS,
}

EC_SIGNATURE_ALGORITHMS: dict[
    type[base.BaseEllepticCurveSignatureAlgorithm],
    typing.Callable,
] = {
    asymmetric.ECDSA: get_ECDSA,
    asymmetric.EdDSA: get_EdDSA,
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
    try:
        return PADDINGS[type(padding)](*args, **kwargs)
    except KeyError as e:
        msg = f"Invalid padding algorithm type: {type(padding)}"
        raise TypeError(msg) from e


def get_ec_signature_algorithm(
    algorithm: base.BaseEllepticCurveSignatureAlgorithm,
    *args: typing.Any,
    **kwargs: typing.Any,
) -> typing.Any:
    try:
        return EC_SIGNATURE_ALGORITHMS[type(algorithm)](*args, **kwargs)
    except KeyError as e:
        msg = f"Invalid signature algorithm type: {type(algorithm)}"
        raise TypeError(msg) from e
