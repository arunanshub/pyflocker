"""Cryptodome backend specific templates and tools for symmetric ciphers."""

from __future__ import annotations

import typing

from ... import base, exc


class NonAEADCipherTemplate(base.BaseNonAEADCipher):
    """
    Template class to provide the default behavior if BaseNonAEADCipher.

    Subclasses need to provide:

    - ``_encrypting``
    - ``_update_func``
    """

    # these are *not* class variables
    _encrypting: bool
    _update_func: typing.Callable

    def is_encrypting(self) -> bool:
        return self._encrypting

    def update(self, data: bytes) -> bytes:
        if self._update_func is None:
            raise exc.AlreadyFinalized
        return self._update_func(data)

    def update_into(
        self,
        data: bytes,
        out: bytearray | memoryview,
    ) -> None:
        if self._update_func is None:
            raise exc.AlreadyFinalized
        self._update_func(data, out)

    def finalize(self) -> None:
        if not self._update_func:
            raise exc.AlreadyFinalized

        self._update_func = None  # type: ignore


class AEADCipherTemplate(base.BaseAEADCipher):
    """
    Template class to provide the default behavior if BaseAEADCipher.

    Subclasses need to provide the following attributes:

    - ``_encrypting``
    - ``_update_func``
    - ``_cipher``
    """

    # these are *not* class variables
    _updated: bool = False
    _tag: bytes | None = None

    _encrypting: bool
    _update_func: typing.Callable
    _cipher: typing.Any

    def is_encrypting(self) -> bool:
        return self._encrypting

    def update(self, data: bytes) -> bytes:
        self._updated = True
        if self._update_func is None:
            raise exc.AlreadyFinalized
        return self._update_func(data)

    def update_into(
        self,
        data: bytes,
        out: bytearray | memoryview,
    ) -> None:
        self._updated = True
        if self._update_func is None:
            raise exc.AlreadyFinalized
        self._update_func(data, out)

    def authenticate(self, data: bytes) -> None:
        if self._update_func is None:
            raise exc.AlreadyFinalized
        if self._updated:
            raise TypeError
        self._cipher.update(data)

    def finalize(self, tag: bytes | None = None) -> None:
        if self._update_func is None:
            raise exc.AlreadyFinalized

        if not self.is_encrypting():
            if tag is None:
                raise ValueError("tag is required for finalization")

            cipher, self._cipher = self._cipher, None
            self._update_func = None  # type: ignore
            try:
                cipher.verify(tag)
            except ValueError as e:
                raise exc.DecryptionError from e
        else:
            self._tag, self._cipher = self._cipher.digest(), None
            self._update_func = None  # type: ignore

    def calculate_tag(self) -> bytes | None:
        if self._update_func is not None:
            raise exc.NotFinalized

        return self._tag
