# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t
import uuid

import pytest
from cryptography.hazmat.primitives import hashes

from dpapi_ng import _crypto as crypto


def test_cek_decrypt_invalid_algorithm() -> None:
    with pytest.raises(NotImplementedError, match="Unknown cek encryption algorithm OID '1.2'"):
        crypto.cek_decrypt("1.2", None, b"", b"")


def test_content_decrypt_aes256_gcm_no_parameters() -> None:
    with pytest.raises(ValueError, match="Expecting parameters for AES256 GCM decryption but received none"):
        crypto.content_decrypt("2.16.840.1.101.3.4.1.46", None, b"", b"")


def test_content_decrypt_invalid_algorithm() -> None:
    with pytest.raises(NotImplementedError, match="Unknown content encryption algorithm OID '1.2'"):
        crypto.content_decrypt("1.2", None, b"", b"")


def test_cek_encrypt_invalid_algorithm() -> None:
    with pytest.raises(NotImplementedError, match="Unknown cek encryption algorithm OID '1.2'"):
        crypto.cek_encrypt("1.2", None, b"", b"")


def test_content_encrypt_aes256_gcm_no_parameters() -> None:
    with pytest.raises(ValueError, match="Expecting parameters for AES256 GCM encryption but received none"):
        crypto.content_encrypt("2.16.840.1.101.3.4.1.46", None, b"", b"")


def test_content_encrypt_invalid_algorithm() -> None:
    with pytest.raises(NotImplementedError, match="Unknown content encryption algorithm OID '1.2'"):
        crypto.content_encrypt("1.2", None, b"", b"")


def test_cek_generate_invalid_algorithm() -> None:
    with pytest.raises(NotImplementedError, match="Unknown cek encryption algorithm OID '1.2'"):
        crypto.cek_generate("1.2")
