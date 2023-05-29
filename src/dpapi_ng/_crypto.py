# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import os
import typing as t

from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

from ._asn1 import ASN1Reader


class AlgorithmOID(str, enum.Enum):
    """OIDs for cryptographic algorithms."""

    AES256_WRAP = "2.16.840.1.101.3.4.1.45"
    AES256_GCM = "2.16.840.1.101.3.4.1.46"


def cek_decrypt(
    algorithm: str,
    parameters: t.Optional[bytes],
    kek: bytes,
    value: bytes,
) -> bytes:
    if algorithm == AlgorithmOID.AES256_WRAP:
        return keywrap.aes_key_unwrap(kek, value)

    else:
        raise NotImplementedError(f"Unknown cek encryption algorithm OID '{algorithm}'")


def cek_encrypt(
    algorithm: str,
    parameters: t.Optional[bytes],
    kek: bytes,
    value: bytes,
) -> bytes:
    if algorithm == AlgorithmOID.AES256_WRAP:
        return keywrap.aes_key_wrap(kek, value)

    else:
        raise NotImplementedError(f"Unknown cek encryption algorithm OID '{algorithm}'")


def cek_generate(
    algorithm: str,
) -> t.Tuple[bytes, bytes]:
    if algorithm == AlgorithmOID.AES256_WRAP:
        cek = AESGCM.generate_key(bit_length=256)
        cek_iv = os.urandom(12)
        return cek, cek_iv

    else:
        raise NotImplementedError(f"Unknown cek encryption algorithm OID '{algorithm}'")


def content_decrypt(
    algorithm: str,
    parameters: t.Optional[bytes],
    cek: bytes,
    value: bytes,
) -> bytes:
    if algorithm == AlgorithmOID.AES256_GCM:
        if not parameters:
            raise ValueError("Expecting parameters for AES256 GCM decryption but received none.")

        reader = ASN1Reader(parameters).read_sequence()
        iv = reader.read_octet_string()

        cipher = AESGCM(cek)
        return cipher.decrypt(iv, value, None)

    else:
        raise NotImplementedError(f"Unknown content encryption algorithm OID '{algorithm}'")


def content_encrypt(
    algorithm: str,
    parameters: t.Optional[bytes],
    cek: bytes,
    value: bytes,
) -> bytes:
    if algorithm == AlgorithmOID.AES256_GCM:
        if not parameters:
            raise ValueError("Expecting parameters for AES256 GCM decryption but received none.")

        reader = ASN1Reader(parameters).read_sequence()
        iv = reader.read_octet_string()

        cipher = AESGCM(cek)
        return cipher.encrypt(iv, value, None)

    else:
        raise NotImplementedError(f"Unknown content encryption algorithm OID '{algorithm}'")


def kdf(
    algorithm: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
) -> bytes:
    # KDF(HashAlg, KI, Label, Context, L)
    # where KDF is SP800-108 in counter mode.
    kdf = KBKDFHMAC(
        algorithm=algorithm,
        mode=Mode.CounterMode,
        length=length,
        label=label,
        context=context,
        # MS-SMB2 uses the same KDF function and my implementation that
        # sets a value of 4 seems to work so assume that's the case here.
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        fixed=None,
    )
    return kdf.derive(secret)


def kdf_concat(
    algorithm: hashes.HashAlgorithm,
    shared_secret: bytes,
    algorithm_id: bytes,
    party_uinfo: bytes,
    party_vinfo: bytes,
    length: int,
) -> bytes:
    otherinfo = b"".join([algorithm_id, party_uinfo, party_vinfo])
    return ConcatKDFHash(
        algorithm,
        length=length,
        otherinfo=otherinfo,
    ).derive(shared_secret)
