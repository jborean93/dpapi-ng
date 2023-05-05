# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

from ._asn1 import ASN1Reader


def cek_decrypt(
    algorithm: str,
    parameters: t.Optional[bytes],
    kek: bytes,
    value: bytes,
) -> bytes:
    if algorithm == "2.16.840.1.101.3.4.1.45":  # AES256-wrap
        return keywrap.aes_key_unwrap(kek, value)

    else:
        raise NotImplementedError(f"Unknown cek encryption algorithm OID '{algorithm}'")


def content_decrypt(
    algorithm: str,
    parameters: t.Optional[bytes],
    cek: bytes,
    value: bytes,
) -> bytes:
    if algorithm == "2.16.840.1.101.3.4.1.46":  # AES256-GCM
        if not parameters:
            raise ValueError("Expecting parameters for AES256 GCM decryption but received none.")

        reader = ASN1Reader(parameters).read_sequence()
        iv = reader.read_octet_string()

        cipher = AESGCM(cek)
        return cipher.decrypt(iv, value, None)

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
    shared_secret: bytes,
    algorithm_id: bytes,
    party_uinfo: bytes,
    party_vinfo: bytes,
    length: int,
) -> bytes:
    otherinfo = b"".join([algorithm_id, party_uinfo, party_vinfo])
    return ConcatKDFHash(
        # BCryptDeriveKey always uses t the SHA256 algorithm here for
        # SP800_56A_CONCAT.
        hashes.SHA256(),
        length=length,
        otherinfo=otherinfo,
    ).derive(shared_secret)
