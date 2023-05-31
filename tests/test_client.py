# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import json
import uuid

import pytest

import dpapi_ng

from .conftest import get_test_data

# These scenarios were created with tests/integration/files/New-KdsRootKey.ps1
# and tests/integration/files/ConvertTo-DpapiNgBlob.ps1


def _load_root_key(scenario: str) -> tuple[bytes, dpapi_ng.KeyCache]:
    data = json.loads(get_test_data(f"{scenario}.json"))

    cache = dpapi_ng.KeyCache()
    cache.load_key(
        key=base64.b16decode(data["RootKeyData"]),
        root_key_id=uuid.UUID(data["RootKeyId"]),
        version=data["Version"],
        kdf_algorithm=data["KdfAlgorithm"],
        kdf_parameters=base64.b16decode(data["KdfParameters"]),
        secret_algorithm=data["SecretAgreementAlgorithm"],
        secret_parameters=base64.b16decode(data["SecretAgreementParameters"]),
        private_key_length=data["PrivateKeyLength"],
        public_key_length=data["PublicKeyLength"],
    )

    return base64.b16decode(data["Data"]), cache


def _load_seed_key(scenario: str) -> dpapi_ng.KeyCache:
    data = json.loads(get_test_data(f"{scenario}.json"))

    cache = dpapi_ng.KeyCache()
    cache._store_key(
        target_sd=base64.b16decode(data["SecurityDescriptor"]),
        key=dpapi_ng._gkdi.GroupKeyEnvelope(
            version=data["Version"],
            flags=data["Flags"],
            l0=data["L0"],
            l1=data["L1"],
            l2=data["L2"],
            root_key_identifier=uuid.UUID(data["RootKeyId"]),
            kdf_algorithm=data["KdfAlgorithm"],
            kdf_parameters=base64.b16decode(data["KdfParameters"]),
            secret_algorithm=data["SecretAlgorithm"],
            secret_parameters=base64.b16decode(data["SecretParameters"]),
            private_key_length=data["PrivateKeyLength"],
            public_key_length=data["PublicKeyLength"],
            domain_name=data["DomainName"],
            forest_name=data["ForestName"],
            l1_key=base64.b16decode(data["L1Key"]),
            l2_key=base64.b16decode(data["L2Key"]),
        ),
    )

    return cache


def test_protect_secret() -> None:
    test_data = b"schorschii"
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    test_root_key_identifier = "c1f25b76-d435-4015-1259-b14e5cca4e00"

    key_cache = _load_seed_key("seed_key")

    encrypted = dpapi_ng.ncrypt_protect_secret(
        test_data, test_protection_descriptor, root_key_identifier=uuid.UUID(test_root_key_identifier), cache=key_cache
    )
    decrypted = dpapi_ng.ncrypt_unprotect_secret(encrypted, cache=key_cache)
    assert test_data == decrypted


async def test_async_protect_secret() -> None:
    test_data = b"schorschii"
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    test_root_key_identifier = "c1f25b76-d435-4015-1259-b14e5cca4e00"

    key_cache = _load_seed_key("seed_key")

    encrypted = await dpapi_ng.async_ncrypt_protect_secret(
        test_data, test_protection_descriptor, root_key_identifier=uuid.UUID(test_root_key_identifier), cache=key_cache
    )
    decrypted = await dpapi_ng.async_ncrypt_unprotect_secret(encrypted, cache=key_cache)
    assert test_data == decrypted


@pytest.mark.parametrize(
    "scenario",
    [
        "kdf_sha1_nonce",
        "kdf_sha256_nonce",
        "kdf_sha384_nonce",
        "kdf_sha512_nonce",
        "kdf_sha1_dh",
        "kdf_sha256_dh",
        "kdf_sha384_dh",
        "kdf_sha512_dh",
        "kdf_sha1_ecdh_p256",
        "kdf_sha256_ecdh_p256",
        "kdf_sha384_ecdh_p256",
        "kdf_sha512_ecdh_p256",
        "kdf_sha1_ecdh_p384",
        "kdf_sha256_ecdh_p384",
        "kdf_sha384_ecdh_p384",
        "kdf_sha512_ecdh_p384",
    ],
)
def test_unprotect_secret(
    scenario: str,
) -> None:
    expected = b"\x00"

    data, key_cache = _load_root_key(scenario)

    actual = dpapi_ng.ncrypt_unprotect_secret(data, cache=key_cache)
    assert actual == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "kdf_sha1_nonce",
        "kdf_sha256_nonce",
        "kdf_sha384_nonce",
        "kdf_sha512_nonce",
        "kdf_sha1_dh",
        "kdf_sha256_dh",
        "kdf_sha384_dh",
        "kdf_sha512_dh",
        "kdf_sha1_ecdh_p256",
        "kdf_sha256_ecdh_p256",
        "kdf_sha384_ecdh_p256",
        "kdf_sha512_ecdh_p256",
        "kdf_sha1_ecdh_p384",
        "kdf_sha256_ecdh_p384",
        "kdf_sha384_ecdh_p384",
        "kdf_sha512_ecdh_p384",
    ],
)
async def test_async_unprotect_secret(
    scenario: str,
) -> None:
    expected = b"\x00"

    data, key_cache = _load_root_key(scenario)

    actual = await dpapi_ng.async_ncrypt_unprotect_secret(data, cache=key_cache)
    assert actual == expected
