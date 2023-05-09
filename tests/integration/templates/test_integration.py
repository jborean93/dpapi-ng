# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import os
import pathlib
import socket

import pytest

import dpapi_ng

DOMAIN_REALM = "{{ domain_name }}"
DC_FQDN = f"dc01.{DOMAIN_REALM}"
DC_IP = socket.gethostbyname(DC_FQDN)
USERNAME = "{{ domain_username | lower }}"
PASSWORD = "{{ domain_password }}"
USER_UPN = f"{USERNAME}@{DOMAIN_REALM.upper()}"

BLOB_USER = base64.b64decode((pathlib.Path(__file__).parent / "blob-user").read_text())
BLOB_DIFFERENT = base64.b64decode((pathlib.Path(__file__).parent / "blob-different").read_text())


@pytest.mark.parametrize("data", [BLOB_USER, BLOB_DIFFERENT], ids=["user", "different"])
def test_decrypt_sync(data: bytes) -> None:
    expected = b"\x00"

    actual = dpapi_ng.ncrypt_unprotect_secret(data)
    assert actual == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [BLOB_USER, BLOB_DIFFERENT], ids=["user", "different"])
async def test_decrypt_async(data: bytes) -> None:
    expected = b"\x00"

    actual = await dpapi_ng.async_ncrypt_unprotect_secret(data)
    assert actual == expected


@pytest.mark.parametrize("protocol", ["negotiate", "negotiate-ntlm", "kerberos", "ntlm"])
def test_rpc_auth(protocol: str) -> None:
    expected = b"\x00"
    server = None
    username = None
    password = None
    is_ntlm = protocol in ["negotiate-ntlm", "ntlm"]
    if protocol == "negotiate-ntlm":
        server = DC_IP
        protocol = "negotiate"

    if os.name != "nt" and is_ntlm:
        username = USER_UPN
        password = PASSWORD

    actual = dpapi_ng.ncrypt_unprotect_secret(
        BLOB_USER,
        server,
        username=username,
        password=password,
        auth_protocol=protocol,
    )
    assert actual == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["negotiate", "negotiate-ntlm", "kerberos", "ntlm"])
async def test_rpc_auth_async(protocol: str) -> None:
    expected = b"\x00"
    server = None
    username = None
    password = None
    is_ntlm = protocol in ["negotiate-ntlm", "ntlm"]
    if protocol == "negotiate-ntlm":
        server = DC_IP
        protocol = "negotiate"

    if os.name != "nt" and is_ntlm:
        username = USER_UPN
        password = PASSWORD

    actual = await dpapi_ng.async_ncrypt_unprotect_secret(
        BLOB_USER,
        server,
        username=username,
        password=password,
        auth_protocol=protocol,
    )
    assert actual == expected
