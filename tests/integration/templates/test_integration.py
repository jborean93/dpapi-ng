# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import socket
import typing as t

import psrp
import pytest

import dpapi_ng

DOMAIN_REALM = "{{ domain_name }}"
DC_FQDN = f"dc01.{DOMAIN_REALM}"
DC_IP = socket.gethostbyname(DC_FQDN)
USERNAME1 = "{{ domain_username | lower }}"
USERNAME2 = "{{ domain_username2 | lower }}"
PASSWORD = "{{ domain_password }}"
USER_UPN = f"{USERNAME1}@{DOMAIN_REALM.upper()}"

GET_SID_SCRIPT = r"""[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $UserName
)

([System.Security.Principal.NTAccount]$UserName).Translate([System.Security.Principal.SecurityIdentifier]).Value
"""

ENCRYPT_SCRIPT = r"""[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $ProtectionDescriptor,

    [Parameter(Mandatory)]
    [byte[]]
    $InputObject
)

$ErrorActionPreference = 'Stop'

# Ensure we remove any cached key so the latest KDS root is selected
$cryptoKeysPath = "$env:LOCALAPPDATA\Microsoft\Crypto\KdsKey"
if (Test-Path -LiteralPath $cryptoKeysPath) {
    Get-ChildItem -LiteralPath $cryptoKeysPath | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
}

[byte[]]$res = . "C:\temp\ConvertTo-DpapiNgBlob.ps1" -ProtectionDescriptor $ProtectionDescriptor -InputObject $InputObject
, $res
"""

DECRYPT_SCRIPT = r"""[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [byte[]]
    $InputObject
)

$ErrorActionPreference = 'Stop'

[byte[]]$res = . "C:\temp\ConvertFrom-DpapiNgBlob.ps1" -InputObject $InputObject
, $res
"""

wsman = psrp.WSManInfo(DC_FQDN)
with psrp.SyncRunspacePool(wsman) as rp:
    ps = psrp.SyncPowerShell(rp)
    ps.add_script(GET_SID_SCRIPT).add_parameter("UserName", USERNAME1)
    USERNAME1_SID = ps.invoke()[0]

    ps = psrp.SyncPowerShell(rp)
    ps.add_script(GET_SID_SCRIPT).add_parameter("UserName", USERNAME2)
    USERNAME2_SID = ps.invoke()[0]


def test_decrypt_sync_with_nonce() -> None:
    data = os.urandom(64)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME1, password=PASSWORD)
    with psrp.SyncRunspacePool(wsman) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script(ENCRYPT_SCRIPT).add_parameters(
            ProtectionDescriptor=f"SID={USERNAME1_SID}",
            InputObject=data,
        )
        enc_blob = ps.invoke()[0]

    actual = dpapi_ng.ncrypt_unprotect_secret(enc_blob)
    assert actual == data


@pytest.mark.asyncio
async def test_decrypt_async_with_nonce() -> None:
    data = os.urandom(64)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME1, password=PASSWORD)
    async with psrp.AsyncRunspacePool(wsman) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(ENCRYPT_SCRIPT).add_parameters(
            ProtectionDescriptor=f"SID={USERNAME1_SID}",
            InputObject=data,
        )
        enc_blob = (await ps.invoke())[0]

    actual = await dpapi_ng.async_ncrypt_unprotect_secret(enc_blob)
    assert actual == data


def test_decrypt_sync_with_public_key() -> None:
    data = os.urandom(64)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME2, password=PASSWORD)
    with psrp.SyncRunspacePool(wsman) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script(ENCRYPT_SCRIPT).add_parameters(
            ProtectionDescriptor=f"SID={USERNAME1_SID}",
            InputObject=data,
        )
        enc_blob = ps.invoke()[0]

    actual = dpapi_ng.ncrypt_unprotect_secret(enc_blob)
    assert actual == data


@pytest.mark.asyncio
async def test_decrypt_async_with_public_key() -> None:
    data = os.urandom(64)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME2, password=PASSWORD)
    async with psrp.AsyncRunspacePool(wsman) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(ENCRYPT_SCRIPT).add_parameters(
            ProtectionDescriptor=f"SID={USERNAME1_SID}",
            InputObject=data,
        )
        enc_blob = (await ps.invoke())[0]

    actual = dpapi_ng.ncrypt_unprotect_secret(enc_blob)
    assert actual == data


def test_encrypt_sync_as_authorised_user() -> None:
    data = os.urandom(64)

    kwargs: t.Dict[str, t.Any] = {}
    if os.name != "nt":
        kwargs["domain_name"] = DOMAIN_REALM

    blob = dpapi_ng.ncrypt_protect_secret(data, USERNAME1_SID, **kwargs)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME1, password=PASSWORD)
    with psrp.SyncRunspacePool(wsman) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script(DECRYPT_SCRIPT).add_argument(blob)
        actual = ps.invoke()

        assert not ps.had_errors
        assert actual == [data]


@pytest.mark.asyncio
async def test_encrypt_async_as_authorised_user() -> None:
    data = os.urandom(64)

    kwargs: t.Dict[str, t.Any] = {}
    if os.name != "nt":
        kwargs["domain_name"] = DOMAIN_REALM

    blob = dpapi_ng.ncrypt_protect_secret(data, USERNAME1_SID, **kwargs)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME1, password=PASSWORD)
    async with psrp.AsyncRunspacePool(wsman) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(DECRYPT_SCRIPT).add_argument(blob)
        actual = await ps.invoke()

        assert not ps.had_errors
        assert actual == [data]


def test_encrypt_sync_as_unauthorised_user() -> None:
    data = os.urandom(64)

    kwargs: t.Dict[str, t.Any] = {}
    if os.name != "nt":
        kwargs["domain_name"] = DOMAIN_REALM

    blob = dpapi_ng.ncrypt_protect_secret(data, USERNAME2_SID, **kwargs)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME2, password=PASSWORD)
    with psrp.SyncRunspacePool(wsman) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script(DECRYPT_SCRIPT).add_argument(blob)
        actual = ps.invoke()

        assert not ps.had_errors
        assert actual == [data]


@pytest.mark.asyncio
async def test_encrypt_async_as_unauthorised_user() -> None:
    data = os.urandom(64)

    kwargs: t.Dict[str, t.Any] = {}
    if os.name != "nt":
        kwargs["domain_name"] = DOMAIN_REALM

    blob = dpapi_ng.ncrypt_protect_secret(data, USERNAME2_SID, **kwargs)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME2, password=PASSWORD)
    async with psrp.AsyncRunspacePool(wsman) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(DECRYPT_SCRIPT).add_argument(blob)
        actual = await ps.invoke()

        assert not ps.had_errors
        assert actual == [data]


@pytest.mark.parametrize("protocol", ["negotiate", "negotiate-ntlm", "kerberos", "ntlm"])
def test_rpc_auth(protocol: str) -> None:
    data = os.urandom(64)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME1, password=PASSWORD)
    with psrp.SyncRunspacePool(wsman) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script(ENCRYPT_SCRIPT).add_parameters(
            ProtectionDescriptor=f"SID={USERNAME1_SID}",
            InputObject=data,
        )
        enc_blob = ps.invoke()[0]

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
        enc_blob,
        server,
        username=username,
        password=password,
        auth_protocol=protocol,
    )
    assert actual == data


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["negotiate", "negotiate-ntlm", "kerberos", "ntlm"])
async def test_rpc_auth_async(protocol: str) -> None:
    data = os.urandom(64)

    wsman = psrp.WSManInfo(DC_FQDN, auth="credssp", username=USERNAME1, password=PASSWORD)
    async with psrp.AsyncRunspacePool(wsman) as rp:
        ps = psrp.AsyncPowerShell(rp)
        ps.add_script(ENCRYPT_SCRIPT).add_parameters(
            ProtectionDescriptor=f"SID={USERNAME1_SID}",
            InputObject=data,
        )
        enc_blob = (await ps.invoke())[0]

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
        enc_blob,
        server,
        username=username,
        password=password,
        auth_protocol=protocol,
    )
    assert actual == data
