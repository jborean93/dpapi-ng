# dpapi_ng - Python DPAPI-NG Decryption Library

[![Test workflow](https://github.com/jborean93/dpapi-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/jborean93/dpapi-ng/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/dpapi-ng/branch/main/graph/badge.svg?token=UEA7VoocS5)](https://codecov.io/gh/jborean93/dpapi-ng)
[![PyPI version](https://badge.fury.io/py/dpapi-ng.svg)](https://badge.fury.io/py/dpapi-ng)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/dpapi-ng/blob/main/LICENSE)

Library for [DPAPI NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi), also known as CNG DPAPI, de- and encryption in Python.
It is designed to replicate the behaviour of [NCryptUnprotectSecret](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret) and [NCryptProtectSecret](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret).
This can be used on non-Windows hosts to de-/encrypt DPAPI NG protected secrets, like PFX user protected password, or LAPS encrypted password.
It can either de-/encrypt any DPAPI NG blobs using an offline copy of the domain's root key or by using the credentials of the supplied user to retrieve the required information over RPC.

Currently only these protection descriptors are supported:

|Type|Purpose|
|-|-|
|SID|Only the SID user or members of the SID group can decrypt the secret|

This implements the [MS-GKDI Group Key Distribution Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/943dd4f6-6b80-4a66-8594-80df6d2aad0a).

## Requirements

* CPython 3.7+
* [cryptography](https://pypi.org/project/cryptography/)
* [dnspython >= 2.0.0](https://pypi.org/project/dnspython/)
* [pyspnego >= 0.9.0](https://pypi.org/project/pyspnego/)

## How to Install

To install dpapi-ng with all the basic features, run

```bash
python -m pip install dpapi-ng
```

### Kerberos Authentication

Kerberos authentication support won't be installed by default as it relies on system libraries and a valid compiler to be present.
The krb5 library and compiler can be installed by installing these packages:

```bash
# Debian/Ubuntu
apt-get install gcc python3-dev libkrb5-dev

# Centos/RHEL
yum install gcc python-devel krb5-devel

# Fedora
dnf install gcc python-devel krb5-devel

# Arch Linux
pacman -S gcc krb5
```

Once installed, the Kerberos Python extras can be installed with

```bash
python -m pip install dpapi-ng[kerberos]
```

Kerberos also needs to be configured to talk to the domain but that is outside the scope of this page.

### From Source

```bash
git clone https://github.com/jborean93/dpapi-ng.git
cd dpapi-ng
pip install -e .
```

## Examples

There is both a sync and asyncio API available to de-/encrypt a blob.

```python
import dpapi_ng

# decryption
dpapi_ng_blob = b"..."
decrypted_blob = dpapi_ng.ncrypt_unprotect_secret(dpapi_ng_blob)
# async equivalent to the above
decrypted_blob = await dpapi_ng.async_ncrypt_unprotect_secret(dpapi_ng_blob)

# encryption
blob_bytes = b"..."
target_sid = "S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX"
dpapi_ng_blob = dpapi_ng.ncrypt_protect_secret(blob_bytes, target_sid)
# async equivalent to the above
dpapi_ng_blob = await dpapi_ng.async_ncrypt_protect_secret(blob_bytes, target_sid)
```

To decrypt the blob, the key specified in the blob needs to be retrieved from the domain controller the blob was generated by. To encrypt a blob, the group key of the target SID specified needs to be retrieved.
The domain controller hostname is retrieved through an `SRV` lookup of `_ldap._tcp.dc._msdcs.{domain_name}` or with the value specified in the `server` kwarg.
It will attempt to authenticate with the current user identifier which on Linux will only exist if `kinit` has already been called to retrieve a user's ticket.
Otherwise if no identity is available, the `username` and `password` kwargs can be used to specify a custom user.

The following kwargs can be used for both `ncrypt_unprotect_secret` and `async_ncrypt_unprotect_secret`.

* `server`: Use this server as the RPC target if a key needs to be retrieved
* `username`: The username to authenticate as for the RPC connection
* `password`: The password to authenticate with for the RPC connection
* `auth_protocol`: The authentication protocol (`negotiate`, `kerberos`, `ntlm`) to use for the RPC connection
* `cache`: A cache to store keys retrieved for future operation

It is also possible to decrypt the DPAPI-NG blob by providing the root key stored in the domain.
This can either be retrieved using an offline attack or through an LDAP query if running as a Domain Admin user.
To retrieve the domain root keys using PowerShell the following can be run:

```powershell
$configurationContext = (Get-ADRootDSE).configurationNamingContext
$getParams = @{
    LDAPFilter = '(objectClass=msKds-ProvRootKey)'
    SearchBase = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$configurationContext"
    SearchScope = 'OneLevel'
    Properties = @(
        'cn'
        'msKds-KDFAlgorithmID'
        'msKds-KDFParam'
        'msKds-SecretAgreementAlgorithmID'
        'msKds-SecretAgreementParam'
        'msKds-PrivateKeyLength'
        'msKds-PublicKeyLength'
        'msKds-RootKeyData'
    )
}
Get-ADObject @getParams | ForEach-Object {
    [PSCustomObject]@{
        Version = 1
        RootKeyId = [Guid]::new($_.cn)
        KdfAlgorithm = $_.'msKds-KDFAlgorithmID'
        KdfParameters = [System.Convert]::ToBase64String($_.'msKds-KDFParam')
        SecretAgreementAlgorithm = $_.'msKds-SecretAgreementAlgorithmID'
        SecretAgreementParameters = [System.Convert]::ToBase64String($_.'msKds-SecretAgreementParam')
        PrivateKeyLength = $_.'msKds-PrivateKeyLength'
        PublicKeyLength = $_.'msKds-PublicKeyLength'
        RootKeyData = [System.Convert]::ToBase64String($_.'msKds-RootKeyData')
    }
}
```

The following `ldapsearch` command can be used outside of Windows:

```bash
ldapsearch \
    -b 'CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=domain,DC=test' \
    -s one \
    '(objectClass=msKds-ProvRootKey)' \
    cn \
    msKds-KDFAlgorithmID \
    msKds-KDFParam \
    msKds-SecretAgreementAlgorithmID \
    msKds-SecretAgreementParam \
    msKds-PrivateKeyLength \
    msKds-PublicKeyLength \
    msKds-RootKeyData
```

_Note: ldapsearch will most likely need the -H and user bind information to succeed._

The information retrieved there can be stored in a cache and used for subsequent `ncrypt_unprotect_secret` calls:

```python
import uuid

import dpapi_ng

cache = dpapi_ng.KeyCache()

root_key_id = uuid.UUID("76ec8b2d-d444-4f67-9db7-2f62b4358b35")
cache.load_key(
    b"...",                             # msKds-RootKeydata
    root_key_id,                        # cn
    version=1,
    kdf_algorithm="SP800_108_CTR_HMAC", # msKds-KDFAlgorithmID
    kdf_parameters=b"...",              # msKds-KDFParam
    secret_algorithm="DH",              # mskds-SecretAgreementAlgorithmID
    secret_parameters=b"...",           # msKds-SecretAgreementParam
    private_key_length=512,             # msKds-PrivateKeyLength
    public_key_length=2048,             # msKds-PublicKeyLength
)

dpapi_ng.ncrypt_unprotect_secret(b"...", cache=cache)
```

Currently the `SP800_108_CTR_HMAC` KDF algorithm and `DH`, `ECDH_P256`, and `ECDH_P384` secret agreement algorithms have been tested to work.
The `ECDH_P521` secret agreement algorithm should also work but has been untested as a test environment cannot be created with it right now.

## Special Thanks

I would like to thank the following people (Twitter handles in brackets) for their help on this project:

* Grzegorz Tworek (@0gtweet) and Michał Grzegorzewski for providing more information on the internal BCrypt* API workflow used in DPAPI-NG
* Marc-André Moreau (@awakecoding) for their help with reverse engineering some of the Windows APIs and talking through some theories
* SkelSec (@SkelSec) for help on the RPC calls and being available as a general sounding board for my theories
* Steve Syfuhs (@SteveSyfuhs) for connecting me with some Microsoft engineers to help understand some undocumented logic

Without their patience and knowledge this probably would not have been possible.
