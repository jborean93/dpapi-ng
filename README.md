# dpapi_ng - Python DPAPI-NG Decryption Library

[![Test workflow](https://github.com/jborean93/dpapi-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/jborean93/dpapi-ng/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/dpapi-ng/branch/main/graph/badge.svg?token=UEA7VoocS5)](https://codecov.io/gh/jborean93/dpapi-ng)
[![PyPI version](https://badge.fury.io/py/dpapi-ng.svg)](https://badge.fury.io/py/dpapi-ng)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/dpapi-ng/blob/main/LICENSE)

Library for [DPAPI NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi), also known as CNG DPAPI, decryption in Python.
This can be used on non-Windows hosts to decrypt DPAPI NG protected secrets, like PFX user protected password, or LAPS encrypted password.
It can either decrypt any DPAPI NG blobs using an offline copy of the domain's root key or by using the credentials of the supplied user to retrieve the required information over RPC.

## Requirements

* CPython 3.7+

## Examples

TODO: This.

## Install

### From PyPI

```bash
pip install dpapi-ng
```

### From Source

```bash
git clone https://github.com/jborean93/dpapi-ng.git
cd dpapi-ng
pip install -e .
```
