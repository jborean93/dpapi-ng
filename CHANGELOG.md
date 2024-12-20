# Changelog

## 0.3.0 - TBD

+ Dropped end of life Python versions 3.7, and 3.8
+ Added explicit support for Python 3.12, and 3.13
+ Added mininum version for the `cryptography` dep at `>= 3.4.4`

## 0.2.0 - 2023-06-02

+ Added functions to encrypt data using DPAPI-NG:
    + `async_ncrypt_protect_secret`
    + `ncrypt_protect_secret`
+ Fixed packing of DH and ECDH key structures with small integer values

## 0.1.1 - 2023-05-16

+ Fix up RPC stub data unpacking with no padding data - https://github.com/jborean93/dpapi-ng/issues/2

## 0.1.0 - 2023-05-09

Initial release of `dpapi-ng`
