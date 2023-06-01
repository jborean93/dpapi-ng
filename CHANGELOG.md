# Changelog

## 0.2.0 - TBD

+ Added functions to encrypt data using DPAPI-NG:
    + `async_ncrypt_protect_secret`
    + `ncrypt_protect_secret`
+ Fixed packing of DH and ECDH key structures with small integer values

## 0.1.1 - 2023-05-16

+ Fix up RPC stub data unpacking with no padding data - https://github.com/jborean93/dpapi-ng/issues/2

## 0.1.0 - 2023-05-09

Initial release of `dpapi-ng`
