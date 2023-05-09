import uuid

import dpapi_ng

cache = dpapi_ng.KeyCache()
cache.load_key(
    b"...",
    uuid.UUID("76ec8b2d-d444-4f67-9db7-2f62b4358b35"),
    version=1,
    kdf_algorithm="SP800_108_CTR_HMAC",
    kdf_parameters=b"...",
    secret_algorithm="DH",
    secret_parameters=b"...",
    private_key_length=512,
    public_key_length=2048,
)

dpapi_ng.ncrypt_unprotect_secret(b"...", cache=cache)
