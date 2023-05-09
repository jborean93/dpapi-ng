import base64
import uuid

from cryptography.hazmat.primitives import hashes

from dpapi_ng import _crypto as crypto
from dpapi_ng import _gkdi as gkdi

algorithm = hashes.SHA512()
key_id = uuid.UUID("2e1b932a-4e21-ced3-0b7b-8815aff8335d")

# This should be the L1 seed key for (L0, 31, -1)
l1_key = base64.b16decode(
    "60E0A81F93164F5DC3ABE981E1EE54C1A6B9B0EDB6FF8274642758D29BBC66559D11F1871A82A6E3F232C42490D7C41C6AD2B8B189FE2752A88CEC2EA4B2021C"
)
l0 = 361
l1 = 31
l2 = 31
l2_key = b""

while l1 >= 0:
    print(f"({l0}, {l1:<2}, -1) {base64.b16encode(l1_key).decode()}")

    while l2 >= 0:
        if l2 == 31:
            l2_key = crypto.kdf(
                algorithm,
                l1_key,
                gkdi.KDS_SERVICE_LABEL,
                gkdi.compute_kdf_context(key_id, l0, l1, l2),
                64,
            )

        else:
            l2_key = crypto.kdf(
                algorithm,
                l2_key,
                gkdi.KDS_SERVICE_LABEL,
                gkdi.compute_kdf_context(key_id, l0, l1, l2),
                64,
            )

        print(f"({l0}, {l1:<2}, {l2:<2}) {base64.b16encode(l2_key).decode()}")
        l2 -= 1

    l2 = 31
    l1 -= 1
    l1_key = crypto.kdf(
        algorithm,
        l1_key,
        gkdi.KDS_SERVICE_LABEL,
        gkdi.compute_kdf_context(key_id, l0, l1, -1),
        64,
    )
