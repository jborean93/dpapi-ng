# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t
import uuid

from ._bind import SyntaxId

ISD_KEY = SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)


@dataclasses.dataclass
class GetKeyRequest:
    opnum: int = dataclasses.field(init=False, repr=False, default=0)

    target_sd: bytes
    root_key_id: t.Optional[uuid.UUID] = None
    l0_key_id: int = -1
    l1_key_id: int = -1
    l2_key_id: int = -1

    # MS-GKDI 3.1.4.1 GetKey (Opnum 0)
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39
    # HRESULT GetKey(
    #     [in] handle_t hBinding,
    #     [in] ULONG cbTargetSD,
    #     [in] [size_is(cbTargetSD)] [ref] char* pbTargetSD,
    #     [in] [unique] GUID* pRootKeyID,
    #     [in] LONG L0KeyID,
    #     [in] LONG L1KeyID,
    #     [in] LONG L2KeyID,
    #     [out] unsigned long* pcbOut,
    #     [out] [size_is(, *pcbOut)] byte** ppbOut);

    def pack(self) -> bytes:
        # Strictly speaking it is only 4 bytes but NDR64 needs 8 byte alignment
        # on the field after.
        target_sd_len = len(self.target_sd).to_bytes(8, byteorder="little")

        return b"".join(
            [
                # cbTargetSD
                target_sd_len,
                # pbTargetSD - pointer header includes the length + padding
                target_sd_len,
                self.target_sd,
                b"\x00" * (-len(self.target_sd) % 8),
                # pRootKeyID - includes referent id
                b"\x00\x00\x02\x00\x00\x00\x00\x00",
                self.root_key_id.bytes_le if self.root_key_id else b"\x00" * 16,
                # L0KeyID
                self.l0_key_id.to_bytes(4, byteorder="little", signed=True),
                # L1KeyID
                self.l1_key_id.to_bytes(4, byteorder="little", signed=True),
                # L2KeyID
                self.l2_key_id.to_bytes(4, byteorder="little", signed=True),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> GetKeyRequest:
        view = memoryview(data)

        target_sd_len = int.from_bytes(view[:4], byteorder="little")
        target_sd = view[16 : 16 + target_sd_len].tobytes()
        padding = -target_sd_len % 8

        view = view[24 + target_sd_len + padding :]
        root_key_id = uuid.UUID(bytes_le=view[:16].tobytes())
        l0_key_id = int.from_bytes(view[16:20], byteorder="little", signed=True)
        l1_key_id = int.from_bytes(view[20:24], byteorder="little", signed=True)
        l2_key_id = int.from_bytes(view[24:28], byteorder="little", signed=True)

        return GetKeyRequest(
            target_sd=target_sd,
            root_key_id=root_key_id,
            l0_key_id=l0_key_id,
            l1_key_id=l1_key_id,
            l2_key_id=l2_key_id,
        )
