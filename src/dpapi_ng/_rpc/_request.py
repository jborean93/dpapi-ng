# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t
import uuid

from ._pdu import PDU, PacketFlags, PacketType, PDUHeader, SecTrailer, register_pdu


@dataclasses.dataclass(frozen=True)
@register_pdu(PacketType.REQUEST)
class Request(PDU):
    alloc_hint: int
    context_id: int
    opnum: int
    obj: t.Optional[uuid.UUID]
    stub_data: bytes

    def pack(self) -> bytes:
        return b"".join(
            [
                self.header.pack(),
                self.alloc_hint.to_bytes(4, byteorder="little"),
                self.context_id.to_bytes(2, byteorder="little"),
                self.opnum.to_bytes(2, byteorder="little"),
                self.obj.bytes_le if self.obj else b"",
                self.stub_data,
                self.sec_trailer.pack() if self.sec_trailer else b"",
            ]
        )

    @classmethod
    def _unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        header: PDUHeader,
        sec_trailer: t.Optional[SecTrailer],
    ) -> Request:
        view = memoryview(data)

        alloc_hint = int.from_bytes(view[:4], byteorder="little")
        context_id = int.from_bytes(view[4:6], byteorder="little")
        opnum = int.from_bytes(view[6:8], byteorder="little")

        view = view[8:]
        obj = None
        if header.packet_flags & PacketFlags.PFC_OBJECT_UUID:
            obj = uuid.UUID(bytes_le=view[:16].tobytes())
            view = view[16:]

        return cls(
            header=header,
            sec_trailer=sec_trailer,
            alloc_hint=alloc_hint,
            context_id=context_id,
            opnum=opnum,
            obj=obj,
            stub_data=view.tobytes(),
        )


@dataclasses.dataclass(frozen=True)
@register_pdu(PacketType.RESPONSE)
class Response(PDU):
    alloc_hint: int
    context_id: int
    cancel_count: int
    stub_data: bytes

    def pack(self) -> bytes:
        return b"".join(
            [
                self.header.pack(),
                self.alloc_hint.to_bytes(4, byteorder="little"),
                self.context_id.to_bytes(2, byteorder="little"),
                self.cancel_count.to_bytes(1, byteorder="little"),
                b"\x00",  # reserved
                self.stub_data,
                self.sec_trailer.pack() if self.sec_trailer else b"",
            ]
        )

    @classmethod
    def _unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        header: PDUHeader,
        sec_trailer: t.Optional[SecTrailer],
    ) -> Response:
        view = memoryview(data)

        return cls(
            header=header,
            sec_trailer=sec_trailer,
            alloc_hint=int.from_bytes(view[:4], byteorder="little"),
            context_id=int.from_bytes(view[4:6], byteorder="little"),
            cancel_count=view[6],
            stub_data=view[8:].tobytes(),
        )
