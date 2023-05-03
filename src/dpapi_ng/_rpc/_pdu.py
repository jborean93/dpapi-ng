# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t


class IntegerRep(enum.IntEnum):
    BIG_ENDIAN = 0
    LITTLE_ENDIAN = 1


class CharacterRep(enum.IntEnum):
    ASCII = 0
    EBCDIC = 1


class FloatingPointRep(enum.IntEnum):
    IEEE = 0
    VAX = 1
    CRAY = 2
    IBM = 3


class PacketType(enum.IntEnum):
    REQUEST = 0
    PING = 1
    RESPONSE = 2
    FAULT = 3
    WORKING = 4
    NOCALL = 5
    REJECT = 6
    ACK = 7
    CL_CANCEL = 8
    FACK = 9
    CANCEL_ACK = 10
    BIND = 11
    BIND_ACK = 12
    BIND_NAK = 13
    ALTER_CONTEXT = 14
    ALTER_CONTEXT_RESP = 15
    SHUTDOWN = 17
    CO_CANCEL = 18
    ORPHANED = 19


class PacketFlags(enum.IntFlag):
    NONE = 0x00
    PFC_FIRST_FRAG = 0x01
    PFC_LAST_FRAG = 0x02
    PFC_PENDING_CANCEL = 0x04
    PFC_SUPPORT_HEADER_SIGN = 0x04  # MS-RPCE extension used in Bind/AlterContext
    PFC_RESERVED_1 = 0x08
    PFC_CONC_MPX = 0x10
    PFC_DID_NOT_EXECUTE = 0x20
    PFC_MAYBE = 0x40
    PFC_OBJECT_UUID = 0x80


@dataclasses.dataclass(frozen=True)
class DataRep:
    # https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm
    byte_order: IntegerRep = IntegerRep.LITTLE_ENDIAN
    character: CharacterRep = CharacterRep.ASCII
    floating_point: FloatingPointRep = FloatingPointRep.IEEE

    def pack(self) -> bytes:
        first_octet = self.byte_order << 4 | self.character
        return b"".join(
            [
                first_octet.to_bytes(1, byteorder="little"),
                self.floating_point.to_bytes(1, byteorder="little"),
                b"\x00\x00",
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> DataRep:
        view = memoryview(data)

        return cls(
            byte_order=IntegerRep((view[0] & 0b11110000) >> 4),
            character=CharacterRep(view[0] & 0b00001111),
            floating_point=FloatingPointRep(view[1]),
        )


@dataclasses.dataclass(frozen=True)
class PDUHeader:
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    version: int
    version_minor: int
    packet_type: PacketType
    packet_flags: PacketFlags
    data_rep: DataRep
    frag_len: int
    auth_len: int
    call_id: int

    def pack(self) -> bytes:
        return b"".join(
            [
                self.version.to_bytes(1, byteorder="little"),
                self.version_minor.to_bytes(1, byteorder="little"),
                self.packet_type.to_bytes(1, byteorder="little"),
                self.packet_flags.to_bytes(1, byteorder="little"),
                self.data_rep.pack(),
                self.frag_len.to_bytes(2, byteorder="little"),
                self.auth_len.to_bytes(2, byteorder="little"),
                self.call_id.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> PDUHeader:
        view = memoryview(data)

        return cls(
            version=view[0],
            version_minor=view[1],
            packet_type=PacketType(view[2]),
            packet_flags=PacketFlags(view[3]),
            data_rep=DataRep.unpack(view[4:8]),
            frag_len=int.from_bytes(view[8:10], byteorder="little"),
            auth_len=int.from_bytes(view[10:12], byteorder="little"),
            call_id=int.from_bytes(view[12:16], byteorder="little"),
        )


class SecurityProvider(enum.IntEnum):
    RPC_C_AUTHN_NONE = 0x00
    RPC_C_AUTHN_GSS_NEGOTIATE = 0x09
    RPC_C_AUTHN_WINNT = 0x0A
    RPC_C_AUTHN_GSS_SCHANNEL = 0x0E
    RPC_C_AUTHN_GSS_KERBEROS = 0x10
    RPC_C_AUTHN_NETLOGON = 0x44
    RPC_C_AUTHN_DEFAULT = 0xFF


class AuthenticationLevel(enum.IntEnum):
    RPC_C_AUTHN_LEVEL_DEFAULT = 0x00
    RPC_C_AUTHN_LEVEL_NONE = 0x01
    RPC_C_AUTHN_LEVEL_CONNECT = 0x02
    RPC_C_AUTHN_LEVEL_CALL = 0x03
    RPC_C_AUTHN_LEVEL_PKT = 0x04
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 0x05
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 0x06


@dataclasses.dataclass(frozen=True)
class SecTrailer:
    # https://pubs.opengroup.org/onlinepubs/9629399/chap13.htm
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab45c6a5-951a-4096-b805-7347674dc6ab
    type: SecurityProvider
    level: AuthenticationLevel
    pad_length: int
    context_id: int
    auth_value: bytes

    def pack(self) -> bytes:
        return b"".join(
            [
                self.type.to_bytes(1, byteorder="little"),
                self.level.to_bytes(1, byteorder="little"),
                self.pad_length.to_bytes(1, byteorder="little"),
                b"\x00",  # Auth-Rsrvd
                self.context_id.to_bytes(4, byteorder="little"),
                self.auth_value,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> SecTrailer:
        view = memoryview(data)

        return cls(
            type=SecurityProvider(view[0]),
            level=AuthenticationLevel(view[1]),
            pad_length=view[2],
            context_id=int.from_bytes(view[4:8], byteorder="little"),
            auth_value=view[8:].tobytes(),
        )


T = t.TypeVar("T")

_PACKET_TYPE_REGISTRY: t.Dict[PacketType, t.Callable[[memoryview, PDUHeader, t.Optional[SecTrailer]], PDU]] = {}


@dataclasses.dataclass(frozen=True)
class PDU:
    header: PDUHeader
    sec_trailer: t.Optional[SecTrailer]

    def pack(self) -> bytearray:
        raise NotImplementedError()

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> PDU:
        view = memoryview(data)

        header = PDUHeader.unpack(view)
        view = view[16 : header.frag_len]

        sec_trailer = None
        if header.auth_len:
            sec_trailer = SecTrailer.unpack(view[-(header.auth_len + 8) :])
            view = view[: -(header.auth_len + 8)]

        return _PACKET_TYPE_REGISTRY[header.packet_type](
            view,
            header,
            sec_trailer,
        )


def register_pdu(packet_type: PacketType) -> t.Callable[[T], T]:
    def wrap(cls: T) -> T:
        _PACKET_TYPE_REGISTRY[packet_type] = getattr(cls, "_unpack")
        return cls

    return wrap


class FaultFlags(enum.IntFlag):
    NONE = 0x00
    EXTENDED_ERROR_PRESENT = 0x01


@dataclasses.dataclass(frozen=True)
@register_pdu(PacketType.FAULT)
class Fault(PDU):
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    alloc_hint: int
    context_id: int
    cancel_count: int
    status: int
    flags: FaultFlags  # Extension of MS-RPCE
    stub_data: bytes

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                self.header.pack(),
                self.alloc_hint.to_bytes(4, byteorder="little"),
                self.context_id.to_bytes(2, byteorder="little"),
                self.cancel_count.to_bytes(1, byteorder="little"),
                self.flags.to_bytes(1, byteorder="little"),
                self.status.to_bytes(4, byteorder="little"),
                b"\x00\x00\x00\x00",  # alignment padding
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
    ) -> Fault:
        view = memoryview(data)

        return cls(
            header=header,
            sec_trailer=sec_trailer,
            alloc_hint=int.from_bytes(view[:4], byteorder="little"),
            context_id=int.from_bytes(view[4:6], byteorder="little"),
            cancel_count=view[6],
            flags=FaultFlags(view[7]),
            status=int.from_bytes(view[8:12], byteorder="little"),
            stub_data=view[16:].tobytes(),
        )
