# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t
import uuid

from ._bind import SyntaxId

EPM = SyntaxId(uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)

# https://pubs.opengroup.org/onlinepubs/9629399/apdxl.htm
# https://pubs.opengroup.org/onlinepubs/9629399/apdxi.htm#tagcjh_28


class Protocol(enum.IntEnum):
    OSI = 0x00
    DNA_SESSION_CONTROL = 0x02
    DNA_SESSION_CONTROL_V3 = 0x03
    DNA_NSP_TRANSPORT = 0x04
    TP4 = 0x05
    CLNS = 0x06
    TCP = 0x07
    UDP = 0x08
    IP = 0x09
    RPC_CONNECTIONLESS = 0x0A
    RPC_CONNECTION_ORIENTED = 0x0B
    UUID_ID = 0x0D
    NAMED_PIPES = 0x10
    NETBIOS = 0x11
    NETBEUI = 0x12
    NETWARE_SPX = 0x13
    NETWARE_IPX = 0x14
    APPLETALK_STREAM = 0x16
    APPLETALK_DATARAM = 0x17
    APPLETALK = 0x18
    NETBIOS2 = 0x19
    VINES_SPP = 0x1A
    VINES_IPC = 0x1B
    STREET_TALK = 0x1C
    UNIX_DOMAIN_SOCKET = 0x20
    NULL = 0x21
    NETBIOS3 = 0x22


@dataclasses.dataclass(frozen=True)
class Floor:
    protocol: Protocol
    lhs: bytes
    rhs: bytes

    def pack(self) -> bytes:
        return b"".join(
            [
                (len(self.lhs) + 1).to_bytes(2, byteorder="little"),
                self.protocol.to_bytes(1, byteorder="little"),
                self.lhs,
                len(self.rhs).to_bytes(2, byteorder="little"),
                self.rhs,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> Floor:
        view = memoryview(data)

        lhs_len = int.from_bytes(view[:2], byteorder="little")
        proto = Protocol(view[2])
        lhs = view[3 : lhs_len + 2].tobytes()
        offset = lhs_len + 2

        rhs_len = int.from_bytes(view[offset : offset + 2], byteorder="little")
        rhs = view[offset + 2 : offset + rhs_len + 2].tobytes()

        unpack_func = _FLOOR_TYPE_REGISTRY.get(proto, None)
        if unpack_func:
            floor = unpack_func(lhs, rhs)
            object.__setattr__(floor, "lhs", lhs)
            object.__setattr__(floor, "rhs", rhs)
            return floor

        else:
            return cls(protocol=proto, lhs=lhs, rhs=rhs)


T = t.TypeVar("T")
_FLOOR_TYPE_REGISTRY: t.Dict[Protocol, t.Callable[[bytes, bytes], Floor]] = {}


def register_floor(cls: T) -> T:
    _FLOOR_TYPE_REGISTRY[getattr(cls, "protocol").default] = getattr(cls, "_unpack")
    return cls


@dataclasses.dataclass(frozen=True)
class _KnownFloor(Floor):
    lhs: bytes = dataclasses.field(init=False, repr=False, default=b"")
    rhs: bytes = dataclasses.field(init=False, repr=False, default=b"")


@dataclasses.dataclass(frozen=True)
@register_floor
class TCPFloor(_KnownFloor):
    protocol: Protocol = dataclasses.field(init=False, default=Protocol.TCP)
    port: int

    def pack(self) -> bytes:
        return Floor(self.protocol, b"", self.port.to_bytes(2, byteorder="big")).pack()

    @classmethod
    def _unpack(
        cls,
        lhs: bytes,
        rhs: bytes,
    ) -> TCPFloor:
        return TCPFloor(int.from_bytes(rhs, byteorder="big"))


@dataclasses.dataclass(frozen=True)
@register_floor
class IPFloor(_KnownFloor):
    protocol: Protocol = dataclasses.field(init=False, default=Protocol.IP)
    addr: int

    def pack(self) -> bytes:
        return Floor(self.protocol, b"", self.addr.to_bytes(2, byteorder="big")).pack()

    @classmethod
    def _unpack(
        cls,
        lhs: bytes,
        rhs: bytes,
    ) -> IPFloor:
        return IPFloor(int.from_bytes(rhs, byteorder="big"))


@dataclasses.dataclass(frozen=True)
@register_floor
class RPCConnectionOrientedFloor(_KnownFloor):
    protocol: Protocol = dataclasses.field(init=False, default=Protocol.RPC_CONNECTION_ORIENTED)
    version_minor: int

    def pack(self) -> bytes:
        return Floor(self.protocol, b"", self.version_minor.to_bytes(2, byteorder="little")).pack()

    @classmethod
    def _unpack(
        cls,
        lhs: bytes,
        rhs: bytes,
    ) -> RPCConnectionOrientedFloor:
        return RPCConnectionOrientedFloor(int.from_bytes(rhs, byteorder="little"))


@dataclasses.dataclass(frozen=True)
@register_floor
class UUIDFloor(_KnownFloor):
    protocol: Protocol = dataclasses.field(init=False, default=Protocol.UUID_ID)
    uuid: uuid.UUID
    version: int
    version_minor: int

    def pack(self) -> bytes:
        return Floor(
            protocol=self.protocol,
            lhs=self.uuid.bytes_le + self.version.to_bytes(2, byteorder="little"),
            rhs=self.version_minor.to_bytes(2, byteorder="little"),
        ).pack()

    @classmethod
    def _unpack(
        cls,
        lhs: bytes,
        rhs: bytes,
    ) -> UUIDFloor:
        object_uuid = uuid.UUID(bytes_le=lhs[:16])
        version = int.from_bytes(lhs[16:18], byteorder="little")
        version_minor = int.from_bytes(rhs, byteorder="little")

        return UUIDFloor(object_uuid, version, version_minor)


def build_tcpip_tower(
    service: SyntaxId,
    data_rep: SyntaxId,
    port: int,
    addr: int,
) -> t.List[Floor]:
    return [
        UUIDFloor(service.uuid, service.version, service.version_minor),
        UUIDFloor(data_rep.uuid, data_rep.version, data_rep.version_minor),
        RPCConnectionOrientedFloor(0),
        TCPFloor(port),
        IPFloor(addr),
    ]


@dataclasses.dataclass(frozen=True)
class EptMap:
    opnum: int = dataclasses.field(init=False, repr=False, default=3)

    obj: t.Optional[uuid.UUID]
    tower: t.List[Floor]
    entry_handle: t.Optional[tuple[int, uuid.UUID]]
    max_towers: int

    # MS-RPCE 2.2.1.2.5 ept_map Method
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab744583-430e-4055-8901-3c6bc007e791
    # void ept_map(
    #     [in] handle_t hEpMapper,
    #     [in, ptr] UUID* obj,
    #     [in, ptr] twr_p_t map_tower,
    #     [in, out] ept_lookup_handle_t* entry_handle,
    #     [in, range(0,500)] unsigned long max_towers,
    #     [out] unsigned long* num_towers,
    #     [out, ptr, size_is(max_towers), length_is(*num_towers)]
    #         twr_p_t* ITowers,
    #     [out] error_status* status
    # );

    def pack(self) -> bytes:
        b_tower = b"".join(
            [
                len(self.tower).to_bytes(2, byteorder="little"),
                b"".join(f.pack() for f in self.tower),
            ]
        )
        tower_padding = -(len(b_tower) + 4) % 8

        if self.entry_handle:
            b_entry_handle = self.entry_handle[0].to_bytes(4, byteorder="little") + self.entry_handle[1].bytes_le
        else:
            b_entry_handle = b"\x00" * 20

        return b"".join(
            [
                # obj with a referent id of 1
                b"\x01\x00\x00\x00\x00\x00\x00\x00",
                self.obj.bytes_le if self.obj else b"\x00" * 16,
                # Tower referent id 2
                b"\x02\x00\x00\x00\x00\x00\x00\x00",
                len(b_tower).to_bytes(8, byteorder="little"),
                len(b_tower).to_bytes(4, byteorder="little"),
                b_tower,
                b"\x00" * tower_padding,
                b_entry_handle,
                self.max_towers.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EptMap:
        view = memoryview(data)

        b_obj = view[8:24].tobytes()
        if b_obj == b"\x00" * 16:
            obj = None
        else:
            obj = uuid.UUID(bytes_le=b_obj)

        view = view[32:]

        tower_length = int.from_bytes(view[:8], byteorder="little")
        padding = -(tower_length + 4) % 8

        floor_len = int.from_bytes(view[12:14], byteorder="little")
        assert floor_len == 5
        view = view[14:]

        tower = []
        for _ in range(floor_len):
            floor = Floor.unpack(view)
            view = view[len(floor.lhs) + len(floor.rhs) + 5 :]
            tower.append(floor)

        view = view[padding:]

        b_entry_handle = view[:20].tobytes()
        if b_entry_handle == b"\x00" * 20:
            entry_handle = None
        else:
            entry_handle = (
                int.from_bytes(view[:4], byteorder="little"),
                uuid.UUID(bytes_le=view[4:20].tobytes()),
            )

        max_towers = int.from_bytes(view[20:24], byteorder="little")

        return cls(
            obj=obj,
            tower=tower,
            entry_handle=entry_handle,
            max_towers=max_towers,
        )


@dataclasses.dataclass(frozen=True)
class EptMapResult:
    entry_handle: t.Optional[tuple[int, uuid.UUID]]
    towers: t.List[t.List[Floor]]
    status: int

    def pack(self) -> bytes:
        if self.entry_handle:
            b_entry_handle = self.entry_handle[0].to_bytes(4, byteorder="little") + self.entry_handle[1].bytes_le
        else:
            b_entry_handle = b"\x00" * 20

        b_tower_referents = bytearray()
        b_tower = bytearray()
        for idx, t in enumerate(self.towers):
            b_tower_referents += (idx + 3).to_bytes(8, byteorder="little")

            b_t = b"".join(
                [
                    len(t).to_bytes(2, byteorder="little"),
                    b"".join(f.pack() for f in t),
                ]
            )
            padding = -(len(b_t)) % 4
            b_tower += b"".join(
                [
                    len(b_t).to_bytes(8, byteorder="little"),
                    len(b_t).to_bytes(4, byteorder="little"),
                    b_t,
                    b"\x00" * padding,
                ]
            )

        return b"".join(
            [
                b_entry_handle,
                len(self.towers).to_bytes(4, byteorder="little"),
                len(self.towers).to_bytes(8, byteorder="little"),
                b"\x00" * 8,  # Tower pointer offset
                len(self.towers).to_bytes(8, byteorder="little"),
                b_tower_referents,
                b_tower,
                self.status.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EptMapResult:
        view = memoryview(data)

        status = int.from_bytes(view[-4:], byteorder="little")
        b_entry_handle = view[:20].tobytes()
        if b_entry_handle == b"\x00" * 20:
            entry_handle = None
        else:
            entry_handle = (
                int.from_bytes(view[:4], byteorder="little"),
                uuid.UUID(bytes_le=view[4:20].tobytes()),
            )

        # num_towers = int.from_bytes(view[20:24], byteorder="little")
        # max_tower_count = int.from_bytes(view[24:32], byteorder="little")
        # tower_offset = int.from_bytes(view[32:40], byteorder="little")
        tower_count = int.from_bytes(view[40:48], byteorder="little")
        tower_data_offset = 8 * tower_count  # Ignore referent ids
        view = view[48 + tower_data_offset :]

        towers: t.List[t.List[Floor]] = []
        for _ in range(tower_count):
            tower_length = int.from_bytes(view[:8], byteorder="little")
            padding = -(tower_length + 4) % 8

            floor_len = int.from_bytes(view[12:14], byteorder="little")
            assert floor_len == 5
            view = view[14:]

            tower = []
            for _ in range(floor_len):
                floor = Floor.unpack(view)
                view = view[len(floor.lhs) + len(floor.rhs) + 5 :]
                tower.append(floor)

            towers.append(tower)
            view = view[padding:]

        return cls(
            entry_handle=entry_handle,
            towers=towers,
            status=status,
        )
