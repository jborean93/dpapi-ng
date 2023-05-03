# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t
import uuid

from ._bind import SyntaxId

EPM = SyntaxId(uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)


class Protocol(enum.IntEnum):
    TP4 = 0x05
    CLNS = 0x06
    TCP = 0x07
    UDP = 0x08
    IP = 0x09
    RPC_CONNECTIONLESS = 0x0A
    RPC_CONNECTION_ORIENTED = 0x0B
    UUID_ID = 0x0D


@dataclasses.dataclass(frozen=True)
class TCPIPTower:
    # https://pubs.opengroup.org/onlinepubs/9629399/apdxl.htm
    service: SyntaxId
    data_rep: SyntaxId
    protocol: Protocol
    port: int
    addr: int

    def pack(self) -> bytes:
        def build_floor(protocol: Protocol, lhs: bytes, rhs: bytes) -> bytes:
            return b"".join(
                [
                    (len(lhs) + 1).to_bytes(2, byteorder="little"),
                    protocol.to_bytes(1, byteorder="little"),
                    lhs,
                    len(rhs).to_bytes(2, byteorder="little"),
                    rhs,
                ]
            )

        floors: t.List[bytes] = [
            build_floor(
                protocol=Protocol.UUID_ID,
                lhs=self.service.uuid.bytes_le + self.service.version.to_bytes(2, byteorder="little"),
                rhs=self.service.version_minor.to_bytes(2, byteorder="little"),
            ),
            build_floor(
                protocol=Protocol.UUID_ID,
                lhs=self.data_rep.uuid.bytes_le + self.data_rep.version.to_bytes(2, byteorder="little"),
                rhs=self.data_rep.version_minor.to_bytes(2, byteorder="little"),
            ),
            build_floor(protocol=self.protocol, lhs=b"", rhs=b"\x00\x00"),
            build_floor(protocol=Protocol.TCP, lhs=b"", rhs=self.port.to_bytes(2, byteorder="big")),
            build_floor(protocol=Protocol.IP, lhs=b"", rhs=self.addr.to_bytes(4, byteorder="big")),
        ]

        return b"".join(
            [
                len(floors).to_bytes(2, byteorder="little"),
                b"".join(floors),
            ]
        )


@dataclasses.dataclass(frozen=True)
class EptMap:
    opnum: int = dataclasses.field(init=False, repr=False, default=3)

    obj: t.Optional[uuid.UUID]
    tower: TCPIPTower
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
        b_tower = self.tower.pack()
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

        def unpack_floor(view: memoryview) -> t.Tuple[int, Protocol, memoryview, memoryview]:
            lhs_len = int.from_bytes(view[:2], byteorder="little")
            proto = Protocol(view[2])
            lhs = view[3 : lhs_len + 2]
            offset = lhs_len + 2

            rhs_len = int.from_bytes(view[offset : offset + 2], byteorder="little")
            rhs = view[offset + 2 : offset + rhs_len + 2]

            return offset + rhs_len + 2, proto, lhs, rhs

        tower_length = int.from_bytes(view[:8], byteorder="little")
        padding = -(tower_length + 4) % 8

        floor_len = int.from_bytes(view[12:14], byteorder="little")
        assert floor_len == 5
        view = view[14:]

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == Protocol.UUID_ID
        service = SyntaxId.unpack(lhs.tobytes() + rhs.tobytes())

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == Protocol.UUID_ID
        data_rep = SyntaxId.unpack(lhs.tobytes() + rhs.tobytes())

        offset, protocol, _, _ = unpack_floor(view)
        view = view[offset:]
        assert protocol == Protocol.RPC_CONNECTION_ORIENTED

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == Protocol.TCP
        port = int.from_bytes(rhs, byteorder="big")

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == Protocol.IP
        addr = int.from_bytes(rhs, byteorder="big")

        tower = TCPIPTower(
            service=service,
            data_rep=data_rep,
            protocol=protocol,
            port=port,
            addr=addr,
        )
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
    towers: t.List[TCPIPTower]
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

            b_t = t.pack()
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

        def unpack_floor(view: memoryview) -> t.Tuple[int, Protocol, memoryview, memoryview]:
            lhs_len = int.from_bytes(view[:2], byteorder="little")
            proto = Protocol(view[2])
            lhs = view[3 : lhs_len + 2]
            offset = lhs_len + 2

            rhs_len = int.from_bytes(view[offset : offset + 2], byteorder="little")
            rhs = view[offset + 2 : offset + rhs_len + 2]

            return offset + rhs_len + 2, proto, lhs, rhs

        towers: t.List[TCPIPTower] = []
        for _ in range(tower_count):
            tower_length = int.from_bytes(view[:8], byteorder="little")
            padding = -(tower_length + 4) % 8

            floor_len = int.from_bytes(view[12:14], byteorder="little")
            assert floor_len == 5
            view = view[14:]

            offset, proto, lhs, rhs = unpack_floor(view)
            view = view[offset:]
            assert proto == Protocol.UUID_ID
            service = SyntaxId.unpack(lhs.tobytes() + rhs.tobytes())

            offset, proto, lhs, rhs = unpack_floor(view)
            view = view[offset:]
            assert proto == Protocol.UUID_ID
            data_rep = SyntaxId.unpack(lhs.tobytes() + rhs.tobytes())

            offset, protocol, _, _ = unpack_floor(view)
            view = view[offset:]
            assert protocol == Protocol.RPC_CONNECTION_ORIENTED

            offset, proto, lhs, rhs = unpack_floor(view)
            view = view[offset:]
            assert proto == Protocol.TCP
            port = int.from_bytes(rhs, byteorder="big")

            offset, proto, lhs, rhs = unpack_floor(view)
            view = view[offset:]
            assert proto == Protocol.IP
            addr = int.from_bytes(rhs, byteorder="big")

            towers.append(
                TCPIPTower(
                    service=service,
                    data_rep=data_rep,
                    protocol=protocol,
                    port=port,
                    addr=addr,
                )
            )
            view = view[padding:]

        return cls(
            entry_handle=entry_handle,
            towers=towers,
            status=status,
        )
