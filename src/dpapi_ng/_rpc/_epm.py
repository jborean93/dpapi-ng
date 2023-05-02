# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import struct
import typing as t
import uuid

EPM_ID = (uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)


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
class Tower:
    service: t.Tuple[uuid.UUID, int, int]
    data_rep: t.Tuple[uuid.UUID, int, int]
    protocol: Protocol

    def pack(self) -> bytes:
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class TCPIPTower(Tower):
    protocol: Protocol = dataclasses.field(init=False, default=Protocol.TCP)
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
                lhs=self.service[0].bytes_le + self.service[1].to_bytes(2, byteorder="little"),
                rhs=self.service[2].to_bytes(2, byteorder="little"),
            ),
            build_floor(
                protocol=Protocol.UUID_ID,
                lhs=self.data_rep[0].bytes_le + self.data_rep[1].to_bytes(2, byteorder="little"),
                rhs=self.data_rep[2].to_bytes(2, byteorder="little"),
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

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> TCPIPTower:
        view = memoryview(data)

        raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class EptMap:
    opnum: int = dataclasses.field(init=False, repr=False, default=3)

    obj: t.Optional[uuid.UUID]
    tower: Tower
    entry_handle: t.Optional[bytes]
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

        # TODO: Figure out context handle value

        return b"".join(
            [
                # obj with a referent id of 1
                b"\x01\x00\x00\x00\x00\x00\x00\x00",
                self.obj.bytes_le if self.obj else b"\x00" * 16,
                # Tower referent id 2
                b"\x02\x00\x00\x00\x00\x00x\00x\00",
                len(b_tower).to_bytes(8, byteorder="little"),
                len(b_tower).to_bytes(4, byteorder="little"),
                b_tower,
                b"\x00" * tower_padding,
                b"\x00" * 20,  # Context handle
                self.max_towers.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EptMap:
        view = memoryview(data)

        raise NotImplementedError()

    @classmethod
    def unpack_response(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> t.List[Tower]:
        view = memoryview(data)

        error_status = int.from_bytes(view[-4:], byteorder="little")
        if error_status != 0:
            raise ValueError(f"Received non 0 error status on response 0x{error_status:08X}")

        # entry_handle = view[:20].tobytes()
        num_towers = int.from_bytes(view[20:24], byteorder="little")
        tower_count = int.from_bytes(view[40:48], byteorder="little")
        tower_data_offset = 8 * tower_count  # Ignore referent ids
        view = view[48 + tower_data_offset :]
        towers: t.List[Tower] = []

        return towers

        def unpack_floor(view: memoryview) -> t.Tuple[int, int, memoryview, memoryview]:
            lhs_len = struct.unpack("<H", view[:2])[0]
            proto = view[2]
            lhs = view[3 : lhs_len + 2]
            offset = lhs_len + 2

            rhs_len = struct.unpack("<H", view[offset : offset + 2])[0]
            rhs = view[offset + 2 : offset + rhs_len + 2]

            return offset + rhs_len + 2, proto, lhs, rhs

        return_code = struct.unpack("<I", view[-4:])[0]
        assert return_code == 0
        num_towers = struct.unpack("<I", view[20:24])[0]
        # tower_max_count = struct.unpack("<Q", view[24:32])[0]
        # tower_offset = struct.unpack("<Q", view[32:40])[0]
        tower_count = struct.unpack("<Q", view[40:48])[0]

        tower_data_offset = 8 * tower_count  # Ignore referent ids
        view = view[48 + tower_data_offset :]
        towers: t.List[TCPIPTower] = []
        for _ in range(tower_count):
            tower_length = struct.unpack("<Q", view[:8])[0]
            padding = -(tower_length + 4) % 8
            floor_len = struct.unpack("<H", view[12:14])[0]
            assert floor_len == 5
            view = view[14:]

            offset, proto, lhs, rhs = unpack_floor(view)
            view = view[offset:]
            assert proto == 0x0D
            service = (
                uuid.UUID(bytes_le=lhs[:16].tobytes()),
                struct.unpack("<H", lhs[16:])[0],
                struct.unpack("<H", rhs)[0],
            )

            offset, proto, lhs, rhs = unpack_floor(view)
            view = view[offset:]
            assert proto == 0x0D
            data_rep = (
                uuid.UUID(bytes_le=lhs[:16].tobytes()),
                struct.unpack("<H", lhs[16:])[0],
                struct.unpack("<H", rhs)[0],
            )

            offset, protocol, _, _ = unpack_floor(view)
            view = view[offset:]
            assert protocol == 0x0B

            offset, proto, lhs, rhs = unpack_floor(view)
            view = view[offset:]
            assert proto == 0x07
            port = struct.unpack(">H", rhs)[0]

            offset, proto, lhs, rhs = unpack_floor(view)
            view = view[offset:]
            assert proto == 0x09
            addr = struct.unpack(">I", rhs)[0]

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

        assert len(towers) == num_towers

        return towers
