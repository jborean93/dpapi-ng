# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import uuid

import dpapi_ng._rpc as rpc
from dpapi_ng import _epm as epm


def test_ept_map_pack() -> None:
    expected = (
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\x00\x87\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x04\x00\x00\x00"
    )
    service = rpc.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
    data_rep = rpc.SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)

    msg = epm.EptMap(
        obj=None,
        tower=epm.build_tcpip_tower(service, data_rep, 135, 0),
        entry_handle=None,
        max_towers=4,
    )
    actual = msg.pack()
    assert actual == expected


def test_ept_map_unpack() -> None:
    data = (
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\x00\x87\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x04\x00\x00\x00"
    )
    resp = epm.EptMap.unpack(data)
    assert isinstance(resp, epm.EptMap)
    assert resp.obj is None
    assert len(resp.tower) == 5
    assert isinstance(resp.tower[0], epm.UUIDFloor)
    assert resp.tower[0].uuid == uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085")
    assert resp.tower[0].version == 1
    assert resp.tower[0].version_minor == 0
    assert resp.tower[0].protocol == epm.FloorProtocol.UUID_ID
    assert resp.tower[0].lhs
    assert resp.tower[0].rhs
    assert isinstance(resp.tower[1], epm.UUIDFloor)
    assert resp.tower[1].uuid == uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
    assert resp.tower[1].version == 2
    assert resp.tower[1].version_minor == 0
    assert resp.tower[1].protocol == epm.FloorProtocol.UUID_ID
    assert resp.tower[1].lhs
    assert resp.tower[1].rhs
    assert isinstance(resp.tower[2], epm.RPCConnectionOrientedFloor)
    assert resp.tower[2].version_minor == 0
    assert resp.tower[2].protocol == epm.FloorProtocol.RPC_CONNECTION_ORIENTED
    assert resp.tower[2].lhs == b""
    assert resp.tower[2].rhs
    assert isinstance(resp.tower[3], epm.TCPFloor)
    assert resp.tower[3].port == 135
    assert resp.tower[3].protocol == epm.FloorProtocol.TCP
    assert resp.tower[3].lhs == b""
    assert resp.tower[3].rhs
    assert isinstance(resp.tower[4], epm.IPFloor)
    assert resp.tower[4].addr == 0
    assert resp.tower[4].protocol == epm.FloorProtocol.IP
    assert resp.tower[4].lhs == b""
    assert resp.tower[4].rhs
    assert resp.entry_handle is None
    assert resp.max_towers == 4


def test_ept_map_pack_obj_and_entry_handle() -> None:
    expected = (
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x33\x05\x90\x80\x92\xbc\x6f\x40"
        b"\xbf\xbb\xb2\xdc\xd4\xa7\x26\xee"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x09\x00\x00\x00\x00\x00\x00\x00"
        b"\x09\x00\x00\x00\x01\x00\x01\x00"
        b"\x0b\x02\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x50\x62\x62\xea"
        b"\x2f\x27\xb2\x4a\x88\xa7\x8a\xbe"
        b"\x11\x40\x37\x24\x01\x00\x00\x00"
    )

    msg = epm.EptMap(
        obj=uuid.UUID("80900533-bc92-406f-bfbb-b2dcd4a726ee"),
        tower=[epm.RPCConnectionOrientedFloor(0)],
        entry_handle=(0, uuid.UUID("ea626250-272f-4ab2-88a7-8abe11403724")),
        max_towers=1,
    )
    actual = msg.pack()
    assert actual == expected


def test_ept_map_unpack_obj_and_entry_handle() -> None:
    data = (
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x33\x05\x90\x80\x92\xbc\x6f\x40"
        b"\xbf\xbb\xb2\xdc\xd4\xa7\x26\xee"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x09\x00\x00\x00\x00\x00\x00\x00"
        b"\x09\x00\x00\x00\x01\x00\x01\x00"
        b"\x0b\x02\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x50\x62\x62\xea"
        b"\x2f\x27\xb2\x4a\x88\xa7\x8a\xbe"
        b"\x11\x40\x37\x24\x01\x00\x00\x00"
    )
    resp = epm.EptMap.unpack(data)
    assert isinstance(resp, epm.EptMap)
    assert resp.obj == uuid.UUID("80900533-bc92-406f-bfbb-b2dcd4a726ee")
    assert len(resp.tower) == 1
    assert isinstance(resp.tower[0], epm.RPCConnectionOrientedFloor)
    assert resp.tower[0].version_minor == 0
    assert resp.tower[0].protocol == epm.FloorProtocol.RPC_CONNECTION_ORIENTED
    assert resp.tower[0].lhs == b""
    assert resp.tower[0].rhs
    assert resp.entry_handle == (0, uuid.UUID("ea626250-272f-4ab2-88a7-8abe11403724"))
    assert resp.max_towers == 1


def test_ept_map_result_pack() -> None:
    expected = (
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x03\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x05\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x08\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x06\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x03\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )
    service = rpc.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
    data_rep = rpc.SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)

    msg = epm.EptMapResult(
        entry_handle=None,
        towers=[
            epm.build_tcpip_tower(service, data_rep, 49672, 0),
            epm.build_tcpip_tower(service, data_rep, 49670, 0),
            epm.build_tcpip_tower(service, data_rep, 49667, 0),
        ],
        status=0,
    )
    actual = msg.pack()
    assert actual == expected


def test_ept_map_result_unpack() -> None:
    data = (
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x03\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x05\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x08\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x06\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x03\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )
    resp = epm.EptMapResult.unpack(data)
    assert isinstance(resp, epm.EptMapResult)
    assert resp.entry_handle is None
    assert len(resp.towers) == 3

    for idx, port in enumerate([49672, 49670, 49667]):
        floors = resp.towers[idx]

        assert len(floors) == 5
        assert isinstance(floors[0], epm.UUIDFloor)
        assert floors[0].uuid == uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085")
        assert floors[0].version == 1
        assert floors[0].version_minor == 0
        assert floors[0].protocol == epm.FloorProtocol.UUID_ID
        assert floors[0].lhs
        assert floors[0].rhs
        assert isinstance(floors[1], epm.UUIDFloor)
        assert floors[1].uuid == uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
        assert floors[1].version == 2
        assert floors[1].version_minor == 0
        assert floors[1].protocol == epm.FloorProtocol.UUID_ID
        assert floors[1].lhs
        assert floors[1].rhs
        assert isinstance(floors[2], epm.RPCConnectionOrientedFloor)
        assert floors[2].version_minor == 0
        assert floors[2].protocol == epm.FloorProtocol.RPC_CONNECTION_ORIENTED
        assert floors[2].lhs == b""
        assert floors[2].rhs
        assert isinstance(floors[3], epm.TCPFloor)
        assert floors[3].port == port
        assert floors[3].protocol == epm.FloorProtocol.TCP
        assert floors[3].lhs == b""
        assert floors[3].rhs
        assert isinstance(floors[4], epm.IPFloor)
        assert floors[4].addr == 0
        assert floors[4].protocol == epm.FloorProtocol.IP
        assert floors[4].lhs == b""
        assert floors[4].rhs


def test_ept_map_result_pack_handle() -> None:
    expected = (
        b"\x00\x00\x00\x00\xc9\x53\xc3\x6b"
        b"\xe9\x11\xaa\x47\xb6\xfd\x13\x8d"
        b"\x04\xda\x08\x9d\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    msg = epm.EptMapResult(
        entry_handle=(0, uuid.UUID("6bc353c9-11e9-47aa-b6fd-138d04da089d")),
        towers=[],
        status=0,
    )
    actual = msg.pack()
    assert actual == expected


def test_ept_map_result_unpack_handle() -> None:
    data = (
        b"\x00\x00\x00\x00\xc9\x53\xc3\x6b"
        b"\xe9\x11\xaa\x47\xb6\xfd\x13\x8d"
        b"\x04\xda\x08\x9d\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    resp = epm.EptMapResult.unpack(data)
    assert isinstance(resp, epm.EptMapResult)
    assert resp.entry_handle == (0, uuid.UUID("6bc353c9-11e9-47aa-b6fd-138d04da089d"))
    assert len(resp.towers) == 0


def test_unpack_unknown_floor() -> None:
    data = b"\x02\x00\xFF\x00\x01\x00\x00"

    msg = epm.Floor.unpack(data)

    assert msg.protocol == epm.FloorProtocol(0xFF)
    assert msg.lhs == b"\x00"
    assert msg.rhs == b"\x00"
