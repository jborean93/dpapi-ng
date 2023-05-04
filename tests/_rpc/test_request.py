# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import uuid

from dpapi_ng._rpc import _pdu as pdu
from dpapi_ng._rpc import _request as request


def test_request_pack() -> None:
    expected = (
        b"\x05\x00\x00\x03\x10\x00\x00\x00"
        b"\x1c\x00\x00\x00\x02\x00\x00\x00"
        b"\x90\x00\x00\x00\x01\x00\x03\x00"
        b"\x01\x00\x00\x00"
    )

    msg = request.Request(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.REQUEST,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
            data_rep=pdu.DataRep(),
            frag_len=28,
            auth_len=0,
            call_id=2,
        ),
        sec_trailer=None,
        alloc_hint=144,
        context_id=1,
        opnum=3,
        obj=None,
        stub_data=b"\x01\x00\x00\x00",
    )
    actual = msg.pack()
    assert actual == expected


def test_request_unpack() -> None:
    data = (
        b"\x05\x00\x00\x03\x10\x00\x00\x00"
        b"\x1c\x00\x00\x00\x02\x00\x00\x00"
        b"\x90\x00\x00\x00\x01\x00\x03\x00"
        b"\x01\x00\x00\x00"
    )

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, request.Request)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.REQUEST
    assert msg.header.packet_flags == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 28
    assert msg.header.auth_len == 0
    assert msg.header.call_id == 2
    assert msg.alloc_hint == 144
    assert msg.context_id == 1
    assert msg.opnum == 3
    assert msg.obj is None
    assert msg.stub_data == b"\x01\x00\x00\x00"
    assert msg.sec_trailer is None


def test_request_pack_with_obj() -> None:
    expected = (
        b"\x05\x00\x00\x83\x10\x00\x00\x00"
        b"\x2c\x00\x00\x00\x02\x00\x00\x00"
        b"\x90\x00\x00\x00\x01\x00\x03\x00"
        b"\xff\xff\xff\xff\xff\xff\xff\xff"
        b"\xff\xff\xff\xff\xff\xff\xff\xff"
        b"\x01\x00\x00\x00"
    )

    msg = request.Request(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.REQUEST,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG
            | pdu.PacketFlags.PFC_LAST_FRAG
            | pdu.PacketFlags.PFC_OBJECT_UUID,
            data_rep=pdu.DataRep(),
            frag_len=44,
            auth_len=0,
            call_id=2,
        ),
        sec_trailer=None,
        alloc_hint=144,
        context_id=1,
        opnum=3,
        obj=uuid.UUID(bytes_le=b"\xff" * 16),
        stub_data=b"\x01\x00\x00\x00",
    )
    actual = msg.pack()
    assert actual == expected


def test_request_unpack_with_obj() -> None:
    data = (
        b"\x05\x00\x00\x83\x10\x00\x00\x00"
        b"\x2c\x00\x00\x00\x02\x00\x00\x00"
        b"\x90\x00\x00\x00\x01\x00\x03\x00"
        b"\xff\xff\xff\xff\xff\xff\xff\xff"
        b"\xff\xff\xff\xff\xff\xff\xff\xff"
        b"\x01\x00\x00\x00"
    )

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, request.Request)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.REQUEST
    assert (
        msg.header.packet_flags
        == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG | pdu.PacketFlags.PFC_OBJECT_UUID
    )
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 44
    assert msg.header.auth_len == 0
    assert msg.header.call_id == 2
    assert msg.alloc_hint == 144
    assert msg.context_id == 1
    assert msg.opnum == 3
    assert msg.obj == uuid.UUID(bytes_le=b"\xff" * 16)
    assert msg.stub_data == b"\x01\x00\x00\x00"
    assert msg.sec_trailer is None


def test_request_pack_sec_trailer() -> None:
    expected = (
        b"\x05\x00\x00\x03\x10\x00\x00\x00"
        b"\x38\x00\x04\x00\x02\x00\x00\x00"
        b"\x94\x00\x00\x00\x01\x00\x00\x00"
        b"\xba\x8b\xff\xf4\x6c\x22\x7f\x25"
        b"\xce\x5c\xd2\x57\x3f\x9c\xd7\xba"
        b"\x09\x06\x0c\x00\x00\x00\x00\x00"
        b"\x05\x04\x06\xff"
    )

    msg = request.Request(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.REQUEST,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
            data_rep=pdu.DataRep(),
            frag_len=56,
            auth_len=4,
            call_id=2,
        ),
        sec_trailer=pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=12,
            context_id=0,
            auth_value=b"\x05\x04\x06\xff",
        ),
        alloc_hint=148,
        context_id=1,
        opnum=0,
        obj=None,
        stub_data=b"\xba\x8b\xff\xf4\x6c\x22\x7f\x25\xce\x5c\xd2\x57\x3f\x9c\xd7\xba",
    )
    actual = msg.pack()
    assert actual == expected


def test_request_unpack_sec_trailer() -> None:
    data = (
        b"\x05\x00\x00\x03\x10\x00\x00\x00"
        b"\x38\x00\x04\x00\x02\x00\x00\x00"
        b"\x94\x00\x00\x00\x01\x00\x00\x00"
        b"\xba\x8b\xff\xf4\x6c\x22\x7f\x25"
        b"\xce\x5c\xd2\x57\x3f\x9c\xd7\xba"
        b"\x09\x06\x0c\x00\x00\x00\x00\x00"
        b"\x05\x04\x06\xff"
    )

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, request.Request)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.REQUEST
    assert msg.header.packet_flags == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 56
    assert msg.header.auth_len == 4
    assert msg.header.call_id == 2
    assert msg.alloc_hint == 148
    assert msg.context_id == 1
    assert msg.opnum == 0
    assert msg.obj is None
    assert msg.stub_data == b"\xba\x8b\xff\xf4\x6c\x22\x7f\x25\xce\x5c\xd2\x57\x3f\x9c\xd7\xba"
    assert isinstance(msg.sec_trailer, pdu.SecTrailer)
    assert msg.sec_trailer.type == pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE
    assert msg.sec_trailer.level == pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    assert msg.sec_trailer.pad_length == 12
    assert msg.sec_trailer.context_id == 0
    assert msg.sec_trailer.auth_value == b"\x05\x04\x06\xff"


def test_response_pack() -> None:
    expected = (
        b"\x05\x00\x02\x03\x10\x00\x00\x00"
        b"\x1c\x00\x00\x00\x02\x00\x00\x00"
        b"\x94\x00\x00\x00\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    msg = request.Response(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.RESPONSE,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
            data_rep=pdu.DataRep(),
            frag_len=28,
            auth_len=0,
            call_id=2,
        ),
        sec_trailer=None,
        alloc_hint=148,
        context_id=1,
        cancel_count=0,
        stub_data=b"\x00\x00\x00\x00",
    )
    actual = msg.pack()
    assert actual == expected


def test_response_unpack() -> None:
    data = (
        b"\x05\x00\x02\x03\x10\x00\x00\x00"
        b"\x1c\x00\x00\x00\x02\x00\x00\x00"
        b"\x94\x00\x00\x00\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, request.Response)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.RESPONSE
    assert msg.header.packet_flags == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 28
    assert msg.header.auth_len == 0
    assert msg.header.call_id == 2
    assert msg.alloc_hint == 148
    assert msg.context_id == 1
    assert msg.cancel_count == 0
    assert msg.stub_data == b"\x00\x00\x00\x00"
    assert msg.sec_trailer is None


def test_response_pack_sec_trailer() -> None:
    expected = (
        b"\x05\x00\x02\x03\x10\x00\x00\x00"
        b"\x28\x00\x04\x00\x02\x00\x00\x00"
        b"\x60\x00\x00\x00\x01\x00\x00\x00"
        b"\x9d\x08\xd7\x07\x09\x06\x00\x00"
        b"\x00\x00\x00\x00\x05\x04\x07\xff"
    )

    msg = request.Response(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.RESPONSE,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
            data_rep=pdu.DataRep(),
            frag_len=40,
            auth_len=4,
            call_id=2,
        ),
        sec_trailer=pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=0,
            context_id=0,
            auth_value=b"\x05\x04\x07\xff",
        ),
        alloc_hint=96,
        context_id=1,
        cancel_count=0,
        stub_data=b"\x9d\x08\xd7\x07",
    )
    actual = msg.pack()
    assert actual == expected


def test_response_unpack_sec_trailer() -> None:
    data = (
        b"\x05\x00\x02\x03\x10\x00\x00\x00"
        b"\x28\x00\x04\x00\x02\x00\x00\x00"
        b"\x60\x00\x00\x00\x01\x00\x00\x00"
        b"\x9d\x08\xd7\x07\x09\x06\x00\x00"
        b"\x00\x00\x00\x00\x05\x04\x07\xff"
    )

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, request.Response)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.RESPONSE
    assert msg.header.packet_flags == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 40
    assert msg.header.auth_len == 4
    assert msg.header.call_id == 2
    assert msg.alloc_hint == 96
    assert msg.context_id == 1
    assert msg.cancel_count == 0
    assert msg.stub_data == b"\x9d\x08\xd7\x07"
    assert isinstance(msg.sec_trailer, pdu.SecTrailer)
    assert msg.sec_trailer.type == pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE
    assert msg.sec_trailer.level == pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    assert msg.sec_trailer.pad_length == 0
    assert msg.sec_trailer.context_id == 0
    assert msg.sec_trailer.auth_value == b"\x05\x04\x07\xff"
