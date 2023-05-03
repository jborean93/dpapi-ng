# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

from dpapi_ng._rpc import _pdu as pdu


def test_pdu_header_pack() -> None:
    expected = b"\x05\x00\x0b\x03\x10\x00\x00\x00\xa0\x00\x00\x00\x01\x00\x00\x00"

    msg = pdu.PDUHeader(
        version=5,
        version_minor=0,
        packet_type=pdu.PacketType.BIND,
        packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
        data_rep=pdu.DataRep(),
        frag_len=160,
        auth_len=0,
        call_id=1,
    )
    actual = msg.pack()
    assert actual == expected


def test_pdu_header_unpack() -> None:
    data = b"\x05\x00\x0b\x03\x10\x00\x00\x00\xa0\x00\x00\x00\x01\x00\x00\x00"

    header = pdu.PDUHeader.unpack(data)
    assert header.version == 5
    assert header.version_minor == 0
    assert header.packet_type == pdu.PacketType.BIND
    assert header.packet_flags == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    assert header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert header.data_rep.character == pdu.CharacterRep.ASCII
    assert header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert header.frag_len == 160
    assert header.auth_len == 0
    assert header.call_id == 1


def test_sec_trailer_pack() -> None:
    expected = b"\x09\x06\x08\x00\x01\x00\x00\x00\x01"

    msg = pdu.SecTrailer(
        type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
        level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        pad_length=8,
        context_id=1,
        auth_value=b"\x01",
    )
    actual = msg.pack()
    assert actual == expected


def test_sec_trailer_unpack() -> None:
    data = b"\x09\x06\x08\x00\x01\x00\x00\x00\x01"

    sec_trailer = pdu.SecTrailer.unpack(data)
    assert sec_trailer.type == pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE
    assert sec_trailer.level == pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    assert sec_trailer.pad_length == 8
    assert sec_trailer.context_id == 1
    assert sec_trailer.auth_value == b"\x01"


def test_fault_pack() -> None:
    expected = b"\x05\x00\x03\x23\x10\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x03\x00\x01\x1c\x00\x00\x00\x00"

    msg = pdu.Fault(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.FAULT,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG
            | pdu.PacketFlags.PFC_LAST_FRAG
            | pdu.PacketFlags.PFC_DID_NOT_EXECUTE,
            data_rep=pdu.DataRep(),
            frag_len=32,
            auth_len=0,
            call_id=1,
        ),
        sec_trailer=None,
        alloc_hint=32,
        context_id=0,
        cancel_count=0,
        status=0x1C010003,
        flags=pdu.FaultFlags.NONE,
        stub_data=b"",
    )
    actual = msg.pack()
    assert actual == expected


def test_fault_unpack() -> None:
    data = b"\x05\x00\x03\x23\x10\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x03\x00\x01\x1c\x00\x00\x00\x00"

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, pdu.Fault)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.FAULT
    assert (
        msg.header.packet_flags
        == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG | pdu.PacketFlags.PFC_DID_NOT_EXECUTE
    )
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 32
    assert msg.header.auth_len == 0
    assert msg.header.call_id == 1
    assert msg.alloc_hint == 32
    assert msg.context_id == 0
    assert msg.cancel_count == 0
    assert msg.flags == pdu.FaultFlags.NONE
    assert msg.status == 0x1C010003
    assert msg.stub_data == b""
    assert msg.sec_trailer is None
