# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import uuid

from dpapi_ng._rpc import _bind as bind
from dpapi_ng._rpc import _pdu as pdu


def test_bind_pack() -> None:
    expected = (
        b"\x05\x00\x0b\x03\x10\x00\x00\x00"
        b"\xa0\x00\x00\x00\x01\x00\x00\x00"
        b"\xd0\x16\xd0\x16\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x01\x00\x01\x00"
        b"\x08\x83\xaf\xe1\x1f\x5d\xc9\x11"
        b"\x91\xa4\x08\x00\x2b\x14\xa0\xfa"
        b"\x03\x00\x00\x00\x04\x5d\x88\x8a"
        b"\xeb\x1c\xc9\x11\x9f\xe8\x08\x00"
        b"\x2b\x10\x48\x60\x02\x00\x00\x00"
        b"\x02\x00\x01\x00\x08\x83\xaf\xe1"
        b"\x1f\x5d\xc9\x11\x91\xa4\x08\x00"
        b"\x2b\x14\xa0\xfa\x03\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00\x03\x00\x01\x00"
        b"\x08\x83\xaf\xe1\x1f\x5d\xc9\x11"
        b"\x91\xa4\x08\x00\x2b\x14\xa0\xfa"
        b"\x03\x00\x00\x00\x2c\x1c\xb7\x6c"
        b"\x12\x98\x40\x45\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00"
    )
    syntax_id = bind.SyntaxId(uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)

    msg = bind.Bind(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.BIND,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
            data_rep=pdu.DataRep(),
            frag_len=160,
            auth_len=0,
            call_id=1,
        ),
        sec_trailer=None,
        max_xmit_frag=5840,
        max_recv_frag=5840,
        assoc_group=0,
        contexts=[
            bind.ContextElement(
                context_id=1,
                abstract_syntax=syntax_id,
                transfer_syntaxes=[bind.SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)],
            ),
            bind.ContextElement(
                context_id=2,
                abstract_syntax=syntax_id,
                transfer_syntaxes=[bind.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)],
            ),
            bind.ContextElement(
                context_id=3,
                abstract_syntax=syntax_id,
                transfer_syntaxes=[bind.SyntaxId(uuid.UUID("6cb71c2c-9812-4540-0000-000000000000"), 1, 0)],
            ),
        ],
    )
    actual = msg.pack()
    assert actual == expected


def test_bind_unpack() -> None:
    data = (
        b"\x05\x00\x0b\x03\x10\x00\x00\x00"
        b"\xa0\x00\x00\x00\x01\x00\x00\x00"
        b"\xd0\x16\xd0\x16\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x01\x00\x01\x00"
        b"\x08\x83\xaf\xe1\x1f\x5d\xc9\x11"
        b"\x91\xa4\x08\x00\x2b\x14\xa0\xfa"
        b"\x03\x00\x00\x00\x04\x5d\x88\x8a"
        b"\xeb\x1c\xc9\x11\x9f\xe8\x08\x00"
        b"\x2b\x10\x48\x60\x02\x00\x00\x00"
        b"\x02\x00\x01\x00\x08\x83\xaf\xe1"
        b"\x1f\x5d\xc9\x11\x91\xa4\x08\x00"
        b"\x2b\x14\xa0\xfa\x03\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00\x03\x00\x01\x00"
        b"\x08\x83\xaf\xe1\x1f\x5d\xc9\x11"
        b"\x91\xa4\x08\x00\x2b\x14\xa0\xfa"
        b"\x03\x00\x00\x00\x2c\x1c\xb7\x6c"
        b"\x12\x98\x40\x45\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00"
    )
    syntax_id = bind.SyntaxId(uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, bind.Bind)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.BIND
    assert msg.header.packet_flags == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 160
    assert msg.header.auth_len == 0
    assert msg.header.call_id == 1
    assert msg.max_xmit_frag == 5840
    assert msg.max_recv_frag == 5840
    assert msg.assoc_group == 0
    assert len(msg.contexts) == 3

    assert msg.contexts[0].context_id == 1
    assert msg.contexts[0].abstract_syntax == syntax_id
    assert len(msg.contexts[0].transfer_syntaxes) == 1
    assert msg.contexts[0].transfer_syntaxes[0] == bind.SyntaxId(
        uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0
    )

    assert msg.contexts[1].context_id == 2
    assert msg.contexts[1].abstract_syntax == syntax_id
    assert len(msg.contexts[1].transfer_syntaxes) == 1
    assert msg.contexts[1].transfer_syntaxes[0] == bind.SyntaxId(
        uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0
    )

    assert msg.contexts[2].context_id == 3
    assert msg.contexts[2].abstract_syntax == syntax_id
    assert len(msg.contexts[2].transfer_syntaxes) == 1
    assert msg.contexts[2].transfer_syntaxes[0] == bind.SyntaxId(
        uuid.UUID("6cb71c2c-9812-4540-0000-000000000000"), 1, 0
    )

    assert msg.sec_trailer is None


def test_bind_pack_sec_trailer() -> None:
    expected = (
        b"\x05\x00\x0b\x07\x10\x00\x00\x00"
        b"\xac\x00\x04\x00\x02\x00\x00\x00"
        b"\xd0\x16\xd0\x16\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x01\x00"
        b"\x35\x42\x51\xe3\x06\x4b\xd1\x11"
        b"\xab\x04\x00\xc0\x4f\xc2\xdc\xd2"
        b"\x04\x00\x00\x00\x04\x5d\x88\x8a"
        b"\xeb\x1c\xc9\x11\x9f\xe8\x08\x00"
        b"\x2b\x10\x48\x60\x02\x00\x00\x00"
        b"\x01\x00\x01\x00\x35\x42\x51\xe3"
        b"\x06\x4b\xd1\x11\xab\x04\x00\xc0"
        b"\x4f\xc2\xdc\xd2\x04\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00\x02\x00\x01\x00"
        b"\x35\x42\x51\xe3\x06\x4b\xd1\x11"
        b"\xab\x04\x00\xc0\x4f\xc2\xdc\xd2"
        b"\x04\x00\x00\x00\x2c\x1c\xb7\x6c"
        b"\x12\x98\x40\x45\x03\x00\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00"
        b"\x09\x06\x00\x00\x00\x00\x00\x00"
        b"\x60\x82\x07\x3c"
    )
    syntax_id = bind.SyntaxId(uuid.UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2"), 4, 0)

    msg = bind.Bind(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.BIND,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG
            | pdu.PacketFlags.PFC_LAST_FRAG
            | pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN,
            data_rep=pdu.DataRep(),
            frag_len=172,
            auth_len=4,
            call_id=2,
        ),
        sec_trailer=pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=0,
            context_id=0,
            auth_value=b"\x60\x82\x07\x3c",
        ),
        max_xmit_frag=5840,
        max_recv_frag=5840,
        assoc_group=0,
        contexts=[
            bind.ContextElement(
                context_id=0,
                abstract_syntax=syntax_id,
                transfer_syntaxes=[bind.SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)],
            ),
            bind.ContextElement(
                context_id=1,
                abstract_syntax=syntax_id,
                transfer_syntaxes=[bind.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)],
            ),
            bind.ContextElement(
                context_id=2,
                abstract_syntax=syntax_id,
                transfer_syntaxes=[bind.SyntaxId(uuid.UUID("6cb71c2c-9812-4540-0300-000000000000"), 1, 0)],
            ),
        ],
    )
    actual = msg.pack()
    assert actual == expected


def test_bind_unpack_sec_trailer() -> None:
    data = (
        b"\x05\x00\x0b\x07\x10\x00\x00\x00"
        b"\xac\x00\x04\x00\x02\x00\x00\x00"
        b"\xd0\x16\xd0\x16\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x01\x00"
        b"\x35\x42\x51\xe3\x06\x4b\xd1\x11"
        b"\xab\x04\x00\xc0\x4f\xc2\xdc\xd2"
        b"\x04\x00\x00\x00\x04\x5d\x88\x8a"
        b"\xeb\x1c\xc9\x11\x9f\xe8\x08\x00"
        b"\x2b\x10\x48\x60\x02\x00\x00\x00"
        b"\x01\x00\x01\x00\x35\x42\x51\xe3"
        b"\x06\x4b\xd1\x11\xab\x04\x00\xc0"
        b"\x4f\xc2\xdc\xd2\x04\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00\x02\x00\x01\x00"
        b"\x35\x42\x51\xe3\x06\x4b\xd1\x11"
        b"\xab\x04\x00\xc0\x4f\xc2\xdc\xd2"
        b"\x04\x00\x00\x00\x2c\x1c\xb7\x6c"
        b"\x12\x98\x40\x45\x03\x00\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00"
        b"\x09\x06\x00\x00\x00\x00\x00\x00"
        b"\x60\x82\x07\x3c"
    )
    syntax_id = bind.SyntaxId(uuid.UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2"), 4, 0)

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, bind.Bind)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.BIND
    assert (
        msg.header.packet_flags
        == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG | pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN
    )
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 172
    assert msg.header.auth_len == 4
    assert msg.header.call_id == 2
    assert msg.max_xmit_frag == 5840
    assert msg.max_recv_frag == 5840
    assert msg.assoc_group == 0
    assert len(msg.contexts) == 3

    assert msg.contexts[0].context_id == 0
    assert msg.contexts[0].abstract_syntax == syntax_id
    assert len(msg.contexts[0].transfer_syntaxes) == 1
    assert msg.contexts[0].transfer_syntaxes[0] == bind.SyntaxId(
        uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0
    )

    assert msg.contexts[1].context_id == 1
    assert msg.contexts[1].abstract_syntax == syntax_id
    assert len(msg.contexts[1].transfer_syntaxes) == 1
    assert msg.contexts[1].transfer_syntaxes[0] == bind.SyntaxId(
        uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0
    )

    assert msg.contexts[2].context_id == 2
    assert msg.contexts[2].abstract_syntax == syntax_id
    assert len(msg.contexts[2].transfer_syntaxes) == 1
    assert msg.contexts[2].transfer_syntaxes[0] == bind.SyntaxId(
        uuid.UUID("6cb71c2c-9812-4540-0300-000000000000"), 1, 0
    )

    assert isinstance(msg.sec_trailer, pdu.SecTrailer)
    assert msg.sec_trailer.type == pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE
    assert msg.sec_trailer.level == pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    assert msg.sec_trailer.pad_length == 0
    assert msg.sec_trailer.context_id == 0
    assert msg.sec_trailer.auth_value == b"\x60\x82\x07\x3c"


def test_bind_ack_pack() -> None:
    expected = (
        b"\x05\x00\x0c\x03\x10\x00\x00\x00"
        b"\x6c\x00\x00\x00\x01\x00\x00\x00"
        b"\xd0\x16\xd0\x16\x04\x14\x00\x00"
        b"\x04\x00\x31\x33\x35\x00\x00\x00"
        b"\x03\x00\x00\x00\x02\x00\x02\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00\x03\x00\x03\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    msg = bind.BindAck(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.BIND_ACK,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
            data_rep=pdu.DataRep(),
            frag_len=108,
            auth_len=0,
            call_id=1,
        ),
        sec_trailer=None,
        max_xmit_frag=5840,
        max_recv_frag=5840,
        assoc_group=5124,
        sec_addr="135",
        results=[
            bind.ContextResult(
                result=bind.ContextResultCode.PROVIDER_REJECTION,
                reason=2,
                syntax=uuid.UUID(int=0),
                syntax_version=0,
            ),
            bind.ContextResult(
                result=bind.ContextResultCode.ACCEPTANCE,
                reason=0,
                syntax=uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"),
                syntax_version=1,
            ),
            bind.ContextResult(
                result=bind.ContextResultCode.NEGOTIATE_ACK,
                reason=3,
                syntax=uuid.UUID(int=0),
                syntax_version=0,
            ),
        ],
    )
    actual = msg.pack()
    assert actual == expected


def test_bind_ack_unpack() -> None:
    data = (
        b"\x05\x00\x0c\x03\x10\x00\x00\x00"
        b"\x6c\x00\x00\x00\x01\x00\x00\x00"
        b"\xd0\x16\xd0\x16\x04\x14\x00\x00"
        b"\x04\x00\x31\x33\x35\x00\x00\x00"
        b"\x03\x00\x00\x00\x02\x00\x02\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00\x03\x00\x03\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, bind.BindAck)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.BIND_ACK
    assert msg.header.packet_flags == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 108
    assert msg.header.auth_len == 0
    assert msg.header.call_id == 1
    assert msg.max_xmit_frag == 5840
    assert msg.max_recv_frag == 5840
    assert msg.assoc_group == 5124
    assert msg.sec_addr == "135"
    assert len(msg.results) == 3
    assert msg.results[0].result == bind.ContextResultCode.PROVIDER_REJECTION
    assert msg.results[0].reason == 2
    assert msg.results[0].syntax == uuid.UUID(int=0)
    assert msg.results[0].syntax_version == 0
    assert msg.results[1].result == bind.ContextResultCode.ACCEPTANCE
    assert msg.results[1].reason == 0
    assert msg.results[1].syntax == uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36")
    assert msg.results[1].syntax_version == 1
    assert msg.results[2].result == bind.ContextResultCode.NEGOTIATE_ACK
    assert msg.results[2].reason == 3
    assert msg.results[2].syntax == uuid.UUID(int=0)
    assert msg.results[2].syntax_version == 0
    assert msg.sec_trailer is None


def test_bind_ack_pack_sec_trailer() -> None:
    expected = (
        b"\x05\x00\x0c\x07\x10\x00\x00\x00"
        b"\x78\x00\x04\x00\x02\x00\x00\x00"
        b"\xd0\x16\xd0\x16\xc4\x0f\x00\x00"
        b"\x06\x00\x34\x39\x36\x36\x37\x00"
        b"\x03\x00\x00\x00\x02\x00\x02\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00\x03\x00\x03\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x09\x06\x00\x00"
        b"\x00\x00\x00\x00\xa1\x81\xa6\x30"
    )

    msg = bind.BindAck(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.BIND_ACK,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG
            | pdu.PacketFlags.PFC_LAST_FRAG
            | pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN,
            data_rep=pdu.DataRep(),
            frag_len=120,
            auth_len=4,
            call_id=2,
        ),
        sec_trailer=pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=0,
            context_id=0,
            auth_value=b"\xa1\x81\xa6\x30",
        ),
        max_xmit_frag=5840,
        max_recv_frag=5840,
        assoc_group=4036,
        sec_addr="49667",
        results=[
            bind.ContextResult(
                result=bind.ContextResultCode.PROVIDER_REJECTION,
                reason=2,
                syntax=uuid.UUID(int=0),
                syntax_version=0,
            ),
            bind.ContextResult(
                result=bind.ContextResultCode.ACCEPTANCE,
                reason=0,
                syntax=uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"),
                syntax_version=1,
            ),
            bind.ContextResult(
                result=bind.ContextResultCode.NEGOTIATE_ACK,
                reason=3,
                syntax=uuid.UUID(int=0),
                syntax_version=0,
            ),
        ],
    )
    actual = msg.pack()
    assert actual == expected


def test_bind_ack_unpack_sec_trailer() -> None:
    data = (
        b"\x05\x00\x0c\x07\x10\x00\x00\x00"
        b"\x78\x00\x04\x00\x02\x00\x00\x00"
        b"\xd0\x16\xd0\x16\xc4\x0f\x00\x00"
        b"\x06\x00\x34\x39\x36\x36\x37\x00"
        b"\x03\x00\x00\x00\x02\x00\x02\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00\x03\x00\x03\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x09\x06\x00\x00"
        b"\x00\x00\x00\x00\xa1\x81\xa6\x30"
    )

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, bind.BindAck)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.BIND_ACK
    assert (
        msg.header.packet_flags
        == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG | pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN
    )
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 120
    assert msg.header.auth_len == 4
    assert msg.header.call_id == 2
    assert msg.max_xmit_frag == 5840
    assert msg.max_recv_frag == 5840
    assert msg.assoc_group == 4036
    assert msg.sec_addr == "49667"
    assert len(msg.results) == 3
    assert msg.results[0].result == bind.ContextResultCode.PROVIDER_REJECTION
    assert msg.results[0].reason == 2
    assert msg.results[0].syntax == uuid.UUID(int=0)
    assert msg.results[0].syntax_version == 0
    assert msg.results[1].result == bind.ContextResultCode.ACCEPTANCE
    assert msg.results[1].reason == 0
    assert msg.results[1].syntax == uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36")
    assert msg.results[1].syntax_version == 1
    assert msg.results[2].result == bind.ContextResultCode.NEGOTIATE_ACK
    assert msg.results[2].reason == 3
    assert msg.results[2].syntax == uuid.UUID(int=0)
    assert msg.results[2].syntax_version == 0
    assert isinstance(msg.sec_trailer, pdu.SecTrailer)
    assert msg.sec_trailer.type == pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE
    assert msg.sec_trailer.level == pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    assert msg.sec_trailer.pad_length == 0
    assert msg.sec_trailer.context_id == 0
    assert msg.sec_trailer.auth_value == b"\xa1\x81\xa6\x30"


def test_bind_nak_pack() -> None:
    expected = b"\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00"

    msg = bind.BindNak(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.BIND_NAK,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
            data_rep=pdu.DataRep(),
            frag_len=24,
            auth_len=0,
            call_id=1,
        ),
        sec_trailer=None,
        reject_reason=0,
        versions=[(5, 0)],
    )
    actual = msg.pack()
    assert actual == expected


def test_bind_nak_unpack() -> None:
    data = b"\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00"

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, bind.BindNak)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.BIND_NAK
    assert msg.header.packet_flags == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 24
    assert msg.header.auth_len == 0
    assert msg.header.call_id == 1
    assert msg.reject_reason == 0
    assert msg.versions == [(5, 0)]
    assert msg.sec_trailer is None


def test_alter_context_pack() -> None:
    expected = (
        b"\x05\x00\x0e\x07\x10\x00\x00\x00"
        b"\x54\x00\x04\x00\x02\x00\x00\x00"
        b"\xd0\x16\xd0\x16\x00\x00\x00\x00"
        b"\x01\x00\x00\x00\x01\x00\x01\x00"
        b"\x35\x42\x51\xe3\x06\x4b\xd1\x11"
        b"\xab\x04\x00\xc0\x4f\xc2\xdc\xd2"
        b"\x04\x00\x00\x00\x33\x05\x71\x71"
        b"\xba\xbe\x37\x49\x83\x19\xb5\xdb"
        b"\xef\x9c\xcc\x36\x01\x00\x00\x00"
        b"\x09\x06\x00\x00\x00\x00\x00\x00"
        b"\xa1\x81\x89\x30"
    )
    syntax_id = bind.SyntaxId(uuid.UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2"), 4, 0)

    msg = bind.Bind(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.ALTER_CONTEXT,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG
            | pdu.PacketFlags.PFC_LAST_FRAG
            | pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN,
            data_rep=pdu.DataRep(),
            frag_len=84,
            auth_len=4,
            call_id=2,
        ),
        sec_trailer=pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=0,
            context_id=0,
            auth_value=b"\xa1\x81\x89\x30",
        ),
        max_xmit_frag=5840,
        max_recv_frag=5840,
        assoc_group=0,
        contexts=[
            bind.ContextElement(
                context_id=1,
                abstract_syntax=syntax_id,
                transfer_syntaxes=[bind.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)],
            ),
        ],
    )
    actual = msg.pack()
    assert actual == expected


def test_alter_context_unpack() -> None:
    data = (
        b"\x05\x00\x0e\x07\x10\x00\x00\x00"
        b"\x54\x00\x04\x00\x02\x00\x00\x00"
        b"\xd0\x16\xd0\x16\x00\x00\x00\x00"
        b"\x01\x00\x00\x00\x01\x00\x01\x00"
        b"\x35\x42\x51\xe3\x06\x4b\xd1\x11"
        b"\xab\x04\x00\xc0\x4f\xc2\xdc\xd2"
        b"\x04\x00\x00\x00\x33\x05\x71\x71"
        b"\xba\xbe\x37\x49\x83\x19\xb5\xdb"
        b"\xef\x9c\xcc\x36\x01\x00\x00\x00"
        b"\x09\x06\x00\x00\x00\x00\x00\x00"
        b"\xa1\x81\x89\x30"
    )
    syntax_id = bind.SyntaxId(uuid.UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2"), 4, 0)

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, bind.AlterContext)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.ALTER_CONTEXT
    assert (
        msg.header.packet_flags
        == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG | pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN
    )
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 84
    assert msg.header.auth_len == 4
    assert msg.header.call_id == 2
    assert msg.max_xmit_frag == 5840
    assert msg.max_recv_frag == 5840
    assert msg.assoc_group == 0
    assert len(msg.contexts) == 1

    assert msg.contexts[0].context_id == 1
    assert msg.contexts[0].abstract_syntax == syntax_id
    assert len(msg.contexts[0].transfer_syntaxes) == 1
    assert msg.contexts[0].transfer_syntaxes[0] == bind.SyntaxId(
        uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0
    )

    assert isinstance(msg.sec_trailer, pdu.SecTrailer)
    assert msg.sec_trailer.type == pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE
    assert msg.sec_trailer.level == pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    assert msg.sec_trailer.pad_length == 0
    assert msg.sec_trailer.context_id == 0
    assert msg.sec_trailer.auth_value == b"\xa1\x81\x89\x30"


def test_alter_context_resp_pack() -> None:
    expected = (
        b"\x05\x00\x0f\x07\x10\x00\x00\x00"
        b"\x44\x00\x04\x00\x02\x00\x00\x00"
        b"\xd0\x16\xd0\x16\xc4\x0f\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00"
        b"\x00\x00\x00\x00\x33\x05\x71\x71"
        b"\xba\xbe\x37\x49\x83\x19\xb5\xdb"
        b"\xef\x9c\xcc\x36\x01\x00\x00\x00"
        b"\x09\x06\x00\x00\x00\x00\x00\x00"
        b"\xa1\x27\x30\x25"
    )

    msg = bind.AlterContextResponse(
        header=pdu.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=pdu.PacketType.ALTER_CONTEXT_RESP,
            packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG
            | pdu.PacketFlags.PFC_LAST_FRAG
            | pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN,
            data_rep=pdu.DataRep(),
            frag_len=68,
            auth_len=4,
            call_id=2,
        ),
        sec_trailer=pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=0,
            context_id=0,
            auth_value=b"\xa1\x27\x30\x25",
        ),
        max_xmit_frag=5840,
        max_recv_frag=5840,
        assoc_group=4036,
        sec_addr="",
        results=[
            bind.ContextResult(
                result=bind.ContextResultCode.ACCEPTANCE,
                reason=0,
                syntax=uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"),
                syntax_version=1,
            ),
        ],
    )
    actual = msg.pack()
    assert actual == expected


def test_alter_context_resp_unpack() -> None:
    data = (
        b"\x05\x00\x0f\x07\x10\x00\x00\x00"
        b"\x44\x00\x04\x00\x02\x00\x00\x00"
        b"\xd0\x16\xd0\x16\xc4\x0f\x00\x00"
        b"\x00\x00\x34\x39\x01\x00\x00\x00"
        b"\x00\x00\x00\x00\x33\x05\x71\x71"
        b"\xba\xbe\x37\x49\x83\x19\xb5\xdb"
        b"\xef\x9c\xcc\x36\x01\x00\x00\x00"
        b"\x09\x06\x00\x00\x00\x00\x00\x00"
        b"\xa1\x27\x30\x25"
    )

    msg = pdu.PDU.unpack(data)
    assert isinstance(msg, bind.AlterContextResponse)
    assert msg.header.version == 5
    assert msg.header.version_minor == 0
    assert msg.header.packet_type == pdu.PacketType.ALTER_CONTEXT_RESP
    assert (
        msg.header.packet_flags
        == pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG | pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN
    )
    assert msg.header.data_rep.byte_order == pdu.IntegerRep.LITTLE_ENDIAN
    assert msg.header.data_rep.character == pdu.CharacterRep.ASCII
    assert msg.header.data_rep.floating_point == pdu.FloatingPointRep.IEEE
    assert msg.header.frag_len == 68
    assert msg.header.auth_len == 4
    assert msg.header.call_id == 2
    assert msg.max_xmit_frag == 5840
    assert msg.max_recv_frag == 5840
    assert msg.assoc_group == 4036
    assert msg.sec_addr == ""
    assert len(msg.results) == 1
    assert msg.results[0].result == bind.ContextResultCode.ACCEPTANCE
    assert msg.results[0].reason == 0
    assert msg.results[0].syntax == uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36")
    assert msg.results[0].syntax_version == 1

    assert isinstance(msg.sec_trailer, pdu.SecTrailer)
    assert msg.sec_trailer.type == pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE
    assert msg.sec_trailer.level == pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    assert msg.sec_trailer.pad_length == 0
    assert msg.sec_trailer.context_id == 0
    assert msg.sec_trailer.auth_value == b"\xa1\x27\x30\x25"
