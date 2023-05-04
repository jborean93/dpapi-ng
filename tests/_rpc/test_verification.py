# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import uuid

import pytest

from dpapi_ng._rpc import _bind as bind
from dpapi_ng._rpc import _pdu as pdu
from dpapi_ng._rpc import _verification as verification


def test_verification_trailer_pack() -> None:
    expected = (
        b"\x8a\xe3\x13\x71\x02\xf4\x36\x71"
        b"\x02\x40\x28\x00\x60\x59\x78\xb9"
        b"\x4f\x52\xdf\x11\x8b\x6d\x83\xdc"
        b"\xde\xd7\x20\x85\x01\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00"
    )

    msg = verification.VerificationTrailer(
        [
            verification.CommandPContext(
                verification.CommandFlags.SEC_VT_COMMAND_END,
                bind.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0),
                bind.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0),
            )
        ]
    )
    actual = msg.pack()
    assert actual == expected


def test_verification_trailer_unpack() -> None:
    data = (
        b"\x8a\xe3\x13\x71\x02\xf4\x36\x71"
        b"\x02\x40\x28\x00\x60\x59\x78\xb9"
        b"\x4f\x52\xdf\x11\x8b\x6d\x83\xdc"
        b"\xde\xd7\x20\x85\x01\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00"
    )

    msg = verification.VerificationTrailer.unpack(data)
    assert len(msg.commands) == 1
    assert isinstance(msg.commands[0], verification.CommandPContext)
    assert msg.commands[0].command == verification.CommandType.SEC_VT_COMMAND_PCONTEXT
    assert msg.commands[0].flags == verification.CommandFlags.SEC_VT_COMMAND_END
    assert msg.commands[0].value
    assert msg.commands[0].interface_id == bind.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
    assert msg.commands[0].transfer_syntax == bind.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)


def test_verification_trailer_unpack_invalid_signature() -> None:
    with pytest.raises(ValueError, match="Failed to unpack VerificationTrailer as signature header is invalid"):
        verification.VerificationTrailer.unpack(b"\x00")


def test_verification_trailer_unpack_multiple_commands() -> None:
    data = b"\x8a\xe3\x13\x71\x02\xf4\x36\x71\x01\x00\x04\x00\x01\x00\x00\x00\x00\x60\x01\x00\x00"

    msg = verification.VerificationTrailer.unpack(data)
    assert len(msg.commands) == 2
    assert isinstance(msg.commands[0], verification.CommandBitmask)
    assert msg.commands[0].command == verification.CommandType.SEC_VT_COMMAND_BITMASK_1
    assert msg.commands[0].flags == verification.CommandFlags.NONE
    assert msg.commands[0].value == b"\x01\x00\x00\x00"
    assert msg.commands[0].bits == 1

    assert isinstance(msg.commands[1], verification.Command)
    assert msg.commands[1].command == verification.CommandType(0x2000)
    assert msg.commands[1].flags == verification.CommandFlags.SEC_VT_COMMAND_END
    assert msg.commands[1].value == b"\x00"


def test_command_bitmask_pack() -> None:
    expected = b"\x01\x00\x04\x00\x01\x00\x00\x00"

    msg = verification.CommandBitmask(flags=verification.CommandFlags.NONE, bits=1)
    actual = msg.pack()
    assert actual == expected


def test_command_bitmask_unpack() -> None:
    data = b"\x01\x00\x04\x00\x01\x00\x00\x00"

    msg = verification.Command.unpack(data)
    assert isinstance(msg, verification.CommandBitmask)
    assert msg.command == verification.CommandType.SEC_VT_COMMAND_BITMASK_1
    assert msg.flags == verification.CommandFlags.NONE
    assert msg.value == b"\x01\x00\x00\x00"
    assert msg.bits == 1


def test_command_pcontext_pack() -> None:
    expected = (
        b"\x02\x40\x28\x00\x60\x59\x78\xb9"
        b"\x4f\x52\xdf\x11\x8b\x6d\x83\xdc"
        b"\xde\xd7\x20\x85\x01\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00"
    )

    msg = verification.CommandPContext(
        verification.CommandFlags.SEC_VT_COMMAND_END,
        bind.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0),
        bind.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0),
    )
    actual = msg.pack()
    assert actual == expected


def test_command_pcontext_unpack() -> None:
    data = (
        b"\x02\x40\x28\x00\x60\x59\x78\xb9"
        b"\x4f\x52\xdf\x11\x8b\x6d\x83\xdc"
        b"\xde\xd7\x20\x85\x01\x00\x00\x00"
        b"\x33\x05\x71\x71\xba\xbe\x37\x49"
        b"\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
        b"\x01\x00\x00\x00"
    )

    msg = verification.Command.unpack(data)
    assert isinstance(msg, verification.CommandPContext)
    assert msg.command == verification.CommandType.SEC_VT_COMMAND_PCONTEXT
    assert msg.flags == verification.CommandFlags.SEC_VT_COMMAND_END
    assert msg.value
    assert msg.interface_id == bind.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
    assert msg.transfer_syntax == bind.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)


def test_command_header2_pack() -> None:
    expected = b"\x03\x80\x10\x00\x00\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x02\x00\x03\x00"

    msg = verification.CommandHeader2(
        verification.CommandFlags.SEC_VT_MUST_PROCESS_COMMAND,
        pdu.PacketType.REQUEST,
        pdu.DataRep(),
        1,
        2,
        3,
    )
    actual = msg.pack()
    assert actual == expected


def test_command_header2_unpack() -> None:
    data = b"\x03\x80\x10\x00\x00\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x02\x00\x03\x00"

    msg = verification.Command.unpack(data)
    assert isinstance(msg, verification.CommandHeader2)
    assert msg.command == verification.CommandType.SEC_VT_COMMAND_HEADER2
    assert msg.flags == verification.CommandFlags.SEC_VT_MUST_PROCESS_COMMAND
    assert msg.value == b"\x00\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x02\x00\x03\x00"
    assert msg.packet_type == pdu.PacketType.REQUEST
    assert msg.data_rep == pdu.DataRep()
    assert msg.call_id == 1
    assert msg.context_id == 2
    assert msg.opnum == 3


def test_unknown_command_unpack() -> None:
    data = b"\x00\xA0\x02\x00\x00\x01"

    msg = verification.Command.unpack(data)
    assert isinstance(msg, verification.Command)
    assert msg.command == verification.CommandType(0x2000)
    assert msg.flags == verification.CommandFlags.SEC_VT_MUST_PROCESS_COMMAND
    assert msg.value == b"\x00\x01"
