# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t

from ._bind import SyntaxId
from ._pdu import DataRep, PacketType

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/0e9fea61-1bff-4478-9bfe-a3b6d8b64ac3


class CommandType(enum.IntEnum):
    SEC_VT_COMMAND_BITMASK_1 = 0x0001
    SEC_VT_COMMAND_PCONTEXT = 0x0002
    SEC_VT_COMMAND_HEADER2 = 0x0003

    @classmethod
    def _missing_(cls, value: object) -> t.Optional[enum.Enum]:
        new_member = int.__new__(cls)
        new_member._name_ = f"CommandType Unknown 0x{value:04X}"
        new_member._value_ = value  # type: ignore[assignment]
        return cls._value2member_map_.setdefault(value, new_member)


class CommandFlags(enum.IntFlag):
    NONE = 0x0000
    SEC_VT_COMMAND_END = 0x4000
    SEC_VT_MUST_PROCESS_COMMAND = 0x8000


@dataclasses.dataclass(frozen=True)
class Command:
    command: CommandType
    flags: CommandFlags
    value: bytes

    def pack(self) -> bytes:
        return b"".join(
            [
                (self.command.value | self.flags.value).to_bytes(2, byteorder="little"),
                len(self.value).to_bytes(2, byteorder="little"),
                self.value,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> Command:
        view = memoryview(data)

        cmd_field = int.from_bytes(view[:2], byteorder="little")
        command_type = CommandType(cmd_field & 0x3FFF)
        command_flags = CommandFlags(cmd_field & 0xC000)
        command_length = int.from_bytes(view[2:4], byteorder="little")
        value = view[4 : 4 + command_length].tobytes()

        unpack_func = _COMMAND_TYPE_REGISTRY.get(command_type, None)
        if unpack_func:
            cmd = unpack_func(command_flags, value)
            object.__setattr__(cmd, "value", value)
            return cmd

        else:
            return cls(command_type, command_flags, value)


T = t.TypeVar("T")
_COMMAND_TYPE_REGISTRY: t.Dict[CommandType, t.Callable[[CommandFlags, bytes], Command]] = {}


def register_cmd(cls: T) -> T:
    _COMMAND_TYPE_REGISTRY[getattr(cls, "command").default] = getattr(cls, "_unpack")
    return cls


@dataclasses.dataclass(frozen=True)
class _KnownCommand(Command):
    value: bytes = dataclasses.field(init=False, repr=False, default=b"")


@dataclasses.dataclass(frozen=True)
@register_cmd
class CommandBitmask(_KnownCommand):
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/35d7781d-6c5b-46b2-9083-3d53f98bef0d
    CLIENT_SUPPORT_HEADER_SIGNING: int = dataclasses.field(init=False, repr=False, default=0x00000001)

    command: CommandType = dataclasses.field(init=False, default=CommandType.SEC_VT_COMMAND_BITMASK_1)
    bits: int

    def pack(self) -> bytes:
        return Command(self.command, self.flags, self.bits.to_bytes(4, byteorder="little")).pack()

    @classmethod
    def _unpack(
        cls,
        flags: CommandFlags,
        value: bytes,
    ) -> CommandBitmask:
        return cls(
            flags=flags,
            bits=int.from_bytes(value, byteorder="little"),
        )


@dataclasses.dataclass(frozen=True)
@register_cmd
class CommandPContext(_KnownCommand):
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/41e3cf7a-3b42-470c-9d27-c4e047ac6445
    command: CommandType = dataclasses.field(init=False, default=CommandType.SEC_VT_COMMAND_PCONTEXT)
    interface_id: SyntaxId
    transfer_syntax: SyntaxId

    def pack(self) -> bytes:
        value = self.interface_id.pack() + self.transfer_syntax.pack()
        return Command(self.command, self.flags, value).pack()

    @classmethod
    def _unpack(
        cls,
        flags: CommandFlags,
        value: bytes,
    ) -> CommandPContext:
        interface_id = SyntaxId.unpack(value)
        transfer_syntax = SyntaxId.unpack(value[20:])
        return cls(
            flags=flags,
            interface_id=interface_id,
            transfer_syntax=transfer_syntax,
        )


@dataclasses.dataclass(frozen=True)
@register_cmd
class CommandHeader2(_KnownCommand):
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/0a108fbd-c848-4755-9e15-6c4df1c35134
    command: CommandType = dataclasses.field(init=False, default=CommandType.SEC_VT_COMMAND_HEADER2)
    packet_type: PacketType
    data_rep: DataRep
    call_id: int
    context_id: int
    opnum: int

    def pack(self) -> bytes:
        value = b"".join(
            [
                self.packet_type.to_bytes(1, byteorder="little"),
                b"\x00\x00\x00",  # Reserved
                self.data_rep.pack(),
                self.call_id.to_bytes(4, byteorder="little"),
                self.context_id.to_bytes(2, byteorder="little"),
                self.opnum.to_bytes(2, byteorder="little"),
            ]
        )
        return Command(self.command, self.flags, value).pack()

    @classmethod
    def _unpack(
        cls,
        flags: CommandFlags,
        value: bytes,
    ) -> CommandHeader2:
        view = memoryview(value)

        return cls(
            flags=flags,
            packet_type=PacketType(view[0]),
            data_rep=DataRep.unpack(view[4:8]),
            call_id=int.from_bytes(view[8:12], byteorder="little"),
            context_id=int.from_bytes(view[12:14], byteorder="little"),
            opnum=int.from_bytes(view[14:16], byteorder="little"),
        )


@dataclasses.dataclass(frozen=True)
class VerificationTrailer:
    signature: bytes = dataclasses.field(init=False, default=b"\x8A\xE3\x13\x71\x02\xF4\x36\x71")
    commands: t.List[Command]

    def pack(self) -> bytes:
        return b"".join(
            [
                self.signature,
                b"".join(c.pack() for c in self.commands),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> VerificationTrailer:
        view = memoryview(data)

        if view[:8].tobytes() != cls.signature:
            raise ValueError(f"Failed to unpack {cls.__name__} as signature header is invalid")

        view = view[8:]
        commands = []
        while True:
            cmd = Command.unpack(view)
            commands.append(cmd)
            view = view[4 + len(cmd.value) :]
            if cmd.flags & CommandFlags.SEC_VT_COMMAND_END:
                break

        return cls(commands=commands)
