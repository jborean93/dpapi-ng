# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t
import uuid

from ._pdu import PDU, PacketType, PDUHeader, SecTrailer, register_pdu


class BindTimeFeatureNegotiation(enum.IntFlag):
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/cef529cc-77b5-4794-85dc-91e1467e80f0
    NONE = 0x00
    SECURITY_CONTEXT_MULTIPLEXING = 0x01
    KEEP_CONNECTION_ON_ORPHAN = 0x02


@dataclasses.dataclass(frozen=True)
class SyntaxId:
    uuid: uuid.UUID
    version: int
    version_minor: int

    def pack(self) -> bytes:
        return b"".join(
            [
                self.uuid.bytes_le,
                self.version.to_bytes(2, byteorder="little"),
                self.version_minor.to_bytes(2, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> SyntaxId:
        view = memoryview(data)

        return cls(
            uuid=uuid.UUID(bytes_le=view[:16].tobytes()),
            version=int.from_bytes(view[16:18], byteorder="little"),
            version_minor=int.from_bytes(view[18:20], byteorder="little"),
        )


@dataclasses.dataclass(frozen=True)
class ContextElement:
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    context_id: int
    abstract_syntax: SyntaxId
    transfer_syntaxes: t.List[SyntaxId]

    def pack(self) -> bytes:
        return b"".join(
            [
                self.context_id.to_bytes(2, byteorder="little"),
                len(self.transfer_syntaxes).to_bytes(2, byteorder="little"),
                self.abstract_syntax.pack(),
                b"".join([t.pack() for t in self.transfer_syntaxes]),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> ContextElement:
        view = memoryview(data)

        context_id = int.from_bytes(view[:2], byteorder="little")
        num_transfers = int.from_bytes(view[2:4], byteorder="little")
        abstract_syntax = SyntaxId.unpack(view[4:])
        view = view[24:]
        transfer_syntaxes = []
        for _ in range(num_transfers):
            transfer_syntaxes.append(SyntaxId.unpack(view))
            view = view[20:]

        return cls(
            context_id=context_id,
            abstract_syntax=abstract_syntax,
            transfer_syntaxes=transfer_syntaxes,
        )


class ContextResultCode(enum.IntEnum):
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/8df5c4d4-364d-468c-81fe-ec94c1b40917
    ACCEPTANCE = 0
    USER_REJECTION = 1
    PROVIDER_REJECTION = 2
    NEGOTIATE_ACK = 3  # MS-RPCE extension


@dataclasses.dataclass(frozen=True)
class ContextResult:
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    result: ContextResultCode
    reason: int
    syntax: uuid.UUID
    syntax_version: int

    def pack(self) -> bytes:
        return b"".join(
            [
                self.result.to_bytes(2, byteorder="little"),
                self.reason.to_bytes(2, byteorder="little"),
                self.syntax.bytes_le,
                self.syntax_version.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> ContextResult:
        view = memoryview(data)

        return cls(
            result=ContextResultCode(int.from_bytes(view[:2], byteorder="little")),
            reason=int.from_bytes(view[2:4], byteorder="little"),
            syntax=uuid.UUID(bytes_le=view[4:20].tobytes()),
            syntax_version=int.from_bytes(view[20:24], byteorder="little"),
        )


@dataclasses.dataclass(frozen=True)
@register_pdu(PacketType.BIND)
class Bind(PDU):
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    max_xmit_frag: int
    max_recv_frag: int
    assoc_group: int
    contexts: t.List[ContextElement]

    def pack(self) -> bytes:
        return b"".join(
            [
                self.header.pack(),
                self.max_xmit_frag.to_bytes(2, byteorder="little"),
                self.max_recv_frag.to_bytes(2, byteorder="little"),
                self.assoc_group.to_bytes(4, byteorder="little"),
                len(self.contexts).to_bytes(4, byteorder="little"),
                b"".join(c.pack() for c in self.contexts),
                self.sec_trailer.pack() if self.sec_trailer else b"",
            ]
        )

    @classmethod
    def _unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        header: PDUHeader,
        sec_trailer: t.Optional[SecTrailer],
    ) -> Bind:
        view = memoryview(data)

        max_xmit_frag = int.from_bytes(view[:2], byteorder="little")
        max_recv_frag = int.from_bytes(view[2:4], byteorder="little")
        assoc_group = int.from_bytes(view[4:8], byteorder="little")

        num_contexts = view[8]
        view = view[12:]
        contexts = []
        for _ in range(num_contexts):
            c = ContextElement.unpack(view)
            contexts.append(c)
            view = view[24 + (len(c.transfer_syntaxes) * 20) :]

        return cls(
            header=header,
            sec_trailer=sec_trailer,
            max_xmit_frag=max_xmit_frag,
            max_recv_frag=max_recv_frag,
            assoc_group=assoc_group,
            contexts=contexts,
        )


@dataclasses.dataclass(frozen=True)
@register_pdu(PacketType.BIND_ACK)
class BindAck(PDU):
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    max_xmit_frag: int
    max_recv_frag: int
    assoc_group: int
    sec_addr: str
    results: t.List[ContextResult]

    def pack(self) -> bytes:
        b_sec_addr = b""
        if self.sec_addr:
            b_sec_addr = self.sec_addr.encode("utf-8") + b"\x00"
        sec_addr_len = len(b_sec_addr)
        padding = -(2 + sec_addr_len) % 4
        b_result = b"".join([r.pack() for r in self.results])

        return b"".join(
            [
                self.header.pack(),
                self.max_xmit_frag.to_bytes(2, byteorder="little"),
                self.max_recv_frag.to_bytes(2, byteorder="little"),
                self.assoc_group.to_bytes(4, byteorder="little"),
                sec_addr_len.to_bytes(2, byteorder="little"),
                b_sec_addr,
                b"\x00" * padding,
                len(self.results).to_bytes(4, byteorder="little"),
                b_result,
                self.sec_trailer.pack() if self.sec_trailer else b"",
            ]
        )

    @classmethod
    def _unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        header: PDUHeader,
        sec_trailer: t.Optional[SecTrailer],
    ) -> BindAck:
        view = memoryview(data)

        max_xmit_frag = int.from_bytes(view[:2], byteorder="little")
        max_recv_frag = int.from_bytes(view[2:4], byteorder="little")
        assoc_group = int.from_bytes(view[4:8], byteorder="little")
        sec_addr_len = int.from_bytes(view[8:10], byteorder="little")
        sec_addr = view[10 : 10 + sec_addr_len - 1].tobytes().decode("utf-8")
        padding = -(2 + sec_addr_len) % 4
        view = view[10 + sec_addr_len + padding :]

        num_result = view[0]
        view = view[4:]
        results = []
        for _ in range(num_result):
            results.append(ContextResult.unpack(view))
            view = view[24:]

        return cls(
            header=header,
            sec_trailer=sec_trailer,
            max_xmit_frag=max_xmit_frag,
            max_recv_frag=max_recv_frag,
            assoc_group=assoc_group,
            sec_addr=sec_addr,
            results=results,
        )


@dataclasses.dataclass(frozen=True)
@register_pdu(PacketType.BIND_NAK)
class BindNak(PDU):
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    reject_reason: int
    versions: t.List[tuple[int, int]]

    def pack(self) -> bytes:
        protocols = [v[0].to_bytes(1, byteorder="little") + v[1].to_bytes(1, byteorder="little") for v in self.versions]
        b_versions = b"".join(
            [
                len(protocols).to_bytes(1, byteorder="little"),
                b"".join(protocols),
            ]
        )
        padding = -(2 + len(b_versions)) % 4

        return b"".join(
            [
                self.header.pack(),
                self.reject_reason.to_bytes(2, byteorder="little"),
                b_versions,
                b"\x00" * padding,
            ]
        )

    @classmethod
    def _unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        header: PDUHeader,
        sec_trailer: t.Optional[SecTrailer],
    ) -> BindNak:
        view = memoryview(data)

        reject_reason = int.from_bytes(view[:2], byteorder="little")
        versions = []
        num_versions = view[2]

        view = view[3:]
        for _ in range(num_versions):
            versions.append((view[0], view[1]))
            view = view[2:]

        return cls(
            header=header,
            sec_trailer=None,
            reject_reason=reject_reason,
            versions=versions,
        )


@dataclasses.dataclass(frozen=True)
@register_pdu(PacketType.ALTER_CONTEXT)
class AlterContext(Bind):
    @classmethod
    def _unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        header: PDUHeader,
        sec_trailer: t.Optional[SecTrailer],
    ) -> AlterContext:
        return Bind._unpack.__func__(cls, data, header, sec_trailer)  # type: ignore[attr-defined]


@dataclasses.dataclass(frozen=True)
@register_pdu(PacketType.ALTER_CONTEXT_RESP)
class AlterContextResponse(BindAck):
    @classmethod
    def _unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        header: PDUHeader,
        sec_trailer: t.Optional[SecTrailer],
    ) -> AlterContextResponse:
        return BindAck._unpack.__func__(cls, data, header, sec_trailer)  # type: ignore[attr-defined]


def bind_time_feature_negotiation(
    flags: BindTimeFeatureNegotiation = BindTimeFeatureNegotiation.NONE,
) -> SyntaxId:
    """Creates the Bind Time Feature Negotiation Syntax value from the flags specified."""
    return SyntaxId(
        uuid=uuid.UUID(fields=(0x6CB71C2C, 0x9812, 0x4540, flags, 0, 0)),
        version=1,
        version_minor=0,
    )
