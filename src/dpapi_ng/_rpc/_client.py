# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import socket
import struct
import typing as t
import uuid

BIND_TIME_FEATURE_NEGOTIATION = (uuid.UUID("6cb71c2c-9812-4540-0300-000000000000"), 1, 0)
NDR = (uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)
NDR64 = (uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)


def _create_pdu(
    packet_type: PacketType,
    packet_flags: PacketFlags,
    call_id: int,
    *,
    header_data: t.Optional[bytes] = None,
    stub_data: t.Optional[bytes] = None,
    sec_trailer: t.Optional[SecTrailer] = None,
    authentication_token: t.Optional[bytes] = None,
) -> bytes:
    # https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf
    # 12.6.3 Connection-oriented PDU Data Types - PDU Header
    b_header_data = header_data or b""
    b_stub_data = stub_data or b""
    b_sec_trailer = b""
    if sec_trailer:
        b_sec_trailer = b"".join(
            [
                sec_trailer.type.to_bytes(1, byteorder="little"),
                sec_trailer.level.to_bytes(1, byteorder="little"),
                sec_trailer.pad_length.to_bytes(1, byteorder="little"),
                b"\x00",  # Auth-Rsrvd
                sec_trailer.context_id.to_bytes(4, byteorder="little"),
            ]
        )
    b_authentication_token = authentication_token or b""

    frag_len = 16 + len(b_header_data) + len(b_stub_data) + len(b_sec_trailer) + len(b_authentication_token)

    return b"".join(
        [
            b"\x05\x00",  # Version and minor version
            packet_type.to_bytes(1, byteorder="little"),
            packet_flags.to_bytes(1, byteorder="little"),
            b"\x10\x00\x00\x00",  # Data Representation
            frag_len.to_bytes(2, byteorder="little"),
            len(b_authentication_token).to_bytes(2, byteorder="little"),
            call_id.to_bytes(4, byteorder="little"),
            b_header_data,
            b_stub_data,
            b_sec_trailer,
            b_authentication_token,
        ]
    )


def _create_bind(
    call_id: int,
    service: tuple[uuid.UUID, int, int],
) -> bytes:
    context_header = b"".join(
        [
            b"\x01\x00",
            service[0].bytes_le,
            service[1].to_bytes(2, byteorder="little"),
            service[2].to_bytes(2, byteorder="little"),
        ]
    )

    def pack_syntax(idx: int, syntax: tuple[uuid.UUID, int, int]) -> bytes:
        return b"".join(
            [
                idx.to_bytes(2, byteorder="little"),
                context_header,
                syntax[0].bytes_le,
                syntax[1].to_bytes(2, byteorder="little"),
                syntax[2].to_bytes(2, byteorder="little"),
            ]
        )

    context_data = b"".join(
        [
            pack_syntax(idx, syntax)
            for idx, syntax in enumerate(
                [
                    NDR,
                    NDR64,
                    BIND_TIME_FEATURE_NEGOTIATION,
                ]
            )
        ]
    )

    header_data = b"".join(
        [
            b"\xD0\x16",  # Max Xmit Frag
            b"\xD0\x16",  # Min Recv Frag
            b"\x00\x00\x00\x00",  # Assoc Group
            b"\x03\x00\x00\x00",  # Num context items
            context_data,
        ]
    )
    return _create_pdu(
        packet_type=PacketType.BIND,
        packet_flags=PacketFlags.PFC_FIRST_FRAG | PacketFlags.PFC_LAST_FRAG,
        call_id=call_id,
        header_data=header_data,
    )


def _create_request(
    call_id: int,
    opnum: int,
    stub_data: bytes,
) -> bytes:
    request_header = b"".join(
        [
            len(stub_data).to_bytes(4, byteorder="little"),
            b"\x01\x00",  # Context id
            opnum.to_bytes(2, byteorder="little"),
        ]
    )
    return _create_pdu(
        packet_type=PacketType.REQUEST,
        packet_flags=PacketFlags.PFC_FIRST_FRAG | PacketFlags.PFC_LAST_FRAG,
        call_id=call_id,
        header_data=request_header,
        stub_data=stub_data,
        sec_trailer=None,
    )


def create_rpc_connection(
    server: str,
    port: int = 135,
    connection_timeout: int = 5,
) -> SyncRpcClient:
    sock = socket.create_connection(
        (server, port),
        timeout=connection_timeout,
    )
    sock.settimeout(None)

    return SyncRpcClient(sock, server, port)


class SyncRpcClient:
    def __init__(
        self,
        sock: socket.socket,
        server: str,
        port: int = 135,
    ) -> None:
        self._sock = sock
        self.server = server
        self.port = port

    def __enter__(self) -> SyncRpcClient:
        return self

    def __exit__(self, *args: t.Any, **kwargs: t.Any) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # The socket has already been shutdown for some other reason
            pass
        self._sock.close()

    def bind(
        self,
        service: tuple[uuid.UUID, int, int],
    ) -> BindAck:
        pdu = _create_bind(1, service)
        resp = self._send_pdu(pdu)
        return BindAck.unpack(resp)

    def alter_context(
        self,
    ) -> None:
        return

    def request(
        self,
        opnum: int,
        stub_data: bytes,
    ) -> bytes:
        pdu = _create_request(
            1,
            opnum=opnum,
            stub_data=stub_data,
        )

        self._sock.sendall(pdu)
        resp = self._sock.recv(4096)
        return b""

    def _send_pdu(
        self,
        pdu: bytes,
    ) -> bytearray:
        self._sock.sendall(pdu)

        header = self._sock.recv(16)
        frag_len = int.from_bytes(header[8:10], byteorder="little")

        resp = bytearray(frag_len)
        view = memoryview(resp)
        view[:16] = header
        view = view[16:]

        while view:
            read = self._sock.recv_into(view)
            view = view[read:]

        if resp[2] == PacketType.FAULT:
            raise Exception(f"PDU Fault")

        return resp


@dataclasses.dataclass(frozen=True)
class PDUHeader:
    version: int
    version_minor: int
    packet_type: PacketType
    packet_flags: PacketFlags
    data_rep: bytes
    frag_len: int
    auth_len: int
    call_id: int

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> PDUHeader:
        view = memoryview(data)

        return PDUHeader(
            version=view[0],
            version_minor=view[1],
            packet_type=PacketType(view[2]),
            packet_flags=PacketFlags(view[3]),
            data_rep=view[4:8].tobytes(),
            frag_len=int.from_bytes(view[8:10], byteorder="little"),
            auth_len=int.from_bytes(view[10:12], byteorder="little"),
            call_id=int.from_bytes(view[12:16], byteorder="little"),
        )


@dataclasses.dataclass(frozen=True)
class Request:
    header: PDUHeader
    alloc_hint: int
    context_id: int
    opnum: int
    stub_data: bytes
    sec_trailer: t.Optional[SecTrailer]
    authentication_token: t.Optional[bytes]


class ContextResultCode(enum.IntEnum):
    ACCEPTANCE = 0
    USER_REJECTION = 1
    PROVIDER_REJECTION = 2


class ProviderReason(enum.IntEnum):
    REASON_NOT_SPECIFIED = 0
    ABSTRACT_SYNTAX_NOT_SUPPORTED = 1
    PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED = 2
    LOCAL_LIMIT_EXCEEDED = 3


@dataclasses.dataclass(frozen=True)
class ContextResult:
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    result: ContextResultCode
    reason: ProviderReason
    syntax: uuid.UUID
    syntax_version: int

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> ContextResult:
        view = memoryview(data)

        return ContextResult(
            result=ContextResultCode(int.from_bytes(view[:2], byteorder="little")),
            reason=ProviderReason(int.from_bytes(view[2:4], byteorder="little")),
            syntax=uuid.UUID(bytes_le=view[4:20].tobytes()),
            syntax_version=int.from_bytes(view[20:24], byteorder="little"),
        )


@dataclasses.dataclass(frozen=True)
class BindAck:
    # https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
    header: PDUHeader
    max_xmit_frag: int
    max_recv_frag: int
    assoc_group: int
    sec_addr: str
    results: t.List[ContextResult]
    auth_verifier: t.Optional[bytes]

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> BindAck:
        view = memoryview(data)

        header = PDUHeader.unpack(view)
        view = view[16:]

        if header.packet_type != PacketType.BIND_ACK:
            raise ValueError(f"Expecting PDU packet type BIND_ACK but got {header.packet_type.name}")

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

        auth_verifier = None
        if header.auth_len:
            auth_verifier = view[: header.auth_len].tobytes()

        return BindAck(
            header=header,
            max_xmit_frag=max_xmit_frag,
            max_recv_frag=max_recv_frag,
            assoc_group=assoc_group,
            sec_addr=sec_addr,
            results=results,
            auth_verifier=auth_verifier,
        )


class PacketType(enum.IntEnum):
    REQUEST = 0
    PING = 1
    RESPONSE = 2
    FAULT = 3
    WORKING = 4
    NOCALL = 5
    REJECT = 6
    ACK = 7
    CL_CANCEL = 8
    FACK = 9
    CANCEL_ACK = 10
    BIND = 11
    BIND_ACK = 12
    BIND_NAK = 13
    ALTER_CONTEXT = 14
    ALTER_CONTEXT_RESP = 15
    SHUTDOWN = 17
    CO_CANCEL = 18
    ORPHANED = 19


class PacketFlags(enum.IntFlag):
    PFC_FIRST_FRAG = 0x01
    PFC_LAST_FRAG = 0x02
    PFC_PENDING_CANCEL = 0x04
    PFC_SUPPORT_HEADER_SIGN = 0x04  # MS-RPCE extension used in Bind/AlterContext
    PFC_RESERVED_1 = 0x08
    PFC_CONC_MPX = 0x10
    PFC_DID_NOT_EXECUTE = 0x20
    PFC_MAYBE = 0x40
    PFC_OBJECT_UUID = 0x80


class SecurityProvider(enum.IntEnum):
    RPC_C_AUTHN_NONE = 0x00
    RPC_C_AUTHN_GSS_NEGOTIATE = 0x09
    RPC_C_AUTHN_WINNT = 0x0A
    RPC_C_AUTHN_GSS_SCHANNEL = 0x0E
    RPC_C_AUTHN_GSS_KERBEROS = 0x10
    RPC_C_AUTHN_NETLOGON = 0x44
    RPC_C_AUTHN_DEFAULT = 0xFF


class AuthenticationLevel(enum.IntEnum):
    RPC_C_AUTHN_LEVEL_DEFAULT = 0x00
    RPC_C_AUTHN_LEVEL_NONE = 0x01
    RPC_C_AUTHN_LEVEL_CONNECT = 0x02
    RPC_C_AUTHN_LEVEL_CALL = 0x03
    RPC_C_AUTHN_LEVEL_PKT = 0x04
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 0x05
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 0x06


@dataclasses.dataclass(frozen=True)
class SecTrailer:
    type: SecurityProvider
    level: AuthenticationLevel
    pad_length: int
    context_id: int
