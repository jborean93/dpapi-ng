# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import socket
import typing as t
import uuid

from ._auth import AuthenticationProvider
from ._bind import (
    AlterContext,
    AlterContextResponse,
    Bind,
    BindAck,
    BindNak,
    ContextElement,
    SyntaxId,
)
from ._pdu import PDU, DataRep, Fault, PacketFlags, PacketType, PDUHeader, SecTrailer
from ._request import Request, Response

NDR = SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)
NDR64 = SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)

T = t.TypeVar("T")


class BindTimeFeatureNegotiation(enum.IntFlag):
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/cef529cc-77b5-4794-85dc-91e1467e80f0
    NONE = 0x00
    SECURITY_CONTEXT_MULTIPLEXING = 0x01
    KEEP_CONNECTION_ON_ORPHAN = 0x02


def _create_pdu_header(
    packet_type: PacketType,
    auth_len: int,
    call_id: int,
    *,
    flags: PacketFlags = PacketFlags.NONE,
) -> PDUHeader:
    return PDUHeader(
        version=5,
        version_minor=0,
        packet_type=packet_type,
        packet_flags=flags | PacketFlags.PFC_FIRST_FRAG | PacketFlags.PFC_LAST_FRAG,
        data_rep=DataRep(),
        frag_len=0,  # Set after the payload is built
        auth_len=auth_len,
        call_id=call_id,
    )


def bind_time_feature_negotiation(
    flags: BindTimeFeatureNegotiation = BindTimeFeatureNegotiation.NONE,
) -> SyntaxId:
    """Creates the Bind Time Feature Negotiation Syntax value from the flags specified."""
    return SyntaxId(
        uuid=uuid.UUID(fields=(0x6CB71C2C, 0x9812, 0x4540, flags, 0, 0)),
        version=1,
        version_minor=0,
    )


def create_rpc_connection(
    server: str,
    port: int = 135,
    connection_timeout: int = 5,
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    auth_protocol: t.Optional[str] = None,
) -> SyncRpcClient:
    auth_provider = None
    if auth_protocol:
        auth_provider = AuthenticationProvider(username, password, server, auth_protocol)

    sock = socket.create_connection(
        (server, port),
        timeout=connection_timeout,
    )
    sock.settimeout(None)

    return SyncRpcClient(sock, auth_provider)


class SyncRpcClient:
    def __init__(
        self,
        sock: socket.socket,
        auth: t.Optional[AuthenticationProvider] = None,
    ) -> None:
        self._sock = sock
        self._auth = auth
        self._sign_header = False

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
        contexts: t.List[ContextElement],
    ) -> BindAck:
        flags = PacketFlags.NONE
        sec_trailer = None

        if self._auth:
            self._sign_header = True
            flags |= PacketFlags.PFC_SUPPORT_HEADER_SIGN
            sec_trailer = self._auth.step()

        bind = Bind(
            header=_create_pdu_header(
                PacketType.BIND,
                len(sec_trailer.auth_value) if sec_trailer else 0,
                1,
                flags=flags,
            ),
            sec_trailer=sec_trailer,
            max_xmit_frag=5840,
            max_recv_frag=5840,
            assoc_group=0,
            contexts=contexts,
        )
        bind_ack = self._send_pdu(bind.pack(), BindAck)

        if self._auth:
            if not bind_ack.header.packet_flags & PacketFlags.PFC_SUPPORT_HEADER_SIGN:
                self._sign_header = False
                flags &= ~PacketFlags.PFC_SUPPORT_HEADER_SIGN

            ack = bind_ack
            while not self._auth.complete:
                if not ack.sec_trailer:
                    raise Exception("Expecting sec_trailer on bind ack but received none")

                sec_trailer = self._auth.step(ack.sec_trailer.auth_value)
                if not sec_trailer.auth_value:
                    break

                alter_context = AlterContext(
                    header=_create_pdu_header(
                        PacketType.ALTER_CONTEXT,
                        len(sec_trailer.auth_value),
                        1,
                        flags=flags,
                    ),
                    sec_trailer=sec_trailer,
                    max_xmit_frag=5840,
                    max_recv_frag=5840,
                    assoc_group=0,
                    contexts=contexts,
                )
                ack = self._send_pdu(alter_context.pack(), AlterContextResponse)

        return bind_ack

    def request(
        self,
        context_id: int,
        opnum: int,
        stub_data: bytes,
    ) -> Response:
        sec_trailer = None
        if self._auth:
            pad_length = -len(stub_data) % 16
            stub_data += b"\x00" * pad_length
            sec_trailer = self._auth.get_empty_trailer(pad_length)

        req = Request(
            header=_create_pdu_header(
                PacketType.REQUEST,
                len(sec_trailer.auth_value) if sec_trailer else 0,
                1,
            ),
            sec_trailer=sec_trailer,
            alloc_hint=len(stub_data),
            context_id=context_id,
            opnum=opnum,
            obj=None,
            stub_data=stub_data,
        )

        if self._auth:
            b_req = req.pack()

            sec_trailer_data = b_req[-(req.header.auth_len + 8) : -req.header.auth_len]
            b_req = self._auth.wrap(b_req[:24], stub_data, sec_trailer_data, self._sign_header)

            resp = self._send_pdu(b_req, Response)

        else:
            resp = self._send_pdu(req.pack(), Response)

        return resp

    def _send_pdu(
        self,
        pdu: bytearray,
        resp_type: t.Type[T],
    ) -> T:
        memoryview(pdu)[8:10] = len(pdu).to_bytes(2, byteorder="little")

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

        pdu_resp = PDU.unpack(resp)
        if isinstance(pdu_resp, BindNak):
            raise Exception(f"Received BindNack with reason 0x{pdu_resp.reject_reason:08X}")
        elif isinstance(pdu_resp, Fault):
            raise Exception(f"Receive Fault with status 0x{pdu_resp.status:08X}")
        elif not isinstance(pdu_resp, resp_type):
            raise ValueError(
                f"Received unexpected PDU response of {type(pdu_resp).__name__} when expecting {resp_type.__name__}"
            )

        return pdu_resp
