# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
import concurrent.futures
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
    ContextResultCode,
    SyntaxId,
)
from ._pdu import PDU, DataRep, Fault, PacketFlags, PacketType, PDUHeader, SecTrailer
from ._request import Request, Response
from ._verification import VerificationTrailer

NDR = SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)
NDR64 = SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)

T = t.TypeVar("T")


async def async_create_rpc_connection(
    server: str,
    port: int = 135,
    connection_timeout: int = 5,
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    auth_protocol: t.Optional[str] = None,
) -> AsyncRpcClient:
    auth_provider = None
    if auth_protocol:
        auth_provider = AuthenticationProvider(username, password, server, auth_protocol)

    conn_future = asyncio.open_connection(server, port=port)
    reader, writer = await asyncio.wait_for(conn_future, connection_timeout)

    return AsyncRpcClient(reader, writer, auth_provider)


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


class RpcClient:
    def __init__(
        self,
        auth: t.Optional[AuthenticationProvider] = None,
    ) -> None:
        self._auth = auth
        self._sign_header = False

    def _create_pdu_header(
        self,
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
            frag_len=0,  # Set after building the PDU
            auth_len=auth_len,
            call_id=call_id,
        )

    def _create_bind(
        self,
        contexts: t.List[ContextElement],
        sec_trailer: t.Optional[SecTrailer] = None,
    ) -> Bind:
        flags = PacketFlags.NONE

        auth_len = 0
        if sec_trailer:
            self._sign_header = True
            flags |= PacketFlags.PFC_SUPPORT_HEADER_SIGN
            auth_len = len(sec_trailer.auth_value)

        return Bind(
            header=self._create_pdu_header(
                PacketType.BIND,
                auth_len,
                1,
                flags=flags,
            ),
            sec_trailer=sec_trailer,
            max_xmit_frag=5840,
            max_recv_frag=5840,
            assoc_group=0,
            contexts=contexts,
        )

    def _create_alter_context(
        self,
        contexts: t.List[ContextElement],
        sec_trailer: SecTrailer,
    ) -> AlterContext:
        flags = PacketFlags.PFC_SUPPORT_HEADER_SIGN if self._sign_header else PacketFlags.NONE

        return AlterContext(
            header=self._create_pdu_header(
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

    def _create_request(
        self,
        context_id: int,
        opnum: int,
        stub_data: bytes,
        *,
        verification_trailer: t.Optional[VerificationTrailer] = None,
    ) -> tuple[Request, t.Optional[tuple[int, int]]]:
        if verification_trailer:
            # The verification trailer needs to be aligned to the next 4 byte
            # boundary.
            padding = -len(stub_data) % 4
            stub_data += (b"\x00" * padding) + verification_trailer.pack()

        auth_len = 0
        sec_trailer = None
        encrypt_offsets = None
        if self._auth:
            # If the security trailer is present it must be aligned to the
            # next 16 byte boundary after the stub data. This padding is
            # included as part of the stub data to be encrypted.
            pad_length = -len(stub_data) % 16
            stub_data += b"\x00" * pad_length
            sec_trailer = self._auth.get_empty_trailer(pad_length)
            auth_len = len(sec_trailer.auth_value)
            encrypt_offsets = (24, 24 + len(stub_data))

        return (
            Request(
                header=self._create_pdu_header(
                    PacketType.REQUEST,
                    auth_len,
                    1,
                ),
                sec_trailer=sec_trailer,
                alloc_hint=len(stub_data),
                context_id=context_id,
                opnum=opnum,
                obj=None,
                stub_data=stub_data,
            ),
            encrypt_offsets,
        )

    def _prepare_pdu(
        self,
        pdu: PDU,
        encrypt_offsets: t.Optional[tuple[int, int]] = None,
    ) -> t.Union[bytes, bytearray]:
        b_pdu: t.Union[bytes, bytearray] = bytearray(pdu.pack())
        view = memoryview(b_pdu)
        view[8:10] = len(b_pdu).to_bytes(2, byteorder="little")

        if self._auth and encrypt_offsets:
            view = memoryview(b_pdu)
            header = view[: encrypt_offsets[0]].tobytes()
            body = view[encrypt_offsets[0] : encrypt_offsets[1]].tobytes()
            sec_trailer = view[encrypt_offsets[1] : encrypt_offsets[1] + 8].tobytes()
            b_pdu = self._auth.wrap(header, body, sec_trailer, self._sign_header)

        return b_pdu

    def _process_bind_ack(
        self,
        ack: t.Union[BindAck, AlterContextResponse],
        contexts: t.List[ContextElement],
    ) -> tuple[t.List[ContextElement], t.Optional[bytes]]:
        alter_contexts = []
        for idx, c in enumerate(contexts):
            context_res = ack.results[idx]
            if context_res.result == ContextResultCode.ACCEPTANCE:
                alter_contexts.append(c)

        if not ack.header.packet_flags & PacketFlags.PFC_SUPPORT_HEADER_SIGN:
            self._sign_header = False

        auth_value = None
        if ack.sec_trailer:
            auth_value = ack.sec_trailer.auth_value

        return alter_contexts, auth_value

    def _process_response(
        self,
        response: bytearray,
        pdu_header: PDUHeader,
        resp_type: t.Type[T],
        encrypt_offsets: t.Optional[tuple[int, int]] = None,
    ) -> T:
        if self._auth and encrypt_offsets and pdu_header.auth_len:
            view = memoryview(response)

            sec_trailer_offset = pdu_header.frag_len - (pdu_header.auth_len + 8)
            header = view[: encrypt_offsets[0]].tobytes()
            body = view[encrypt_offsets[0] : sec_trailer_offset].tobytes()
            sec_trailer = view[sec_trailer_offset : sec_trailer_offset + 8].tobytes()
            signature = view[sec_trailer_offset + 8 :].tobytes()
            dec_stub = self._auth.unwrap(header, body, sec_trailer, signature, self._sign_header)
            response[encrypt_offsets[0] : sec_trailer_offset] = dec_stub

        pdu_resp = PDU.unpack(response)
        if isinstance(pdu_resp, BindNak):
            raise Exception(f"Received BindNack with reason 0x{pdu_resp.reject_reason:08X}")
        elif isinstance(pdu_resp, Fault):
            raise Exception(f"Receive Fault with status 0x{pdu_resp.status:08X}")
        elif not isinstance(pdu_resp, resp_type):
            raise Exception(
                f"Received unexpected PDU response of {type(pdu_resp).__name__} when expecting {resp_type.__name__}"
            )

        return pdu_resp


class AsyncRpcClient(RpcClient):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        auth: t.Optional[AuthenticationProvider] = None,
    ) -> None:
        super().__init__(auth)
        self._reader = reader
        self._writer = writer

    async def __aenter__(self) -> AsyncRpcClient:
        return self

    async def __aexit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        await self.close()

    async def close(self) -> None:
        self._writer.close()
        await self._writer.wait_closed()

    async def bind(
        self,
        contexts: t.List[ContextElement],
    ) -> BindAck:
        sec_trailer = None
        if self._auth:
            sec_trailer = await self._wrap_sync(self._auth.step)

        bind = self._create_bind(contexts, sec_trailer)
        bind_ack = await self._send_pdu(bind, BindAck)

        if not self._auth:
            return bind_ack

        final_contexts, in_token = self._process_bind_ack(bind_ack, contexts)

        while not self._auth.complete:
            sec_trailer = await self._wrap_sync(self._auth.step, (in_token or b""))
            if not sec_trailer.auth_value:
                break

            alter_context = self._create_alter_context(final_contexts, sec_trailer)
            alter_resp = await self._send_pdu(alter_context, AlterContextResponse)
            _, in_token = self._process_bind_ack(alter_resp, final_contexts)

        return bind_ack

    async def request(
        self,
        context_id: int,
        opnum: int,
        stub_data: bytes,
        *,
        verification_trailer: t.Optional[VerificationTrailer] = None,
    ) -> Response:
        req, encrypt_offsets = self._create_request(
            context_id,
            opnum,
            stub_data,
            verification_trailer=verification_trailer,
        )
        return await self._send_pdu(req, Response, encrypt_offsets=encrypt_offsets)

    async def _send_pdu(
        self,
        pdu: PDU,
        resp_type: t.Type[T],
        *,
        encrypt_offsets: t.Optional[tuple[int, int]] = None,
    ) -> T:
        b_pdu = self._prepare_pdu(pdu, encrypt_offsets)

        self._writer.write(b_pdu)
        await self._writer.drain()

        header = await self._reader.readexactly(16)
        resp_header = PDUHeader.unpack(header)

        resp = bytearray(resp_header.frag_len)
        view = memoryview(resp)
        view[:16] = header
        view[16:] = await self._reader.readexactly(len(resp) - 16)

        return self._process_response(resp, resp_header, resp_type, encrypt_offsets)

    async def _wrap_sync(
        self,
        func: t.Callable[..., T],
        *args: t.Any,
    ) -> T:
        exec = concurrent.futures.ThreadPoolExecutor()
        return await asyncio.get_event_loop().run_in_executor(exec, func, *args)


class SyncRpcClient(RpcClient):
    def __init__(
        self,
        sock: socket.socket,
        auth: t.Optional[AuthenticationProvider] = None,
    ) -> None:
        super().__init__(auth)
        self._sock = sock

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
        sec_trailer = None
        if self._auth:
            sec_trailer = self._auth.step()

        bind = self._create_bind(contexts, sec_trailer)
        bind_ack = self._send_pdu(bind, BindAck)

        if not self._auth:
            return bind_ack

        final_contexts, in_token = self._process_bind_ack(bind_ack, contexts)

        while not self._auth.complete:
            sec_trailer = self._auth.step(in_token or b"")
            if not sec_trailer.auth_value:
                break

            alter_context = self._create_alter_context(final_contexts, sec_trailer)
            alter_resp = self._send_pdu(alter_context, AlterContextResponse)
            _, in_token = self._process_bind_ack(alter_resp, final_contexts)

        return bind_ack

    def request(
        self,
        context_id: int,
        opnum: int,
        stub_data: bytes,
        *,
        verification_trailer: t.Optional[VerificationTrailer] = None,
    ) -> Response:
        req, encrypt_offsets = self._create_request(
            context_id,
            opnum,
            stub_data,
            verification_trailer=verification_trailer,
        )
        return self._send_pdu(req, Response, encrypt_offsets=encrypt_offsets)

    def _send_pdu(
        self,
        pdu: PDU,
        resp_type: t.Type[T],
        *,
        encrypt_offsets: t.Optional[tuple[int, int]] = None,
    ) -> T:
        b_pdu = self._prepare_pdu(pdu, encrypt_offsets)
        self._sock.sendall(b_pdu)

        header = self._sock.recv(16)
        resp_header = PDUHeader.unpack(header)

        resp = bytearray(resp_header.frag_len)
        view = memoryview(resp)
        view[:16] = header
        view = view[16:]

        while view:
            read = self._sock.recv_into(view)
            view = view[read:]

        return self._process_response(resp, resp_header, resp_type, encrypt_offsets)
