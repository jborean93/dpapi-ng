# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

import spnego
import spnego.iov

from ._pdu import AuthenticationLevel, SecTrailer, SecurityProvider


class AuthenticationProvider:
    def __init__(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        hostname: str = "unspecified",
        protocol: str = "negotiate",
    ) -> None:
        self.ctx = spnego.client(
            username,
            password,
            hostname=hostname,
            service="host",
            protocol=protocol,
            context_req=spnego.ContextReq.default | spnego.ContextReq.dce_style,
        )
        self.provider = {
            "negotiate": SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            "ntlm": SecurityProvider.RPC_C_AUTHN_GSS_KERBEROS,
            "kerberos": SecurityProvider.RPC_C_AUTHN_WINNT,
        }[protocol]
        self._header_length = 0

    @property
    def complete(self) -> bool:
        return self.ctx.complete

    def step(
        self,
        in_token: t.Optional[bytes] = None,
    ) -> SecTrailer:
        out_token = self.ctx.step(in_token) or b""
        return SecTrailer(
            type=self.provider,
            level=AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=0,
            context_id=0,
            auth_value=out_token,
        )

    def get_empty_trailer(self, pad_length: int) -> SecTrailer:
        header_length = self._header_length = self._header_length or self.ctx.query_message_sizes().header
        return SecTrailer(
            type=self.provider,
            level=AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=pad_length,
            context_id=0,
            auth_value=b"\x00" * header_length,
        )

    def wrap(
        self,
        header: bytes,
        body: bytes,
        trailer: bytes,
        sign_header: bool,
    ) -> bytes:
        sign_buffer_type = spnego.iov.BufferType.sign_only if sign_header else spnego.iov.BufferType.data_readonly
        res = self.ctx.wrap_iov(
            [
                (sign_buffer_type, header),
                body,
                (sign_buffer_type, trailer),
                spnego.iov.BufferType.header,
            ],
            encrypt=True,
            qop=None,
        )

        return b"".join(
            [
                header,
                res.buffers[1].data or b"",
                trailer,
                res.buffers[3].data or b"",
            ]
        )

    def unwrap(
        self,
        header: bytes,
        body: bytes,
        trailer: bytes,
        signature: bytes,
        sign_header: bool,
    ) -> bytes:
        sign_buffer_type = spnego.iov.BufferType.sign_only if sign_header else spnego.iov.BufferType.data_readonly
        res = self.ctx.unwrap_iov(
            [
                (sign_buffer_type, header),
                body,
                (sign_buffer_type, trailer),
                (spnego.iov.BufferType.header, signature),
            ],
        )

        return res.buffers[1].data or b""
