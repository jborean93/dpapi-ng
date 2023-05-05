# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t
import uuid

from ._blob import DPAPINGBlob
from ._crypto import cek_decrypt, content_decrypt
from ._dns import async_lookup_dc, lookup_dc
from ._epm import EPM, EptMap, EptMapResult, TCPFloor, build_tcpip_tower
from ._gkdi import ISD_KEY, GetKey, GroupKeyEnvelope
from ._rpc import (
    NDR,
    NDR64,
    BindAck,
    CommandFlags,
    CommandPContext,
    ContextElement,
    ContextResultCode,
    Response,
    VerificationTrailer,
    async_create_rpc_connection,
    bind_time_feature_negotiation,
    create_rpc_connection,
)

_EPM_CONTEXTS = [
    ContextElement(
        context_id=0,
        abstract_syntax=EPM,
        transfer_syntaxes=[NDR64],
    )
]

_ISD_KEY_CONTEXTS = [
    ContextElement(
        context_id=0,
        abstract_syntax=ISD_KEY,
        transfer_syntaxes=[NDR64],
    ),
    ContextElement(
        context_id=1,
        abstract_syntax=ISD_KEY,
        transfer_syntaxes=[bind_time_feature_negotiation()],
    ),
]

_EPT_MAP_ISD_KEY = EptMap(
    obj=None,
    tower=build_tcpip_tower(
        service=ISD_KEY,
        data_rep=NDR,
        port=135,
        addr=0,
    ),
    entry_handle=None,
    max_towers=4,
)

_VERIFICATION_TRAILER = VerificationTrailer(
    [
        CommandPContext(
            flags=CommandFlags.SEC_VT_COMMAND_END,
            interface_id=ISD_KEY,
            transfer_syntax=NDR64,
        ),
    ]
)


def _process_bind_result(
    requested_contexts: t.List[ContextElement],
    bind_ack: BindAck,
    desired_context: int,
) -> None:
    accepted_ids = []
    for idx, c in enumerate(bind_ack.results):
        if c.result == ContextResultCode.ACCEPTANCE:
            ctx = requested_contexts[idx]
            accepted_ids.append(ctx.context_id)

    if desired_context not in accepted_ids:
        raise Exception("Failed to bind to desired context")

    return


def _process_ept_map_result(
    response: Response,
) -> int:
    map_response = EptMapResult.unpack(response.stub_data)
    if map_response.status != 0:
        raise Exception(f"Receive error during ept_map call 0x{map_response.status:08X}")

    for tower in map_response.towers:
        for floor in tower:
            if isinstance(floor, TCPFloor):
                return floor.port

    raise Exception("Did not find expected TCP Port in ept_map response")


def _process_get_key_result(
    response: Response,
) -> GroupKeyEnvelope:
    pad_length = 0
    if response.sec_trailer:
        pad_length = response.sec_trailer.pad_length
    raw_resp = response.stub_data[:-pad_length]
    return GetKey.unpack_response(raw_resp)


async def _async_get_key(
    server: str,
    target_sd: bytes,
    root_key_id: t.Optional[uuid.UUID],
    l0: int = -1,
    l1: int = -1,
    l2: int = -1,
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    auth_protocol: str = "negotiate",
) -> GroupKeyEnvelope:
    async with (await async_create_rpc_connection(server) as rpc):
        context_id = _EPM_CONTEXTS[0].context_id
        ack = await rpc.bind(contexts=_EPM_CONTEXTS)
        _process_bind_result(_EPM_CONTEXTS, ack, context_id)

        ept_map = _EPT_MAP_ISD_KEY
        resp = await rpc.request(context_id, ept_map.opnum, ept_map.pack())
        isd_key_port = _process_ept_map_result(resp)

    async with (
        await async_create_rpc_connection(
            server,
            isd_key_port,
            username=username,
            password=password,
            auth_protocol=auth_protocol,
        ) as rpc
    ):
        context_id = _ISD_KEY_CONTEXTS[0].context_id
        ack = await rpc.bind(contexts=_ISD_KEY_CONTEXTS)
        _process_bind_result(_ISD_KEY_CONTEXTS, ack, context_id)

        get_key = GetKey(target_sd, root_key_id, l0, l1, l2)
        resp = await rpc.request(
            context_id,
            get_key.opnum,
            get_key.pack(),
            verification_trailer=_VERIFICATION_TRAILER,
        )
        return _process_get_key_result(resp)


def _sync_get_key(
    server: str,
    target_sd: bytes,
    root_key_id: t.Optional[uuid.UUID] = None,
    l0: int = -1,
    l1: int = -1,
    l2: int = -1,
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    auth_protocol: str = "negotiate",
) -> GroupKeyEnvelope:
    with create_rpc_connection(server) as rpc:
        context_id = _EPM_CONTEXTS[0].context_id
        ack = rpc.bind(contexts=_EPM_CONTEXTS)
        _process_bind_result(_EPM_CONTEXTS, ack, context_id)

        ept_map = _EPT_MAP_ISD_KEY
        resp = rpc.request(0, ept_map.opnum, ept_map.pack())
        isd_key_port = _process_ept_map_result(resp)

    with create_rpc_connection(
        server,
        isd_key_port,
        username=username,
        password=password,
        auth_protocol=auth_protocol,
    ) as rpc:
        context_id = _ISD_KEY_CONTEXTS[0].context_id
        ack = rpc.bind(contexts=_ISD_KEY_CONTEXTS)
        _process_bind_result(_ISD_KEY_CONTEXTS, ack, context_id)

        get_key = GetKey(target_sd, root_key_id, l0, l1, l2)
        resp = rpc.request(
            context_id,
            get_key.opnum,
            get_key.pack(),
            verification_trailer=_VERIFICATION_TRAILER,
        )
        return _process_get_key_result(resp)


def _decrypt_blob(
    blob: DPAPINGBlob,
    key: GroupKeyEnvelope,
) -> bytes:
    kek = key.get_kek(blob.key_identifier)

    # With the kek we can unwrap the encrypted cek in the LAPS payload.
    cek = cek_decrypt(
        blob.enc_cek_algorithm,
        blob.enc_cek_parameters,
        kek,
        blob.enc_cek,
    )

    # With the cek we can decrypt the encrypted content in the LAPS payload.
    return content_decrypt(
        blob.enc_content_algorithm,
        blob.enc_content_parameters,
        cek,
        blob.enc_content,
    )


def ncrypt_unprotect_secret(
    data: bytes,
    server: t.Optional[str] = None,
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    auth_protocol: str = "negotiate",
) -> bytes:
    """Decrypt DPAPI-NG Blob.

    Decrypts the DPAPI-NG blob provided. This is meant to replicate the Win32
    API `NCryptUnprotectSecret`_.

    Decrypting the DPAPI-NG blob requires making an RPC call to the domain
    controller for the domain the blob was created in. It will attempt this
    by looking up the DC through an SRV lookup but ``server`` can be specified
    to avoid this SRV lookup.

    The RPC call requires the caller to authenticate before the key information
    is provided. This user must be one who is authorised to decrypt the secret.
    Explicit credentials can be specified, if none are the current Kerberos
    ticket retrieved by ``kinit`` will be used instead. Make sure to install
    the Kerberos extras package ``dpapi-ng[kerberos]`` to ensure Kerberos auth
    can be used.

    Args:
        data: The DPAPI-NG blob to decrypt.
        server: The domain controller to lookup the root key info.
        username: The username to decrypt the DPAPI-NG blob as.
        password: The password for the user.
        auth_protocol: The authentication protocol to use, defaults to
            ``negotiate`` but can be ``kerberos`` or ``ntlm``.

    Returns:
        bytes: The decrypt DPAPI-NG data.

    Raises:
        ValueError: An invalid data structure was found.
        NotImplementedError: An unknown value was found and has not been
            implemented yet.

    _NCryptUnprotectSecret:
        https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret
    """
    blob = DPAPINGBlob.unpack(data)

    if not server:
        srv = lookup_dc(blob.key_identifier.domain_name)
        server = srv.target

    rk = _sync_get_key(
        server,
        blob.security_descriptor,
        blob.key_identifier.root_key_identifier,
        blob.key_identifier.l0,
        blob.key_identifier.l1,
        blob.key_identifier.l2,
        username=username,
        password=password,
        auth_protocol=auth_protocol,
    )

    return _decrypt_blob(blob, rk)


async def async_ncrypt_unprotect_secret(
    data: bytes,
    server: t.Optional[str] = None,
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    auth_protocol: str = "negotiate",
) -> bytes:
    """Decrypt DPAPI-NG Blob.

    Decrypts the DPAPI-NG blob provided. This is meant to replicate the Win32
    API `NCryptUnprotectSecret`_.

    Decrypting the DPAPI-NG blob requires making an RPC call to the domain
    controller for the domain the blob was created in. It will attempt this
    by looking up the DC through an SRV lookup but ``server`` can be specified
    to avoid this SRV lookup.

    The RPC call requires the caller to authenticate before the key information
    is provided. This user must be one who is authorised to decrypt the secret.
    Explicit credentials can be specified, if none are the current Kerberos
    ticket retrieved by ``kinit`` will be used instead. Make sure to install
    the Kerberos extras package ``dpapi-ng[kerberos]`` to ensure Kerberos auth
    can be used.

    Args:
        data: The DPAPI-NG blob to decrypt.
        server: The domain controller to lookup the root key info.
        username: The username to decrypt the DPAPI-NG blob as.
        password: The password for the user.
        auth_protocol: The authentication protocol to use, defaults to
            ``negotiate`` but can be ``kerberos`` or ``ntlm``.

    Returns:
        bytes: The decrypt DPAPI-NG data.

    Raises:
        ValueError: An invalid data structure was found.
        NotImplementedError: An unknown value was found and has not been
            implemented yet.

    _NCryptUnprotectSecret:
        https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret
    """
    blob = DPAPINGBlob.unpack(data)

    if not server:
        srv = await async_lookup_dc(blob.key_identifier.domain_name)
        server = srv.target

    rk = await _async_get_key(
        server,
        blob.security_descriptor,
        blob.key_identifier.root_key_identifier,
        blob.key_identifier.l0,
        blob.key_identifier.l1,
        blob.key_identifier.l2,
        username=username,
        password=password,
        auth_protocol=auth_protocol,
    )

    return _decrypt_blob(blob, rk)
