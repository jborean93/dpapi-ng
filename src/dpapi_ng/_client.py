# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t
import uuid

from ._blob import DPAPINGBlob
from ._crypto import cek_decrypt, content_decrypt
from ._epm import EPM, EptMap, EptMapResult, TCPFloor, build_tcpip_tower
from ._gkdi import ISD_KEY, GetKey, GroupKeyEnvelope
from ._rpc import (
    NDR,
    NDR64,
    CommandFlags,
    CommandPContext,
    ContextElement,
    ContextResultCode,
    VerificationTrailer,
    async_create_rpc_connection,
    bind_time_feature_negotiation,
    create_rpc_connection,
)


async def _async_get_key(
    server: str,
    target_sd: bytes,
    root_key_id: t.Optional[uuid.UUID],
    l0: int = -1,
    l1: int = -1,
    l2: int = -1,
) -> GroupKeyEnvelope:
    async with (await async_create_rpc_connection(server) as rpc):
        context_id = 0
        ack = await rpc.bind(
            contexts=[
                ContextElement(
                    context_id=context_id,
                    abstract_syntax=EPM,
                    transfer_syntaxes=[NDR64],
                ),
            ]
        )
        if ack.results[0].result != ContextResultCode.ACCEPTANCE:
            raise Exception("Unable to find a common context for ept_map")

        ept_map = EptMap(
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

        resp = await rpc.request(context_id, ept_map.opnum, ept_map.pack())
        map_response = EptMapResult.unpack(resp.stub_data)
        if map_response.status != 0:
            raise Exception(f"Receive error during ept_map call 0x{map_response.status:08X}")

        isd_key_port = None
        for tower in map_response.towers:
            for floor in tower:
                if isinstance(floor, TCPFloor):
                    isd_key_port = floor.port
                    break

            if isd_key_port is not None:
                break

        if isd_key_port is None:
            raise Exception("Did not find expected TCP Port in ept_map response")

    async with (
        await async_create_rpc_connection(
            server,
            isd_key_port,
            auth_protocol="negotiate",
        ) as rpc
    ):
        ack = await rpc.bind(
            contexts=[
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
        )
        context_id = -1
        for idx, c in enumerate(ack.results):
            if c.result == ContextResultCode.ACCEPTANCE:
                context_id = idx
                break

        if context_id == -1:
            raise Exception("Failed to bind to any ISD KEY context")

        get_key = GetKey(target_sd, root_key_id, l0, l1, l2)
        verification_trailer = VerificationTrailer(
            [
                CommandPContext(
                    flags=CommandFlags.SEC_VT_COMMAND_END,
                    interface_id=ISD_KEY,
                    transfer_syntax=NDR64,
                ),
            ]
        )

        resp = await rpc.request(
            context_id,
            get_key.opnum,
            get_key.pack(),
            verification_trailer=verification_trailer,
        )
        pad_length = 0
        if resp.sec_trailer:
            pad_length = resp.sec_trailer.pad_length
        raw_resp = resp.stub_data[:-pad_length]
        return GetKey.unpack_response(raw_resp)


def _sync_get_key(
    server: str,
    target_sd: bytes,
    root_key_id: t.Optional[uuid.UUID] = None,
    l0: int = -1,
    l1: int = -1,
    l2: int = -1,
) -> GroupKeyEnvelope:
    with create_rpc_connection(server) as rpc:
        context_id = 0
        ack = rpc.bind(
            contexts=[
                ContextElement(
                    context_id=context_id,
                    abstract_syntax=EPM,
                    transfer_syntaxes=[NDR64],
                ),
            ]
        )
        if ack.results[0].result != ContextResultCode.ACCEPTANCE:
            raise Exception("Unable to find a common context for ept_map")

        ept_map = EptMap(
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

        resp = rpc.request(context_id, ept_map.opnum, ept_map.pack())
        map_response = EptMapResult.unpack(resp.stub_data)
        if map_response.status != 0:
            raise Exception(f"Receive error during ept_map call 0x{map_response.status:08X}")

        isd_key_port = None
        for tower in map_response.towers:
            for floor in tower:
                if isinstance(floor, TCPFloor):
                    isd_key_port = floor.port
                    break

            if isd_key_port is not None:
                break

        if isd_key_port is None:
            raise Exception("Did not find expected TCP Port in ept_map response")

    with create_rpc_connection(
        server,
        isd_key_port,
        auth_protocol="negotiate",
    ) as rpc:
        ack = rpc.bind(
            contexts=[
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
        )
        context_id = -1
        for idx, c in enumerate(ack.results):
            if c.result == ContextResultCode.ACCEPTANCE:
                context_id = idx
                break

        if context_id == -1:
            raise Exception("Failed to bind to any ISD KEY context")

        get_key = GetKey(target_sd, root_key_id, l0, l1, l2)
        verification_trailer = VerificationTrailer(
            [
                CommandPContext(
                    flags=CommandFlags.SEC_VT_COMMAND_END,
                    interface_id=ISD_KEY,
                    transfer_syntax=NDR64,
                ),
            ]
        )

        resp = rpc.request(
            context_id,
            get_key.opnum,
            get_key.pack(),
            verification_trailer=verification_trailer,
        )
        pad_length = 0
        if resp.sec_trailer:
            pad_length = resp.sec_trailer.pad_length
        raw_resp = resp.stub_data[:-pad_length]
        return GetKey.unpack_response(raw_resp)


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
) -> bytes:
    """

    Raises:
        ValueError:
        NotImplementedError:
    """
    blob = DPAPINGBlob.unpack(data)

    rk = _sync_get_key(
        "dc01.domain.test",
        blob.security_descriptor,
        blob.key_identifier.root_key_identifier,
        blob.key_identifier.l0,
        blob.key_identifier.l1,
        blob.key_identifier.l2,
    )

    return _decrypt_blob(blob, rk)


async def async_ncrypt_unprotect_secret(
    data: bytes,
) -> bytes:
    """

    Raises:
        ValueError:
        NotImplementedError:
    """
    blob = DPAPINGBlob.unpack(data)

    rk = await _async_get_key(
        "dc01.domain.test",
        blob.security_descriptor,
        blob.key_identifier.root_key_identifier,
        blob.key_identifier.l0,
        blob.key_identifier.l1,
        blob.key_identifier.l2,
    )

    return _decrypt_blob(blob, rk)
