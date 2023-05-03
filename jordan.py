import typing as t

from dpapi_ng._rpc._bind import ContextElement, SyntaxId
from dpapi_ng._rpc._client import (
    NDR,
    NDR64,
    bind_time_feature_negotiation,
    create_rpc_connection,
)
from dpapi_ng._rpc._epm import EPM, EptMap, EptMapResult, build_tcpip_tower, TCPFloor
from dpapi_ng._rpc._isd_key import ISD_KEY, GetKeyRequest
from dpapi_ng._rpc._verification import VerificationTrailer, CommandPContext, CommandFlags

with create_rpc_connection("dc01.domain.test") as rpc:
    bind_ack = rpc.bind(
        contexts=[
            ContextElement(
                context_id=0,
                abstract_syntax=EPM,
                transfer_syntaxes=[NDR],
            ),
            ContextElement(
                context_id=1,
                abstract_syntax=EPM,
                transfer_syntaxes=[NDR64],
            ),
            ContextElement(
                context_id=2,
                abstract_syntax=EPM,
                transfer_syntaxes=[bind_time_feature_negotiation()],
            ),
        ]
    )

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

    resp = rpc.request(1, ept_map.opnum, ept_map.pack())
    map_response = EptMapResult.unpack(resp.stub_data)
    assert map_response.status == 0
    assert isinstance(map_response.towers[0][3], TCPFloor)
    isd_key_port = map_response.towers[0][3].port

with create_rpc_connection(
    "dc01.domain.test",
    isd_key_port,
    auth_protocol="negotiate",
) as rpc:
    bind_ack = rpc.bind(
        contexts=[
            ContextElement(
                context_id=0,
                abstract_syntax=ISD_KEY,
                transfer_syntaxes=[NDR],
            ),
            ContextElement(
                context_id=1,
                abstract_syntax=ISD_KEY,
                transfer_syntaxes=[NDR64],
            ),
            ContextElement(
                context_id=2,
                abstract_syntax=ISD_KEY,
                transfer_syntaxes=[bind_time_feature_negotiation()],
            ),
        ]
    )

    target_sd = b""
    get_key = GetKeyRequest(target_sd)
    stub_data = get_key.pack()
    stub_data += b"\x00" * (-len(stub_data) % 4)
    stub_data += VerificationTrailer(
        [
            CommandPContext(
                flags=CommandFlags.SEC_VT_COMMAND_END,
                interface_id=ISD_KEY,
                transfer_syntax=NDR64,
            ),
        ]
    ).pack()

    resp = rpc.request(1, get_key.opnum, stub_data)
    a = ""
