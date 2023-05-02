import spnego

from dpapi_ng._rpc._client import NDR, create_rpc_connection
from dpapi_ng._rpc._epm import EPM_ID, EptMap, TCPIPTower
from dpapi_ng._rpc._isd_key import ISD_KEY_ID

with create_rpc_connection("dc01.domain.test") as rpc:
    rpc.bind(EPM_ID)

    ept_map = EptMap(
        obj=None,
        tower=TCPIPTower(
            service=ISD_KEY_ID,
            data_rep=NDR,
            port=135,
            addr=0,
        ),
        entry_handle=None,
        max_towers=4,
    )

    resp = rpc.request(ept_map.opnum, ept_map.pack())
