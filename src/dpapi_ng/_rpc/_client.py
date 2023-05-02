# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import dataclasses
import enum
import socket
import struct
import typing as t
import uuid

import spnego


BIND_TIME_FEATURE_NEGOTIATION = (uuid.UUID("6cb71c2c-9812-4540-0300-000000000000"), 1, 0)
EMP = (uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)
ISD_KEY = (uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
NDR = (uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)
NDR64 = (uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)


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


@dataclasses.dataclass(frozen=True)
class Tower:
    service: t.Tuple[uuid.UUID, int, int]
    data_rep: t.Tuple[uuid.UUID, int, int]
    protocol: int
    port: int
    addr: int


def create_pdu(
    packet_type: int,
    packet_flags: int,
    call_id: int,
    header_data: t.Optional[bytes] = None,
    *,
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

    frag_length = 16 + len(b_header_data) + len(b_stub_data) + len(b_sec_trailer) + len(b_authentication_token)
    return b"".join(
        [
            b"\x05\x00",  # Version and minor version
            packet_type.to_bytes(1, byteorder="little"),
            packet_flags.to_bytes(1, byteorder="little"),
            b"\x10\x00\x00\x00",  # Data-Representation
            frag_length.to_bytes(2, byteorder="little"),
            len(b_authentication_token).to_bytes(2, byteorder="little"),
            call_id.to_bytes(4, byteorder="little"),
            b_header_data,
            b_stub_data,
            b_sec_trailer,
            b_authentication_token,
        ]
    )


def create_bind(
    service: t.Tuple[uuid.UUID, int, int],
    syntaxes: t.List[bytes],
    auth_data: t.Optional[bytes] = None,
    sign_header: bool = False,
) -> bytes:
    context_header = b"\x00\x00\x01\x00"
    context_header += service[0].bytes_le
    context_header += struct.pack("<H", service[1])
    context_header += struct.pack("<H", service[2])
    context_data = bytearray()
    for idx, s in enumerate(syntaxes):
        offset = len(context_data)
        context_data += context_header
        memoryview(context_data)[offset : offset + 2] = struct.pack("<H", idx)
        context_data += s

    bind_data = bytearray()
    bind_data += b"\xd0\x16"  # Max Xmit Frag
    bind_data += b"\xd0\x16"  # Max Recv Frag
    bind_data += b"\x00\x00\x00\x00"  # Assoc Group
    bind_data += b"\x03\x00\x00\x00"  # Num context items
    bind_data += context_data

    sec_trailer: t.Optional[SecTrailer] = None
    if auth_data:
        sec_trailer = SecTrailer(
            type=9,  # SPNEGO
            level=6,  # Packet Privacy
            pad_length=0,
            context_id=0,
            data=auth_data,
        )

    return create_pdu(
        packet_type=11,
        packet_flags=0x03 | (0x4 if sign_header else 0x0),
        call_id=1,
        header_data=bytes(bind_data),
        sec_trailer=sec_trailer,
    )


def create_alter_context(
    service: t.Tuple[uuid.UUID, int, int],
    token: bytes,
    sign_header: bool = False,
) -> bytes:
    ctx1 = b"\x01\x00\x01\x00"
    ctx1 += service[0].bytes_le
    ctx1 += struct.pack("<H", service[1])
    ctx1 += struct.pack("<H", service[1])
    ctx1 += NDR64[0].bytes_le + struct.pack("<H", NDR64[1]) + struct.pack("<H", NDR[2])

    alter_context_data = bytearray()
    alter_context_data += b"\xd0\x16"  # Max Xmit Frag
    alter_context_data += b"\xd0\x16"  # Max Recv Frag
    alter_context_data += b"\x00\x00\x00\x00"  # Assoc Group
    alter_context_data += b"\x01\x00\x00\x00"  # Num context items
    alter_context_data += ctx1

    auth_data = SecTrailer(
        type=9,  # SPNEGO
        level=6,  # Packet Privacy
        pad_length=0,
        context_id=0,
        data=token,
    )

    return create_pdu(
        packet_type=14,
        packet_flags=0x03 | (0x4 if sign_header else 0x0),
        call_id=1,
        header_data=bytes(alter_context_data),
        sec_trailer=auth_data,
    )


def create_request(
    opnum: int,
    data: bytes,
    ctx: t.Optional[spnego.ContextProxy] = None,
    sign_header: bool = False,
) -> bytes:
    # Add Verification trailer to data
    # MS-RPCE 2.2.2.13 Veritifcation Trailer
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/0e9fea61-1bff-4478-9bfe-a3b6d8b64ac3
    if ctx:
        pcontext = bytearray()
        pcontext += ISD_KEY[0].bytes_le
        pcontext += struct.pack("<H", ISD_KEY[1]) + struct.pack("<H", ISD_KEY[2])
        pcontext += NDR64[0].bytes_le
        pcontext += struct.pack("<H", NDR64[1]) + struct.pack("<H", NDR64[2])

        verification_trailer = bytearray()
        verification_trailer += b"\x8a\xe3\x13\x71\x02\xf4\x36\x71"  # Signature

        verification_trailer += b"\x02\x40"  # Trailer Command - PCONTEXT + End
        verification_trailer += struct.pack("<H", len(pcontext))
        verification_trailer += pcontext

        # Verification trailer to added to a 4 byte boundary on the stub data
        data_padding = -len(data) % 4
        data += b"\x00" * data_padding

        data += verification_trailer
        alloc_hint = len(data)
        auth_padding = -len(data) % 16
        data += b"\x00" * auth_padding

    else:
        alloc_hint = len(data)

    request_data = bytearray()
    request_data += struct.pack("<I", alloc_hint)
    request_data += struct.pack("<H", 1)  # Context id
    request_data += struct.pack("<H", opnum)

    sec_trailer: t.Optional[SecTrailer] = None
    if ctx and sign_header:
        dummy_iov = gssapi.raw.IOV(
            gssapi.raw.IOVBufferType.header,
            b"",
            std_layout=False,
        )
        gssapi.raw.wrap_iov_length(ctx, dummy_iov, confidential=True, qop=None)
        dummy_header = dummy_iov[0].value or b""
        dummy_header_length = len(dummy_header)

        sec_trailer = SecTrailer(
            type=9,  # SPNEGO
            level=6,  # Packet Privacy
            pad_length=auth_padding,
            context_id=0,
            data=dummy_header,
        )
        pdu_req = bytearray(
            create_pdu(
                packet_type=0,
                packet_flags=0x03,
                call_id=1,
                header_data=bytes(request_data),
                stub_data=data,
                sec_trailer=sec_trailer,
            )
        )

        sec_trailer_data = pdu_req[-(dummy_header_length + 8) : -dummy_header_length]
        iov_buffers = gssapi.raw.IOV(
            # The PDU header up to the stub data
            (gssapi.raw.IOVBufferType.sign_only, pdu_req[:24]),
            # The stub data.
            data,
            # The security trailer portion without the auth data
            (gssapi.raw.IOVBufferType.sign_only, sec_trailer_data),
            # Will store the generated header here.
            gssapi.raw.IOVBufferType.header,
            std_layout=False,
        )
        gssapi.raw.wrap_iov(
            ctx,
            message=iov_buffers,
            confidential=True,
            qop=None,
        )

        data_view = memoryview(pdu_req)
        data_view[24 : 24 + len(data)] = iov_buffers[1].value or b""
        data_view[-76:] = bytes(iov_buffers[3].value or b"")

        return bytes(pdu_req)

    elif ctx:
        iov_buffers = gssapi.raw.IOV(
            gssapi.raw.IOVBufferType.header,
            data,
            std_layout=False,
        )
        gssapi.raw.wrap_iov(
            ctx,
            message=iov_buffers,
            confidential=True,
            qop=None,
        )

        sec_trailer = SecTrailer(
            type=9,  # SPNEGO
            level=6,  # Packet Privacy
            pad_length=auth_padding,
            context_id=0,
            data=iov_buffers[0].value or b"",
        )
        stub_data = iov_buffers[1].value

    else:
        stub_data = data

    return create_pdu(
        packet_type=0,
        packet_flags=0x03,
        call_id=1,
        header_data=bytes(request_data),
        stub_data=stub_data,
        sec_trailer=sec_trailer,
    )


def get_fault_pdu_error(data: memoryview) -> int:
    status = struct.unpack("<I", data[24:28])[0]

    return status


def parse_bind_ack(data: bytes) -> t.Optional[bytes]:
    view = memoryview(data)

    pkt_type = struct.unpack("B", view[2:3])[0]
    if pkt_type == 3:
        err = get_fault_pdu_error(view)
        raise Exception(f"Receive Fault PDU: 0x{err:08X}")

    assert pkt_type == 12

    auth_length = struct.unpack("<H", view[10:12])[0]
    if auth_length:
        auth_blob = view[-auth_length:].tobytes()

        return auth_blob

    else:
        return None


def parse_alter_context(data: bytes) -> bytes:
    view = memoryview(data)

    pkt_type = struct.unpack("B", view[2:3])[0]
    if pkt_type == 3:
        err = get_fault_pdu_error(view)
        raise Exception(f"Receive Fault PDU: 0x{err:08X}")

    assert pkt_type == 15

    auth_length = struct.unpack("<H", view[10:12])[0]
    auth_blob = view[-auth_length:].tobytes()

    return auth_blob


def parse_response(
    data: bytes,
    ctx: t.Optional[gssapi.SecurityContext] = None,
    sign_header: bool = False,
) -> bytes:
    view = memoryview(data)

    pkt_type = struct.unpack("B", view[2:3])[0]
    if pkt_type == 3:  # False
        err = get_fault_pdu_error(view)
        raise Exception(f"Receive Fault PDU: 0x{err:08X}")

    assert pkt_type == 2
    frag_length = struct.unpack("<H", view[8:10])[0]
    auth_length = struct.unpack("<H", view[10:12])[0]

    assert len(view) == frag_length
    if auth_length:
        auth_data = view[-(auth_length + 8) :]
        stub_data = view[24 : len(view) - (auth_length + 8)]
        padding = struct.unpack("B", auth_data[2:3])[0]

    else:
        auth_data = memoryview(b"")
        stub_data = view[24:]
        padding = 0

    if ctx and sign_header:
        iov_buffers = gssapi.raw.IOV(
            (gssapi.raw.IOVBufferType.sign_only, data[:24]),
            stub_data.tobytes(),
            (gssapi.raw.IOVBufferType.sign_only, auth_data[:8].tobytes()),
            (gssapi.raw.IOVBufferType.header, False, auth_data[8:].tobytes()),
            std_layout=False,
        )
        gssapi.raw.unwrap_iov(
            ctx,
            message=iov_buffers,
        )

        decrypted_stub = iov_buffers[1].value or b""
        return decrypted_stub[: len(decrypted_stub) - padding]

    elif ctx:
        iov_buffers = gssapi.raw.IOV(
            (gssapi.raw.IOVBufferType.header, False, auth_data[8:].tobytes()),
            stub_data.tobytes(),
            std_layout=False,
        )
        gssapi.raw.unwrap_iov(
            ctx,
            message=iov_buffers,
        )

        decrypted_stub = iov_buffers[1].value or b""
        return decrypted_stub[: len(decrypted_stub) - padding]

    else:
        return stub_data.tobytes()


def create_ept_map_request(
    service: t.Tuple[uuid.UUID, int, int],
    data_rep: t.Tuple[uuid.UUID, int, int],
    protocol: int = 0x0B,  # TCP/IP
    port: int = 135,
    address: int = 0,
) -> t.Tuple[int, bytes]:
    # MS-RPCE 2.2.1.2.5 ept_map Method
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab744583-430e-4055-8901-3c6bc007e791
    # void ept_map(
    #     [in] handle_t hEpMapper,
    #     [in, ptr] UUID* obj,
    #     [in, ptr] twr_p_t map_tower,
    #     [in, out] ept_lookup_handle_t* entry_handle,
    #     [in, range(0,500)] unsigned long max_towers,
    #     [out] unsigned long* num_towers,
    #     [out, ptr, size_is(max_towers), length_is(*num_towers)]
    #         twr_p_t* ITowers,
    #     [out] error_status* status
    # );
    def build_floor(protocol: int, lhs: bytes, rhs: bytes) -> bytes:
        data = bytearray()
        data += struct.pack("<H", len(lhs) + 1)
        data += struct.pack("B", protocol)
        data += lhs
        data += struct.pack("<H", len(rhs))
        data += rhs

        return bytes(data)

    floors: t.List[bytes] = [
        build_floor(
            protocol=0x0D,
            lhs=service[0].bytes_le + struct.pack("<H", service[1]),
            rhs=struct.pack("<H", service[2]),
        ),
        build_floor(
            protocol=0x0D,
            lhs=data_rep[0].bytes_le + struct.pack("<H", data_rep[1]),
            rhs=struct.pack("<H", data_rep[2]),
        ),
        build_floor(protocol=protocol, lhs=b"", rhs=b"\x00\x00"),
        build_floor(protocol=0x07, lhs=b"", rhs=struct.pack(">H", port)),
        build_floor(protocol=0x09, lhs=b"", rhs=struct.pack(">I", address)),
    ]

    tower = bytearray()
    tower += struct.pack("<H", len(floors))
    for f in floors:
        tower += f
    tower_padding = -(len(tower) + 4) % 8

    data = bytearray()
    data += b"\x01" + (b"\x00" * 23)  # Blank UUID pointer with referent id 1
    data += b"\x02\x00\x00\x00\x00\x00\x00\x00"  # Tower referent id 2
    data += struct.pack("<Q", len(tower))
    data += struct.pack("<I", len(tower))
    data += tower
    data += b"\x00" * tower_padding
    data += b"\x00" * 20  # Context handle
    data += struct.pack("<I", 4)  # Max towers

    return 3, bytes(data)


def parse_ept_map_response(data: bytes) -> t.List[Tower]:
    def unpack_floor(view: memoryview) -> t.Tuple[int, int, memoryview, memoryview]:
        lhs_len = struct.unpack("<H", view[:2])[0]
        proto = view[2]
        lhs = view[3 : lhs_len + 2]
        offset = lhs_len + 2

        rhs_len = struct.unpack("<H", view[offset : offset + 2])[0]
        rhs = view[offset + 2 : offset + rhs_len + 2]

        return offset + rhs_len + 2, proto, lhs, rhs

    view = memoryview(data)

    return_code = struct.unpack("<I", view[-4:])[0]
    assert return_code == 0
    num_towers = struct.unpack("<I", view[20:24])[0]
    # tower_max_count = struct.unpack("<Q", view[24:32])[0]
    # tower_offset = struct.unpack("<Q", view[32:40])[0]
    tower_count = struct.unpack("<Q", view[40:48])[0]

    tower_data_offset = 8 * tower_count  # Ignore referent ids
    view = view[48 + tower_data_offset :]
    towers: t.List[Tower] = []
    for _ in range(tower_count):
        tower_length = struct.unpack("<Q", view[:8])[0]
        padding = -(tower_length + 4) % 8
        floor_len = struct.unpack("<H", view[12:14])[0]
        assert floor_len == 5
        view = view[14:]

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == 0x0D
        service = (
            uuid.UUID(bytes_le=lhs[:16].tobytes()),
            struct.unpack("<H", lhs[16:])[0],
            struct.unpack("<H", rhs)[0],
        )

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == 0x0D
        data_rep = (
            uuid.UUID(bytes_le=lhs[:16].tobytes()),
            struct.unpack("<H", lhs[16:])[0],
            struct.unpack("<H", rhs)[0],
        )

        offset, protocol, _, _ = unpack_floor(view)
        view = view[offset:]
        assert protocol == 0x0B

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == 0x07
        port = struct.unpack(">H", rhs)[0]

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == 0x09
        addr = struct.unpack(">I", rhs)[0]

        towers.append(
            Tower(
                service=service,
                data_rep=data_rep,
                protocol=protocol,
                port=port,
                addr=addr,
            )
        )
        view = view[padding:]

    assert len(towers) == num_towers

    return towers


def get_key(
    dc: str,
    target_sd: bytes,
    root_key_id: uuid.UUID,
    l0: int,
    l1: int,
    l2: int,
    sign_header: bool = True,
) -> GroupKeyEnvelope:
    bind_syntaxes = [
        NDR[0].bytes_le + struct.pack("<H", NDR[1]) + struct.pack("<H", NDR[2]),
        NDR64[0].bytes_le + struct.pack("<H", NDR64[1]) + struct.pack("<H", NDR64[2]),
        BIND_TIME_FEATURE_NEGOTIATION[0].bytes_le
        + struct.pack("<H", BIND_TIME_FEATURE_NEGOTIATION[1])
        + struct.pack("<H", BIND_TIME_FEATURE_NEGOTIATION[2]),
    ]

    # Find the dynamic endpoint port for the ISD service.
    with socket.create_connection((dc, 135)) as s:
        bind_data = create_bind(
            EMP,
            bind_syntaxes,
            sign_header=False,
        )
        s.sendall(bind_data)
        resp = s.recv(4096)
        parse_bind_ack(resp)

        opnum, map_request = create_ept_map_request(ISD_KEY, NDR)
        request = create_request(
            opnum,
            map_request,
        )
        s.sendall(request)
        resp = s.recv(4096)

        ept_response = parse_response(resp)
        isd_towers = parse_ept_map_response(ept_response)
        assert len(isd_towers) > 0
        isd_port = isd_towers[0].port

    # DCE style is not exposed in pyspnego yet so use gssapi directly.
    negotiate_mech = gssapi.OID.from_int_seq("1.3.6.1.5.5.2")
    target_spn = gssapi.Name(f"host@{dc}", name_type=gssapi.NameType.hostbased_service)
    flags = (
        gssapi.RequirementFlag.mutual_authentication
        | gssapi.RequirementFlag.replay_detection
        | gssapi.RequirementFlag.out_of_sequence_detection
        | gssapi.RequirementFlag.confidentiality
        | gssapi.RequirementFlag.integrity
        | gssapi.RequirementFlag.dce_style
    )

    ctx = gssapi.SecurityContext(
        name=target_spn,
        flags=flags,
        mech=negotiate_mech,
        usage="initiate",
    )
    out_token = ctx.step()
    assert out_token

    with socket.create_connection((dc, isd_port)) as s:
        bind_data = create_bind(
            ISD_KEY,
            bind_syntaxes,
            auth_data=out_token,
            sign_header=sign_header,
        )

        s.sendall(bind_data)
        resp = s.recv(4096)
        in_token = parse_bind_ack(resp)

        out_token = ctx.step(in_token)
        assert not ctx.complete
        assert out_token

        alter_context = create_alter_context(
            ISD_KEY,
            out_token,
            sign_header=sign_header,
        )
        s.sendall(alter_context)
        resp = s.recv(4096)
        in_token = parse_alter_context(resp)

        out_token = ctx.step(in_token)
        assert ctx.complete
        assert not out_token
        # TODO: Deal with a no header signing.from server

        get_key_req = GetKeyRequest(target_sd, root_key_id, l0, l1, l2)
        request = create_request(
            get_key_req.opnum,
            get_key_req.pack(),
            ctx=ctx,
            sign_header=sign_header,
        )
        s.sendall(request)
        resp = s.recv(4096)

        create_key_resp = parse_response(resp, ctx=ctx, sign_header=sign_header)
        return GetKeyRequest.unpack_response(create_key_resp)
