# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import math
import re
import struct
import typing as t
import uuid

from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

from dpapi_ng._epm import EPM, EptMap, EptMapResult, TCPFloor, build_tcpip_tower
from dpapi_ng._isd_key import ISD_KEY, GetKey
from dpapi_ng._rpc import (
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

from ._asn1 import ASN1Reader
from ._pkcs7 import (
    AlgorithmIdentifier,
    ContentInfo,
    EncryptedContentInfo,
    EnvelopedData,
    KEKRecipientInfo,
    NCryptProtectionDescriptor,
)

KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")


@dataclasses.dataclass(frozen=True)
class KeyIdentifier:
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf
    # 2.2.4 Group Key Envelope
    # This struct seems similar (the magic matches) but the real data seems to
    # be missing a few fields. Anything beyond the root_key_identifier is guess
    # work based on the data seen.
    version: int
    flags: int
    l0: int
    l1: int
    l2: int
    root_key_identifier: uuid.UUID
    key_info: bytes
    domain_name: str
    forest_name: str

    @property
    def is_public_key(self) -> bool:
        return bool(self.flags & 1)

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> KeyIdentifier:
        view = memoryview(data)

        version = int.from_bytes(view[:4], byteorder="little")

        assert view[4:8].tobytes() == b"\x4B\x44\x53\x4B"

        flags = int.from_bytes(view[8:12], byteorder="little")
        l0_index = int.from_bytes(view[12:16], byteorder="little")
        l1_index = int.from_bytes(view[16:20], byteorder="little")
        l2_index = int.from_bytes(view[20:24], byteorder="little")
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        key_info_len = int.from_bytes(view[40:44], byteorder="little")
        domain_len = int.from_bytes(view[44:48], byteorder="little")
        forest_len = int.from_bytes(view[48:52], byteorder="little")
        view = view[52:]

        key_info = view[:key_info_len].tobytes()
        view = view[key_info_len:]

        # Take away 2 for the final null padding
        domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
        view = view[domain_len:]

        forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
        view = view[forest_len:]

        return KeyIdentifier(
            version=version,
            flags=flags,
            l0=l0_index,
            l1=l1_index,
            l2=l2_index,
            root_key_identifier=root_key_identifier,
            key_info=key_info,
            domain_name=domain,
            forest_name=forest,
        )


@dataclasses.dataclass(frozen=True)
class KDFParameters:
    hash_name: str

    # MS-GKDI - 2.2.1 KDF Parameters
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf#%5B%7B%22num%22%3A58%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C210%2C0%5D

    def pack(self) -> bytes:
        b_hash_name = self.hash_name.encode("utf-16-le") + b"\x00\x00"
        return b"".join(
            [
                b"\x00\x00\x00\x00\x01\x00\x00\x00",
                len(b_hash_name).to_bytes(4, byteorder="little"),
                b"\x00\x00\x00\x00",
                b_hash_name,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> KDFParameters:
        view = memoryview(data)

        assert view[:8].tobytes() == b"\x00\x00\x00\x00\x01\x00\x00\x00"
        assert view[12:16].tobytes() == b"\x00\x00\x00\x00"
        hash_length = struct.unpack("<I", view[8:12])[0]

        hash_name = view[16 : 16 + hash_length - 2].tobytes().decode("utf-16-le")

        return KDFParameters(hash_name=hash_name)


@dataclasses.dataclass(frozen=True)
class FFCDHKey:
    key_length: int
    field_order: int
    generator: int
    public_key: int

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> FFCDHKey:
        view = memoryview(data)

        assert view[:4].tobytes() == b"\x44\x48\x50\x42"
        key_length = struct.unpack("<I", view[4:8])[0]

        field_order = view[8 : 8 + key_length].tobytes()
        assert len(field_order) == key_length
        view = view[8 + key_length :]

        generator = view[:key_length].tobytes()
        assert len(generator) == key_length
        view = view[key_length:]

        public_key = view.tobytes()
        assert len(public_key) == key_length

        return FFCDHKey(
            key_length=key_length,
            field_order=int.from_bytes(field_order, byteorder="big"),
            generator=int.from_bytes(generator, byteorder="big"),
            public_key=int.from_bytes(public_key, byteorder="big"),
        )


@dataclasses.dataclass(frozen=True)
class FFCDHParameters:
    key_length: int
    field_order: int
    generator: int

    def pack(self) -> bytes:
        b_field_order = self.field_order.to_bytes((self.field_order.bit_length() + 7) // 8, byteorder="big")
        b_generator = self.generator.to_bytes((self.generator.bit_length() + 7) // 8, byteorder="big")

        return b"".join(
            [
                (12 + len(b_field_order) + len(b_generator)).to_bytes(4, byteorder="little"),
                b"\x44\x48\x50\x4D",
                self.key_length.to_bytes(4, byteorder="little"),
                b_field_order,
                b_generator,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> FFCDHParameters:
        view = memoryview(data)

        length = struct.unpack("<I", view[:4])[0]
        assert len(view) == length
        assert view[4:8].tobytes() == b"\x44\x48\x50\x4d"
        key_length = struct.unpack("<I", view[8:12])[0]

        field_order = view[12 : 12 + key_length].tobytes()
        assert len(field_order) == key_length
        view = view[12 + key_length :]

        generator = view[:key_length].tobytes()
        assert len(generator) == key_length

        return FFCDHParameters(
            key_length=key_length,
            field_order=int.from_bytes(field_order, byteorder="big"),
            generator=int.from_bytes(generator, byteorder="big"),
        )


@dataclasses.dataclass(frozen=True)
class ECDHKey:
    key_length: int
    x: int
    y: int

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> ECDHKey:
        view = memoryview(data)

        assert view[:3].tobytes() == b"\x45\x43\x4B"
        assert view[3] in [49, 51, 53]

        length = struct.unpack("<I", view[4:8])[0]

        x = view[8 : 8 + length].tobytes()
        assert len(x) == length
        view = view[8 + length :]

        y = view[:length].tobytes()
        assert len(y) == length

        return ECDHKey(
            key_length=length,
            x=int.from_bytes(x, byteorder="big"),
            y=int.from_bytes(y, byteorder="big"),
        )


@dataclasses.dataclass(frozen=True)
class GroupKeyEnvelope:
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf
    # 2.2.4 Group Key Envelope
    version: int
    flags: int
    l0: int
    l1: int
    l2: int
    root_key_identifier: uuid.UUID
    kdf_algorithm: str
    kdf_parameters: bytes
    secret_algorithm: str
    secret_parameters: bytes
    private_key_length: int
    public_key_length: int
    domain_name: str
    forest_name: str
    l1_key: bytes
    l2_key: bytes

    @property
    def is_public_key(self) -> bool:
        return bool(self.flags & 1)

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> GroupKeyEnvelope:
        view = memoryview(data)

        version = struct.unpack("<I", view[:4])[0]

        assert view[4:8].tobytes() == b"\x4B\x44\x53\x4B"

        flags = struct.unpack("<I", view[8:12])[0]
        l0_index = struct.unpack("<I", view[12:16])[0]
        l1_index = struct.unpack("<I", view[16:20])[0]
        l2_index = struct.unpack("<I", view[20:24])[0]
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        kdf_algo_len = struct.unpack("<I", view[40:44])[0]
        kdf_para_len = struct.unpack("<I", view[44:48])[0]
        sec_algo_len = struct.unpack("<I", view[48:52])[0]
        sec_para_len = struct.unpack("<I", view[52:56])[0]
        priv_key_len = struct.unpack("<I", view[56:60])[0]
        publ_key_len = struct.unpack("<I", view[60:64])[0]
        l1_key_len = struct.unpack("<I", view[64:68])[0]
        l2_key_len = struct.unpack("<I", view[68:72])[0]
        domain_len = struct.unpack("<I", view[72:76])[0]
        forest_len = struct.unpack("<I", view[76:80])[0]
        view = view[80:]

        kdf_algo = view[: kdf_algo_len - 2].tobytes().decode("utf-16-le")
        view = view[kdf_algo_len:]

        kdf_param = view[:kdf_para_len].tobytes()
        view = view[kdf_para_len:]

        secret_algo = view[: sec_algo_len - 2].tobytes().decode("utf-16-le")
        view = view[sec_algo_len:]

        secret_param = view[:sec_para_len].tobytes()
        view = view[sec_para_len:]

        domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
        view = view[domain_len:]

        forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
        view = view[forest_len:]

        l1_key = view[:l1_key_len].tobytes()
        view = view[l1_key_len:]

        l2_key = view[:l2_key_len].tobytes()
        view = view[l2_key_len:]

        return GroupKeyEnvelope(
            version=version,
            flags=flags,
            l0=l0_index,
            l1=l1_index,
            l2=l2_index,
            root_key_identifier=root_key_identifier,
            kdf_algorithm=kdf_algo,
            kdf_parameters=kdf_param,
            secret_algorithm=secret_algo,
            secret_parameters=secret_param,
            private_key_length=priv_key_len,
            public_key_length=publ_key_len,
            domain_name=domain,
            forest_name=forest,
            l1_key=l1_key,
            l2_key=l2_key,
        )


def _parse_dpapi_ng_blob(
    data: bytes,
) -> t.Tuple[KEKRecipientInfo, EncryptedContentInfo]:
    view = memoryview(data)
    header = ASN1Reader(view).peek_header()
    content_info = ContentInfo.unpack(view[: header.tag_length + header.length], header=header)
    remaining_data = view[header.tag_length + header.length :].tobytes()

    assert content_info.content_type == EnvelopedData.content_type
    enveloped_data = EnvelopedData.unpack(content_info.content)

    assert enveloped_data.version == 2
    assert len(enveloped_data.recipient_infos) == 1
    assert isinstance(enveloped_data.recipient_infos[0], KEKRecipientInfo)

    enc_content = enveloped_data.encrypted_content_info
    if not enc_content.content and remaining_data:
        # The LAPS payload seems to not include this in the payload but at the
        # end of the content, just set it back on the structure.
        object.__setattr__(enc_content, "content", remaining_data)

    return enveloped_data.recipient_infos[0], enc_content


def sid_to_bytes(sid: str) -> bytes:
    sid_pattern = re.compile(r"^S-(\d)-(\d+)(?:-\d+){1,15}$")
    sid_match = sid_pattern.match(sid)
    if not sid_match:
        raise ValueError(f"Input string '{sid}' is not a valid SID string")

    sid_split = sid.split("-")
    revision = int(sid_split[1])
    authority = int(sid_split[2])

    data = bytearray(authority.to_bytes(8, byteorder="big"))
    data[0] = revision
    data[1] = len(sid_split) - 3

    for idx in range(3, len(sid_split)):
        sub_auth = int(sid_split[idx])
        data += sub_auth.to_bytes(4, byteorder="little")

    return bytes(data)


def ace_to_bytes(sid: str, access_mask: int) -> bytes:
    b_sid = sid_to_bytes(sid)

    data = bytearray(8 + len(b_sid))
    view = memoryview(data)

    data[0] = 0  # AceType - ACCESS_ALLOWED_ACE_TYPE
    data[1] = 0  # AceFlags - None
    view[2:4] = len(data).to_bytes(2, byteorder="little")
    view[4:8] = access_mask.to_bytes(4, byteorder="little")
    view[8:] = b_sid

    return bytes(data)


def acl_to_bytes(aces: t.List[bytes]) -> bytes:
    ace_data = b"".join(aces)

    data = bytearray(8 + len(ace_data))
    view = memoryview(data)

    data[0] = 2  # AclRevision - ACL_REVISION
    data[1] = 0  # Sbz1
    view[2:4] = (8 + len(ace_data)).to_bytes(2, byteorder="little")
    view[4:6] = len(aces).to_bytes(2, byteorder="little")
    view[6:8] = b"\x00\x00"  # Sbz2
    view[8:] = ace_data

    return bytes(data)


def sd_to_bytes(
    owner: str,
    group: str,
    sacl: t.Optional[t.List[bytes]] = None,
    dacl: t.Optional[t.List[bytes]] = None,
) -> bytes:
    control = 0b10000000 << 8  # Self-Relative

    # While MS-DTYP state there is no required order for the dynamic data, it
    # is important that the raw bytes are exactly what Microsoft uses on the
    # server side when it computes the seed key values. Luckily the footnote
    # give the correct order the MS-GKDI expects: Sacl, Dacl, Owner, Group
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/11e1608c-6169-4fbc-9c33-373fc9b224f4#Appendix_A_72
    dynamic_data = bytearray()
    current_offset = 20  # Length of the SD header bytes

    sacl_offset = 0
    if sacl:
        sacl_bytes = acl_to_bytes(sacl)
        sacl_offset = current_offset
        current_offset += len(sacl_bytes)

        control |= 0b00010000  # SACL Present
        dynamic_data += sacl_bytes

    dacl_offset = 0
    if dacl:
        dacl_bytes = acl_to_bytes(dacl)
        dacl_offset = current_offset
        current_offset += len(dacl_bytes)

        control |= 0b00000100  # DACL Present
        dynamic_data += dacl_bytes

    owner_bytes = sid_to_bytes(owner)
    owner_offset = current_offset
    current_offset += len(owner_bytes)
    dynamic_data += owner_bytes

    group_bytes = sid_to_bytes(group)
    group_offset = current_offset
    dynamic_data += group_bytes

    return b"".join(
        [
            b"\x01\x00",  # Revision and Sbz1
            control.to_bytes(2, byteorder="little"),
            owner_offset.to_bytes(4, byteorder="little"),
            group_offset.to_bytes(4, byteorder="little"),
            sacl_offset.to_bytes(4, byteorder="little"),
            dacl_offset.to_bytes(4, byteorder="little"),
            dynamic_data,
        ]
    )


async def async_get_key(
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
        return GroupKeyEnvelope.unpack(GetKey.unpack_response(raw_resp))


def sync_get_key(
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
        return GroupKeyEnvelope.unpack(GetKey.unpack_response(raw_resp))


def compute_l2_key(
    algorithm: hashes.HashAlgorithm,
    request: KeyIdentifier,
    rk: GroupKeyEnvelope,
) -> bytes:
    l1 = rk.l1
    l1_key = rk.l1_key
    l2 = rk.l2
    l2_key = rk.l2_key
    reseed_l2 = l2 == 31 or rk.l1 != request.l1

    # MS-GKDI 2.2.4 Group key Envelope
    # If the value in the L2 index field is equal to 31, this contains the
    # L1 key with group key identifier (L0 index, L1 index, -1). In all
    # other cases, this field contains the L1 key with group key identifier
    # (L0 index, L1 index - 1, -1). If this field is present, its length
    # MUST be equal to 64 bytes.
    if l2 != 31 and l1 != request.l1:
        l1 -= 1

    while l1 != request.l1:
        reseed_l2 = True
        l1 -= 1

        l1_key = kdf(
            algorithm,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                rk.root_key_identifier,
                rk.l0,
                l1,
                -1,
            ),
            64,
        )

    if reseed_l2:
        l2 = 31
        l2_key = kdf(
            algorithm,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                rk.root_key_identifier,
                rk.l0,
                l1,
                l2,
            ),
            64,
        )

    while l2 != request.l2:
        l2 -= 1

        l2_key = kdf(
            algorithm,
            l2_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                rk.root_key_identifier,
                rk.l0,
                l1,
                l2,
            ),
            64,
        )

    return l2_key


def aes256gcm_decrypt(
    algorithm: AlgorithmIdentifier,
    key: bytes,
    secret: bytes,
) -> bytes:
    # This is not right but I'm not up to this part yet to try it out.
    assert algorithm.algorithm == "2.16.840.1.101.3.4.1.46"  # AES256-GCM
    assert algorithm.parameters
    reader = ASN1Reader(algorithm.parameters).read_sequence()
    iv = reader.read_octet_string()

    cipher = AESGCM(key)
    data = cipher.decrypt(iv, secret, None)

    return data


def compute_kdf_context(
    key_guid: uuid.UUID,
    l0: int,
    l1: int,
    l2: int,
) -> bytes:
    context = key_guid.bytes_le
    context += struct.pack("<i", l0)
    context += struct.pack("<i", l1)
    context += struct.pack("<i", l2)

    return context


def kdf(
    algorithm: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
) -> bytes:
    # KDF(HashAlg, KI, Label, Context, L)
    # where KDF is SP800-108 in counter mode.
    kdf = KBKDFHMAC(
        algorithm=algorithm,
        mode=Mode.CounterMode,
        length=length,
        label=label,
        context=context,
        # MS-SMB2 uses the same KDF function and my implementation that
        # sets a value of 4 seems to work so assume that's the case here.
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        fixed=None,
    )
    return kdf.derive(secret)


def ncrypt_unprotect_secret(
    data: bytes,
) -> bytes:
    kek_info, enc_content = _parse_dpapi_ng_blob(data)

    assert kek_info.version == 4
    assert kek_info.kekid.other is not None
    assert kek_info.kekid.other.key_attr_id == "1.3.6.1.4.1.311.74.1"
    protection_descriptor = NCryptProtectionDescriptor.unpack(kek_info.kekid.other.key_attr or b"")
    assert protection_descriptor.content_type == "1.3.6.1.4.1.311.74.1.1"
    assert enc_content.content

    key_info = KeyIdentifier.unpack(kek_info.kekid.key_identifier)

    # Build the target security descriptor from the SID passed in. This SD
    # contains an ACE per target user with a mask of 0x3 and a final ACE of the
    # current user with a mask of 0x2. When viewing this over the wire the
    # current user is set as S-1-1-0 (World) and the owner/group is
    # S-1-5-18 (SYSTEM).
    target_sd = sd_to_bytes(
        owner="S-1-5-18",
        group="S-1-5-18",
        dacl=[ace_to_bytes(protection_descriptor.value, 3), ace_to_bytes("S-1-1-0", 2)],
    )

    rk = sync_get_key(
        "dc01.domain.test",
        target_sd,
        key_info.root_key_identifier,
        key_info.l0,
        key_info.l1,
        key_info.l2,
    )

    assert rk.version == 1
    assert not rk.is_public_key
    assert rk.kdf_algorithm == "SP800_108_CTR_HMAC"
    assert rk.l0 == key_info.l0

    kdf_parameters = KDFParameters.unpack(rk.kdf_parameters)
    hash_algo: hashes.HashAlgorithm
    if kdf_parameters.hash_name == "SHA1":
        hash_algo = hashes.SHA1()
    elif kdf_parameters.hash_name == "SHA256":
        hash_algo = hashes.SHA256()
    elif kdf_parameters.hash_name == "SHA384":
        hash_algo = hashes.SHA384()
    elif kdf_parameters.hash_name == "SHA512":
        hash_algo = hashes.SHA512()
    else:
        raise Exception(f"Unsupported hash algorithm {kdf_parameters.hash_name}")

    l2_key = compute_l2_key(hash_algo, key_info, rk)

    if key_info.is_public_key:
        # PrivKey(SD, RK, L0, L1, L2) = KDF(
        #   HashAlg,
        #   Key(SD, RK, L0, L1, L2),
        #   "KDS service",
        #   RK.msKds-SecretAgreement-AlgorithmID,
        #   RK.msKds-PrivateKey-Length
        # )
        private_key = kdf(
            hash_algo,
            l2_key,
            KDS_SERVICE_LABEL,
            (rk.secret_algorithm + "\0").encode("utf-16-le"),
            math.ceil(rk.private_key_length / 8),
        )

        if rk.secret_algorithm == "DH":
            dh_parameters = FFCDHParameters.unpack(rk.secret_parameters)
            assert dh_parameters.key_length == (rk.public_key_length // 8)

            # We can derive the shared secret based on the DH formula.
            # s = y**x mod p
            dh_pub_key = FFCDHKey.unpack(key_info.key_info)
            shared_secret_int = pow(
                dh_pub_key.public_key,
                int.from_bytes(private_key, byteorder="big"),
                dh_pub_key.field_order,
            )
            shared_secret = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, byteorder="big")

        elif rk.secret_algorithm in ["ECDH_P256", "ECDH_P384", "ECDH_P521"]:
            assert not rk.secret_parameters

            curve: ec.EllipticCurve = {
                "ECDH_P256": ec.SECP256R1(),
                "ECDH_P384": ec.SECP384R1(),
                "ECDH_P521": ec.SECP521R1(),
            }[rk.secret_algorithm]

            ecdh_pub_key_info = ECDHKey.unpack(key_info.key_info)

            ecdh_pub_key = ec.EllipticCurvePublicNumbers(ecdh_pub_key_info.x, ecdh_pub_key_info.y, curve).public_key()
            ecdh_private = ec.derive_private_key(
                int.from_bytes(private_key, byteorder="big"),
                curve,
            )
            shared_secret = ecdh_private.exchange(ec.ECDH(), ecdh_pub_key)

        else:
            raise NotImplementedError(f"Unknown secret algorithm '{rk.secret_algorithm}'")

        # This part isn't documented but we use the shared share, use the
        # key derivation algorithm SP 800-56A to derive the kek secret input
        # value. On Windows this uses BCryptDeriveKey which has a hardcoded hash
        # of SHA256 internally regardless of the configured KDF algorithm. The
        # other info is comprised of the following UTF-16-LE encoded NULL
        # terminated strings:
        #   KDF_ALGORITHMID - SHA512
        #   KDF_PARTYUINFO  - KDS public key
        #   KDF_PARTYVINFO  - KDS service
        # The Algorithm is always SHA512 regardless of the KDF parameters set
        # on the key.
        kek_context = "KDS public key\0".encode("utf-16-le")
        otherinfo = "SHA512\0".encode("utf-16-le") + kek_context + KDS_SERVICE_LABEL
        kek_secret = ConcatKDFHash(hashes.SHA256(), length=32, otherinfo=otherinfo).derive(shared_secret)

    else:
        kek_secret = l2_key
        kek_context = key_info.key_info

    kek = kdf(
        hash_algo,
        kek_secret,
        KDS_SERVICE_LABEL,
        kek_context,
        32,
    )

    # With the kek we can unwrap the encrypted cek in the LAPS payload.
    assert kek_info.key_encryption_algorithm.algorithm == "2.16.840.1.101.3.4.1.45"  # AES256-wrap
    assert not kek_info.key_encryption_algorithm.parameters
    cek = keywrap.aes_key_unwrap(kek, kek_info.encrypted_key)

    # With the cek we can decrypt the encrypted content in the LAPS payload.
    password = aes256gcm_decrypt(enc_content.algorithm, cek, enc_content.content)
    return password
