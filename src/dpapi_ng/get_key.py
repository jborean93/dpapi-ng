from __future__ import annotations

import base64
import dataclasses
import hashlib
import math
import re
import socket
import struct
import sys
import typing as t
import uuid

import gssapi
import gssapi.raw
import spnego
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
)

import sansldap
from sansldap._pkcs7 import (
    AlgorithmIdentifier,
    ContentInfo,
    EncryptedContentInfo,
    EnvelopedData,
    KEKRecipientInfo,
    NCryptProtectionDescriptor,
)
from sansldap.asn1 import ASN1Reader

BIND_TIME_FEATURE_NEGOTIATION = (uuid.UUID("6cb71c2c-9812-4540-0300-000000000000"), 1, 0)
EMP = (uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)
ISD_KEY = (uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
NDR = (uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)
NDR64 = (uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)

KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")


def _get_default_kdf_params() -> KDFParameters:
    return KDFParameters("SHA512")


def _get_default_secret_params() -> FFCDHParameters:
    # RFC 5114 - 2.3. 2048-bit MODP Group with 256-bit Prime Order Subgroup
    # https://www.rfc-editor.org/rfc/rfc5114#section-2.3
    return FFCDHParameters(
        key_length=256,
        field_order=17125458317614137930196041979257577826408832324037508573393292981642667139747621778802438775238728592968344613589379932348475613503476932163166973813218698343816463289144185362912602522540494983090531497232965829536524507269848825658311420299335922295709743267508322525966773950394919257576842038771632742044142471053509850123605883815857162666917775193496157372656195558305727009891276006514000409365877218171388319923896309377791762590614311849642961380224851940460421710449368927252974870395873936387909672274883295377481008150475878590270591798350563488168080923804611822387520198054002990623911454389104774092183,
        generator=8041367327046189302693984665026706374844608289874374425728797669509435881459140662650215832833471328470334064628508692231999401840332046192569287351991689963279656892562484773278584208040987631569628520464069532361274047374444344996651832979378318849943741662110395995778429270819222431610927356005913836932462099770076239554042855287138026806960470277326229482818003962004453764400995790974042663675692120758726145869061236443893509136147942414445551848162391468541444355707785697825741856849161233887307017428371823608125699892904960841221593344499088996021883972185241854777608212592397013510086894908468466292313,
    )


@dataclasses.dataclass
class RootKey:
    data: bytes
    version: int = 1
    kdf_algorithm: str = "SP800_108_CTR_HMAC"
    kdf_parameters: KDFParameters = dataclasses.field(default_factory=_get_default_kdf_params)
    secret_algorithm: str = "DH"
    secret_parameters: FFCDHParameters = dataclasses.field(default_factory=_get_default_secret_params)
    public_key_length: int = 512
    private_key_length: int = 2048


@dataclasses.dataclass(frozen=True)
class EncryptedLAPSBlob:
    update_timestamp: int  # FILETIME int64
    flags: int
    blob: bytes

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EncryptedLAPSBlob:
        view = memoryview(data)

        timestamp_upper = struct.unpack("<I", view[:4])[0]
        timestamp_lower = struct.unpack("<I", view[4:8])[0]
        update_timestamp = (timestamp_upper << 32) | timestamp_lower
        blob_len = struct.unpack("<I", view[8:12])[0]
        flags = struct.unpack("<I", view[12:16])[0]
        blob = view[16 : 16 + blob_len]
        assert len(blob) == blob_len
        assert len(view[16 + blob_len :]) == 0

        return EncryptedLAPSBlob(
            update_timestamp=update_timestamp,
            flags=flags,
            blob=blob.tobytes(),
        )


@dataclasses.dataclass(frozen=True)
class SecTrailer:
    type: int
    level: int
    pad_length: int
    context_id: int
    data: bytes


@dataclasses.dataclass(frozen=True)
class Tower:
    service: t.Tuple[uuid.UUID, int, int]
    data_rep: t.Tuple[uuid.UUID, int, int]
    protocol: int
    port: int
    addr: int


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


@dataclasses.dataclass(frozen=True)
class EncPasswordId:
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
    unknown: bytes
    domain_name: str
    forest_name: str

    @property
    def is_public_key(self) -> bool:
        return bool(self.flags & 1)

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EncPasswordId:
        view = memoryview(data)

        version = struct.unpack("<I", view[:4])[0]

        assert view[4:8].tobytes() == b"\x4B\x44\x53\x4B"

        flags = struct.unpack("<I", view[8:12])[0]
        l0_index = struct.unpack("<I", view[12:16])[0]
        l1_index = struct.unpack("<I", view[16:20])[0]
        l2_index = struct.unpack("<I", view[20:24])[0]
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        unknown_len = struct.unpack("<I", view[40:44])[0]
        domain_len = struct.unpack("<I", view[44:48])[0]
        forest_len = struct.unpack("<I", view[48:52])[0]
        view = view[52:]

        unknown = view[:unknown_len].tobytes()
        view = view[unknown_len:]

        # Take away 2 for the final null padding
        domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
        view = view[domain_len:]

        forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
        view = view[forest_len:]

        return EncPasswordId(
            version=version,
            flags=flags,
            l0=l0_index,
            l1=l1_index,
            l2=l2_index,
            root_key_identifier=root_key_identifier,
            unknown=unknown,
            domain_name=domain,
            forest_name=forest,
        )


@dataclasses.dataclass
class GetKeyRequest:
    opnum: int = dataclasses.field(init=False, repr=False, default=0)

    target_sd: bytes
    root_key_id: uuid.UUID
    l0_key_id: int
    l1_key_id: int
    l2_key_id: int

    # MS-GKDI 3.1.4.1 GetKey (Opnum 0)
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39
    # HRESULT GetKey(
    #     [in] handle_t hBinding,
    #     [in] ULONG cbTargetSD,
    #     [in] [size_is(cbTargetSD)] [ref] char* pbTargetSD,
    #     [in] [unique] GUID* pRootKeyID,
    #     [in] LONG L0KeyID,
    #     [in] LONG L1KeyID,
    #     [in] LONG L2KeyID,
    #     [out] unsigned long* pcbOut,
    #     [out] [size_is(, *pcbOut)] byte** ppbOut);

    def pack(self) -> bytes:
        # Strictly speaking it is only 4 bytes but NDR64 needs 8 byte alignment
        # on the field after.
        target_sd_len = len(self.target_sd).to_bytes(8, byteorder="little")

        return b"".join(
            [
                # cbTargetSD
                target_sd_len,
                # pbTargetSD - pointer header includes the length + padding
                target_sd_len,
                self.target_sd,
                b"\x00" * (-len(self.target_sd) % 8),
                # pRootKeyID - includes referent id
                b"\x00\x00\x02\x00\x00\x00\x00\x00",
                self.root_key_id.bytes_le,
                # L0KeyID
                self.l0_key_id.to_bytes(4, byteorder="little", signed=True),
                # L1KeyID
                self.l1_key_id.to_bytes(4, byteorder="little", signed=True),
                # L2KeyID
                self.l2_key_id.to_bytes(4, byteorder="little", signed=True),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> GetKeyRequest:
        view = memoryview(data)

        target_sd_len = struct.unpack("<I", view[:4])[0]
        target_sd = view[16 : 16 + target_sd_len].tobytes()
        padding = -target_sd_len % 8

        view = view[24 + target_sd_len + padding :]
        root_key_id = uuid.UUID(bytes_le=view[:16].tobytes())
        l0_key_id = struct.unpack("<i", view[16:20])[0]
        l1_key_id = struct.unpack("<i", view[20:24])[0]
        l2_key_id = struct.unpack("<i", view[24:28])[0]

        return GetKeyRequest(
            target_sd=target_sd,
            root_key_id=root_key_id,
            l0_key_id=l0_key_id,
            l1_key_id=l1_key_id,
            l2_key_id=l2_key_id,
        )

    @classmethod
    def unpack_response(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> GroupKeyEnvelope:
        view = memoryview(data)

        hresult = struct.unpack("<I", view[-4:].tobytes())[0]
        view = view[:-4]
        if hresult != 0:
            raise Exception(f"GetKey failed 0x{hresult:08X}")

        key_length = struct.unpack("<I", view[:4])[0]
        view = view[8:]  # Skip padding as well
        # Skip the referent id and double up on pointer size
        key = view[16 : 16 + key_length].tobytes()
        assert len(key) == key_length
        # print(f"GetKey Response: {base64.b16encode(data).decode()}")

        return GroupKeyEnvelope.unpack(key)


def get_laps_enc_password(dc: str, server: str) -> bytes:
    with socket.create_connection((dc, 389)) as s:
        ctx = spnego.client(hostname=dc, service="ldap")

        ldap = sansldap.LDAPClient()
        ldap.bind_sasl("GSS-SPNEGO", None, ctx.step())
        s.sendall(ldap.data_to_send())

        bind_resp = ldap.receive(s.recv(4096))[0]
        assert isinstance(bind_resp, sansldap.BindResponse)
        assert bind_resp.result.result_code == sansldap.LDAPResultCode.SUCCESS
        ctx.step(bind_resp.server_sasl_creds)
        assert ctx.complete

        ldap.search_request(
            server,
            scope=sansldap.SearchScope.BASE,
            attributes=["msLAPS-EncryptedPassword"],
        )
        req = ldap.data_to_send()
        wrapped_req = ctx.wrap(req).data
        s.sendall(struct.pack(">I", len(wrapped_req)) + wrapped_req)
        resp = s.recv(4096)

        search_res = ldap.receive(ctx.unwrap(resp[4:]).data)
        assert len(search_res) == 2
        assert isinstance(search_res[0], sansldap.SearchResultEntry)
        assert isinstance(search_res[1], sansldap.SearchResultDone)
        assert search_res[1].result.result_code == sansldap.LDAPResultCode.SUCCESS

        return search_res[0].attributes[0].values[0]


def sid_to_bytes(sid: str) -> bytes:
    sid_pattern = re.compile(r"^S-(\d)-(\d+)(?:-\d+){1,15}$")
    sid_match = sid_pattern.match(sid)
    if not sid_match:
        raise ValueError(f"Input string '{sid}' is not a valid SID string")

    sid_split = sid.split("-")
    revision = int(sid_split[1])
    authority = int(sid_split[2])

    data = bytearray(8)
    memoryview(data)[:8] = struct.pack(">Q", authority)
    data[0] = revision
    data[1] = len(sid_split) - 3

    for idx in range(3, len(sid_split)):
        sub_auth = int(sid_split[idx])
        data += struct.pack("<I", sub_auth)

    return bytes(data)


def ace_to_bytes(sid: str, access_mask: int) -> bytes:
    b_sid = sid_to_bytes(sid)

    data = bytearray(8 + len(b_sid))
    view = memoryview(data)

    data[0] = 0  # AceType - ACCESS_ALLOWED_ACE_TYPE
    data[1] = 0  # AceFlags - None
    view[2:4] = struct.pack("<H", len(data))
    view[4:8] = struct.pack("<I", access_mask)
    view[8:] = b_sid

    return bytes(data)


def acl_to_bytes(aces: t.List[bytes]) -> bytes:
    ace_data = b"".join(aces)

    data = bytearray(8 + len(ace_data))
    view = memoryview(data)

    data[0] = 2  # AclRevision - ACL_REVISION
    data[1] = 0  # Sbz1
    view[2:4] = struct.pack("<H", 8 + len(ace_data))
    view[4:6] = struct.pack("<H", len(aces))
    view[6:8] = struct.pack("<H", 0)  # Sbz2
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


def create_pdu(
    packet_type: int,
    packet_flags: int,
    call_id: int,
    header_data: bytes,
    *,
    stub_data: t.Optional[bytes] = None,
    sec_trailer: t.Optional[SecTrailer] = None,
) -> bytes:
    # https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf
    # 12.6.3 Connection-oriented PDU Data Types - PDU Header
    data = bytearray()
    data += struct.pack("B", 5)  # Version
    data += struct.pack("B", 0)  # Version minor
    data += struct.pack("B", packet_type)
    data += struct.pack("B", packet_flags)
    data += b"\x10\x00\x00\x00"  # Data Representation
    data += b"\x00\x00"  # Fragment length - set at the end below
    data += struct.pack("<H", len(sec_trailer.data) if sec_trailer else 0)
    data += struct.pack("<I", call_id)
    data += header_data
    data += stub_data or b""

    if sec_trailer:
        data += struct.pack("B", sec_trailer.type)
        data += struct.pack("B", sec_trailer.level)
        data += struct.pack("B", sec_trailer.pad_length)
        data += struct.pack("B", 0)  # Auth Rsrvd
        data += struct.pack("<I", sec_trailer.context_id)
        data += sec_trailer.data

    memoryview(data)[8:10] = struct.pack("<H", len(data))

    return bytes(data)


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
    ctx: t.Optional[gssapi.SecurityContext] = None,
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


def generate_l1_seed_key(
    target_sd: bytes,
    root_key_id: uuid.UUID,
    l0: int,
    root_key: RootKey,
) -> GroupKeyEnvelope:
    hash_algo: hashes.HashAlgorithm
    if root_key.kdf_parameters.hash_name == "SHA1":
        hash_algo = hashes.SHA512()
    elif root_key.kdf_parameters.hash_name == "SHA256":
        hash_algo = hashes.SHA256()
    elif root_key.kdf_parameters.hash_name == "SHA384":
        hash_algo = hashes.SHA384()
    elif root_key.kdf_parameters.hash_name == "SHA512":
        hash_algo = hashes.SHA512()
    else:
        raise NotImplementedError(f"Unsupported hash algorithm {root_key.kdf_parameters.hash_name}")

    # Note: 512 is number of bits, we use byte length here
    # Key(SD, RK, L0, -1, -1) = KDF(
    #   HashAlg,
    #   RK.msKds-RootKeyData,
    #   "KDS service",
    #   RKID || L0 || 0xffffffff || 0xffffffff,
    #   512
    # )
    l0_seed = kdf(
        hash_algo,
        root_key.data,
        KDS_SERVICE_LABEL,
        compute_kdf_context(root_key_id, l0, -1, -1),
        64,
    )

    # Key(SD, RK, L0, 31, -1) = KDF(
    #   HashAlg,
    #   Key(SD, RK, L0, -1, -1),
    #   "KDS service",
    #   RKID || L0 || 31 || 0xffffffff || SD,
    #   512
    # )
    l1_seed = kdf(
        hash_algo,
        l0_seed,
        KDS_SERVICE_LABEL,
        compute_kdf_context(root_key_id, l0, 31, -1) + target_sd,
        64,
    )

    return GroupKeyEnvelope(
        version=1,
        flags=2,
        l0=l0,
        l1=31,
        l2=31,
        root_key_identifier=root_key_id,
        kdf_algorithm=root_key.kdf_algorithm,
        kdf_parameters=root_key.kdf_parameters.pack(),
        secret_algorithm=root_key.secret_algorithm,
        secret_parameters=root_key.secret_parameters.pack(),
        private_key_length=root_key.private_key_length,
        public_key_length=root_key.public_key_length,
        domain_name="",
        forest_name="",
        l1_key=l1_seed,
        l2_key=b"",
    )


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


def parse_dpapi_ng_blob(data: bytes) -> t.Tuple[KEKRecipientInfo, EncryptedContentInfo]:
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


def compute_l2_key(
    algorithm: hashes.HashAlgorithm,
    request: EncPasswordId,
    rk: GroupKeyEnvelope,
) -> bytes:
    l1 = rk.l1
    l1_key = rk.l1_key
    l2 = rk.l2
    l2_key = rk.l2_key
    reseed_l2 = rk.l1 != request.l1

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


def ncrypt_unprotect_secret(
    dc: str,
    blob: bytes,
    rpc_sign_header: bool = True,
    root_key: t.Optional[RootKey] = None,
) -> bytes:
    kek_info, enc_content = parse_dpapi_ng_blob(blob)

    assert kek_info.version == 4
    assert kek_info.kekid.other is not None
    assert kek_info.kekid.other.key_attr_id == "1.3.6.1.4.1.311.74.1"
    protection_descriptor = NCryptProtectionDescriptor.unpack(kek_info.kekid.other.key_attr or b"")
    assert protection_descriptor.content_type == "1.3.6.1.4.1.311.74.1.1"
    assert enc_content.content

    password_id = EncPasswordId.unpack(kek_info.kekid.key_identifier)

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

    if root_key:
        rk = generate_l1_seed_key(
            target_sd,
            password_id.root_key_identifier,
            password_id.l0,
            root_key,
        )
    else:
        rk = get_key(
            dc,
            target_sd,
            password_id.root_key_identifier,
            password_id.l0,
            password_id.l1,
            password_id.l2,
            sign_header=rpc_sign_header,
        )

    assert rk.version == 1
    assert not rk.is_public_key
    assert rk.kdf_algorithm == "SP800_108_CTR_HMAC"
    assert rk.l0 == password_id.l0

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

    l2_key = compute_l2_key(hash_algo, password_id, rk)

    if password_id.is_public_key:
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
            dh_pub_key = FFCDHKey.unpack(password_id.unknown)
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

            ecdh_pub_key_info = ECDHKey.unpack(password_id.unknown)

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
        kek_context = password_id.unknown

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


def main() -> None:
    # dc = "dc01.domain.test"
    # server = "CN=SERVER2022,OU=Servers,DC=domain,DC=test"

    dc = "dc01.laps.test"
    server = "CN=APP01,OU=Servers,DC=laps,DC=test"

    sign_header = True

    root_key = RootKey(
        data=base64.b16decode(
            "dc24ff6db13170188ec9ffb511fa41a6eb51d049fe8cfe27d683d51ed5a10faf643f672ee6ed8f9f5e1118727b3aa9384ff943ff5b04f310530b083c3437996e".upper()
        ),
    )

    # Delete the key under C:\Users\vagrant-domain\AppData\Local\Microsoft\Crypto\KdsKey\62dfbd45d9ce7632efd1f252eedb7a94b806849138424140b12517aa45eb1f47\PrivateKey\361-bac64fa8-e890-917c-1090-83e7b0f85996
    # to test out the RPC traffic. Will need to figure out how this format is created.
    # GetSIDKeyFileName in KdsCli.dll

    # Manual call to NCryptProtectSecret with b"\x00" - PowerShell
    """
    $ncrypt = New-CtypesLib ncrypt.dll

    $descriptor = [IntPtr]::Zero
    $res = $ncrypt.NCryptCreateProtectionDescriptor(
        $ncrypt.MarshalAs("SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)", "LPWStr"),
        0,
        [ref]$descriptor)
    if ($res) {
        throw [System.ComponentModel.Win32Exception]$res
    }

    $data = [byte[]]::new(1)
    $blob = [IntPtr]::Zero
    $blobLength = 0
    $res = $ncrypt.NCryptProtectSecret(
        $descriptor,
        0x40,  # NCRYPT_SILENT_FLAG
        $ncrypt.MarshalAs($data, 'LPArray'),
        $data.Length,
        $null,
        $null,
        [ref]$blob,
        [ref]$blobLength)
    if ($res) {
        throw [System.ComponentModel.Win32Exception]$res
    }
    $encBlob = [byte[]]::new($blobLength)
    [System.Runtime.InteropServices.Marshal]::Copy($blob, $encBlob, 0, $encBlob.Length)
    [System.Convert]::ToBase64String($encBlob)
    """
    # enc_blob = base64.b64decode(
    #     "MIIBeAYJKoZIhvcNAQcDoIIBaTCCAWUCAQIxggEeooIBGgIBBDCB3QSBhAEAAABLRFNLAgAAAGkBAAAPAAAAGwAAAKhPxrqQ6HyREJCD57D4WZYgAAAAGAAAABgAAAAa/cFOt3P0FBkN6GSXlXNOAl40T+fROdNdSUMskOmuKGQAbwBtAGEAaQBuAC4AdABlAHMAdAAAAGQAbwBtAGEAaQBuAC4AdABlAHMAdAAAADBUBgkrBgEEAYI3SgEwRwYKKwYBBAGCN0oBATA5MDcwNQwDU0lEDC5TLTEtNS0yMS00MTUxODA4Nzk3LTM0MzA1NjEwOTItMjg0MzQ2NDU4OC0xMTA0MAsGCWCGSAFlAwQBLQQoxsqDoXhEIMILLVXlzv5lxVBeFKMAERib1FLNLP2spEzg5FPGLL0hLDA+BgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFtAVOwxnWdYMTxYyQIBEIARjFXg19IqURZ0g3hSWScPs24="
    # )
    # plaintext = ncrypt_unprotect_secret(dc, enc_blob, rpc_sign_header=sign_header)

    # enc_blob = base64.b16decode(
    #     "3082045006092a864886f70d010703a08204413082043d02010231820409a2820405020104308203c704820370010000004b44534b03000000690100000f0000001e00000069d83cd1d10ebfac4620a164e805f56e080300001a0000001a000000444850420001000087a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa3016c3d91134096faa3bf4296d830e9a7c209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76b63acae1caa6b7902d52526735488a0ef13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103a4b54330c198af126116d2276e11715f693877fad7ef09cadb094ae91e1a15973fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc4165911914ea310a2766c1ec2f5ba89d34002d975da503cc1809d05249fbad13f038a5a9fcb381601e04ec4b9b4f31f6ef25a3f56356d28590727df18f626a04caa3cd81ec602c22e0172a029256caf961a461e3ab61502ee6f27f1f134a88f37019534c7075cfe990ecfe535d1042ee1964af66a7e9e1167a0ffbd8359a6042a3117102240cf5cfd9c442259f0f3db45d1dd51a10e7f3e314250f2079b6122d84ebd9d405c83826d625c8a57dfe518389d645ee4daec02d48b7470e8419c84ed7bcabaf47ded6a1b1f132010d35004adf37fec61dfbc008fda690389ed945ea96bad5f3acffe0fe01f818cd10d01d58d012a37b98758928531d9bf5a614041f4cfbf4e00450057004c004100500053002e0043004f005200500000004e00450057004c004100500053002e0043004f00520050000000305106092b0601040182374a013044060a2b0601040182374a01013036303430320c035349440c2b532d312d352d32312d39323130343037302d313632323731323839342d333433363534373836332d353132300b060960864801650304012d04281a7b6922fc2450c81354ad9d3ce1020d24c327a071f57de6a74dddf3c0b4acb9cf3104efc06fb18d302b06092a864886f70d010701301e060960864801650304012e3011040c247911a21b5c7f4fd08359f9020110426af21e4b446113ce8c4ea45685ecf21d800047f61d5772452b3dab1efc093692f0e3fa3a16ad0fbdbe0df9e9953a934ff129848d34c1e1bc2f5eaefbe67eaa40f158759144b800325ac1307aafd02ce418badf3a9ed849d4053ffde7c2a3822d169377ebcce5c9a9a1a95261c02d49ba014edf882aa54141d0d9b5aa03155eef9f05a0233dbbd9c45f62f58f407cd25320".upper()
    # )
    # plaintext = ncrypt_unprotect_secret(dc, enc_blob, rpc_sign_header=sign_header)

    # LAPS - msLAPS-EncryptedPassword
    enc_password = get_laps_enc_password(dc, server)
    laps_blob = EncryptedLAPSBlob.unpack(enc_password)
    plaintext = ncrypt_unprotect_secret(
        dc,
        laps_blob.blob,
        rpc_sign_header=sign_header,
        # root_key=root_key,
    )
    print(f"LAPS Password: {plaintext.decode('utf-16-le')}")

    print(f"Plaintext hex: {base64.b16encode(plaintext).decode()}")


if __name__ == "__main__":
    main()
