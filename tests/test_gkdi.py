# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t
import uuid

import pytest
from cryptography.hazmat.primitives import hashes

from dpapi_ng import _blob as blob
from dpapi_ng import _gkdi as gkdi

from .conftest import get_test_data


def test_get_key_pack() -> None:
    expected = (
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x01\x02\x03\x04\x00\x00\x00\x00"
        b"\x00\x00\x02\x00\x00\x00\x00\x00"
        b"\x20\x44\x29\x73\x7f\x91\x6a\x41"
        b"\x9e\xc3\x86\x08\x2a\xfa\xfb\x9e"
        b"\xff\xff\xff\xff\x01\x00\x00\x00"
        b"\x1f\x00\x00\x00"
    )

    msg = gkdi.GetKey(
        target_sd=b"\x01\x02\x03\x04",
        root_key_id=uuid.UUID("73294420-917f-416a-9ec3-86082afafb9e"),
        l0_key_id=-1,
        l1_key_id=1,
        l2_key_id=31,
    )
    actual = msg.pack()
    assert actual == expected


def test_get_key_unpack() -> None:
    data = (
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x01\x02\x03\x04\x00\x00\x00\x00"
        b"\x00\x00\x02\x00\x00\x00\x00\x00"
        b"\x20\x44\x29\x73\x7f\x91\x6a\x41"
        b"\x9e\xc3\x86\x08\x2a\xfa\xfb\x9e"
        b"\xff\xff\xff\xff\x01\x00\x00\x00"
        b"\x1f\x00\x00\x00"
    )
    resp = gkdi.GetKey.unpack(data)
    assert isinstance(resp, gkdi.GetKey)
    assert resp.target_sd == b"\x01\x02\x03\x04"
    assert resp.root_key_id == uuid.UUID("73294420-917f-416a-9ec3-86082afafb9e")
    assert resp.l0_key_id == -1
    assert resp.l1_key_id == 1
    assert resp.l2_key_id == 31


def test_get_key_pack_no_root_key() -> None:
    expected = (
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x01\x02\x03\x04\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xff\xff\xff\xff\x01\x00\x00\x00"
        b"\x1f\x00\x00\x00"
    )

    msg = gkdi.GetKey(
        target_sd=b"\x01\x02\x03\x04",
        root_key_id=None,
        l0_key_id=-1,
        l1_key_id=1,
        l2_key_id=31,
    )
    actual = msg.pack()
    assert actual == expected


def test_get_key_unpack_no_root_key() -> None:
    data = (
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x01\x02\x03\x04\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xff\xff\xff\xff\x01\x00\x00\x00"
        b"\x1f\x00\x00\x00"
    )
    resp = gkdi.GetKey.unpack(data)
    assert isinstance(resp, gkdi.GetKey)
    assert resp.target_sd == b"\x01\x02\x03\x04"
    assert resp.root_key_id is None
    assert resp.l0_key_id == -1
    assert resp.l1_key_id == 1
    assert resp.l2_key_id == 31


def test_get_key_unpack_response() -> None:
    expected = gkdi.GroupKeyEnvelope(1, 0, 0, 0, 0, uuid.UUID(int=0), "", b"", "", b"", 0, 0, "", "", b"", b"")
    b_expected = expected.pack()
    data = (
        len(b_expected).to_bytes(4, byteorder="little")
        + (b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00")
        + b_expected
        + b"\x00\x00\x00\x00"
    )

    actual = gkdi.GetKey.unpack_response(data)
    assert isinstance(actual, gkdi.GroupKeyEnvelope)
    assert actual == expected


def test_get_key_unpack_response_fail() -> None:
    data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x57\x00\x07\x80"

    with pytest.raises(Exception, match="GetKey failed 0x80070057"):
        gkdi.GetKey.unpack_response(data)


def test_kdf_parameters_pack() -> None:
    expected = (
        b"\x00\x00\x00\x00\x01\x00\x00\x00"
        b"\x0E\x00\x00\x00\x00\x00\x00\x00"
        b"\x53\x00\x48\x00\x41\x00\x35\x00"
        b"\x31\x00\x32\x00\x00\x00"
    )

    msg = gkdi.KDFParameters("SHA512")
    actual = msg.pack()
    assert actual == expected


def test_kdf_parameters_unpack() -> None:
    data = (
        b"\x00\x00\x00\x00\x01\x00\x00\x00"
        b"\x0E\x00\x00\x00\x00\x00\x00\x00"
        b"\x53\x00\x48\x00\x41\x00\x35\x00"
        b"\x31\x00\x32\x00\x00\x00"
    )

    msg = gkdi.KDFParameters.unpack(data)
    assert msg.hash_name == "SHA512"


@pytest.mark.parametrize(
    "name, expected",
    [
        ("SHA1", hashes.SHA1),
        ("SHA256", hashes.SHA256),
        ("SHA384", hashes.SHA384),
        ("SHA512", hashes.SHA512),
    ],
)
def test_kdf_parameter_hash_algo(
    name: str,
    expected: t.Type[hashes.HashAlgorithm],
) -> None:
    msg = gkdi.KDFParameters(name)
    assert isinstance(msg.hash_algorithm, expected)


def test_kdf_parameters_invalid_hash() -> None:
    with pytest.raises(NotImplementedError, match="Unsupported hash algorithm MD5"):
        gkdi.KDFParameters("MD5").hash_algorithm


def test_kdf_parameters_invalid_magic() -> None:
    data = b"\x00\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x01"

    with pytest.raises(ValueError, match="Failed to unpack KDFParameters as magic identifier is invalid"):
        gkdi.KDFParameters.unpack(data)


def test_ffc_dh_parameters_pack() -> None:
    expected = get_test_data("ffc_dh_parameters")

    msg = gkdi.FFCDHParameters(
        key_length=256,
        field_order=17125458317614137930196041979257577826408832324037508573393292981642667139747621778802438775238728592968344613589379932348475613503476932163166973813218698343816463289144185362912602522540494983090531497232965829536524507269848825658311420299335922295709743267508322525966773950394919257576842038771632742044142471053509850123605883815857162666917775193496157372656195558305727009891276006514000409365877218171388319923896309377791762590614311849642961380224851940460421710449368927252974870395873936387909672274883295377481008150475878590270591798350563488168080923804611822387520198054002990623911454389104774092183,
        generator=8041367327046189302693984665026706374844608289874374425728797669509435881459140662650215832833471328470334064628508692231999401840332046192569287351991689963279656892562484773278584208040987631569628520464069532361274047374444344996651832979378318849943741662110395995778429270819222431610927356005913836932462099770076239554042855287138026806960470277326229482818003962004453764400995790974042663675692120758726145869061236443893509136147942414445551848162391468541444355707785697825741856849161233887307017428371823608125699892904960841221593344499088996021883972185241854777608212592397013510086894908468466292313,
    )
    actual = msg.pack()
    assert actual == expected


def test_ffc_dh_parameters_pack_small_int() -> None:
    expected = b"\x0C\x02\x00\x00\x44\x48\x50\x4D\x00\x01\x00\x00" + (b"\x00" * 512)

    msg = gkdi.FFCDHParameters(
        key_length=256,
        field_order=0,
        generator=0,
    )
    actual = msg.pack()
    assert actual == expected


def test_ffc_dh_parameters_unpack() -> None:
    data = get_test_data("ffc_dh_parameters")

    msg = gkdi.FFCDHParameters.unpack(data)
    assert msg.key_length == 256
    assert (
        msg.field_order
        == 17125458317614137930196041979257577826408832324037508573393292981642667139747621778802438775238728592968344613589379932348475613503476932163166973813218698343816463289144185362912602522540494983090531497232965829536524507269848825658311420299335922295709743267508322525966773950394919257576842038771632742044142471053509850123605883815857162666917775193496157372656195558305727009891276006514000409365877218171388319923896309377791762590614311849642961380224851940460421710449368927252974870395873936387909672274883295377481008150475878590270591798350563488168080923804611822387520198054002990623911454389104774092183
    )
    assert (
        msg.generator
        == 8041367327046189302693984665026706374844608289874374425728797669509435881459140662650215832833471328470334064628508692231999401840332046192569287351991689963279656892562484773278584208040987631569628520464069532361274047374444344996651832979378318849943741662110395995778429270819222431610927356005913836932462099770076239554042855287138026806960470277326229482818003962004453764400995790974042663675692120758726145869061236443893509136147942414445551848162391468541444355707785697825741856849161233887307017428371823608125699892904960841221593344499088996021883972185241854777608212592397013510086894908468466292313
    )


def test_ffc_dh_parameters_invalid_magic() -> None:
    data = b"\x00\x00\x00\x00\x44\x48\x50\x00"

    with pytest.raises(ValueError, match="Failed to unpack FFCDHParameters as magic identifier is invalid"):
        gkdi.FFCDHParameters.unpack(data)


def test_ffc_dh_key_pack() -> None:
    expected = get_test_data("ffc_dh_key")

    msg = gkdi.FFCDHKey(
        key_length=256,
        field_order=17125458317614137930196041979257577826408832324037508573393292981642667139747621778802438775238728592968344613589379932348475613503476932163166973813218698343816463289144185362912602522540494983090531497232965829536524507269848825658311420299335922295709743267508322525966773950394919257576842038771632742044142471053509850123605883815857162666917775193496157372656195558305727009891276006514000409365877218171388319923896309377791762590614311849642961380224851940460421710449368927252974870395873936387909672274883295377481008150475878590270591798350563488168080923804611822387520198054002990623911454389104774092183,
        generator=8041367327046189302693984665026706374844608289874374425728797669509435881459140662650215832833471328470334064628508692231999401840332046192569287351991689963279656892562484773278584208040987631569628520464069532361274047374444344996651832979378318849943741662110395995778429270819222431610927356005913836932462099770076239554042855287138026806960470277326229482818003962004453764400995790974042663675692120758726145869061236443893509136147942414445551848162391468541444355707785697825741856849161233887307017428371823608125699892904960841221593344499088996021883972185241854777608212592397013510086894908468466292313,
        public_key=5704885921161305204062286453104607919457992927353423073733430775789858496179130688612797173128744245915638749285001365389666398628213879947801588663753164579318944467717026038784117675067248922438216443819787917524104523712708262452393840096093436355765031795113819575193160867788883459494877281145141827767886732955150877747794489653818702322115914625862335942729341854451475767409522001908542192343439374586040439834199899031631166319847176777504380608639274486108367307182844033431414378380156678122207936287391923825983630503829617043562049870198440347689535112361024113575576761204481698354807673154816364980520,
    )
    actual = msg.pack()
    assert actual == expected


def test_ffc_dh_key_pack_small_int() -> None:
    expected = b"\x44\x48\x50\x42\x00\x01\x00\x00" + (b"\x00" * 768)

    msg = gkdi.FFCDHKey(
        key_length=256,
        field_order=0,
        generator=0,
        public_key=0,
    )
    actual = msg.pack()
    assert actual == expected


def test_ffc_dh_key_unpack() -> None:
    data = get_test_data("ffc_dh_key")

    msg = gkdi.FFCDHKey.unpack(data)
    assert msg.key_length == 256
    assert (
        msg.field_order
        == 17125458317614137930196041979257577826408832324037508573393292981642667139747621778802438775238728592968344613589379932348475613503476932163166973813218698343816463289144185362912602522540494983090531497232965829536524507269848825658311420299335922295709743267508322525966773950394919257576842038771632742044142471053509850123605883815857162666917775193496157372656195558305727009891276006514000409365877218171388319923896309377791762590614311849642961380224851940460421710449368927252974870395873936387909672274883295377481008150475878590270591798350563488168080923804611822387520198054002990623911454389104774092183
    )
    assert (
        msg.generator
        == 8041367327046189302693984665026706374844608289874374425728797669509435881459140662650215832833471328470334064628508692231999401840332046192569287351991689963279656892562484773278584208040987631569628520464069532361274047374444344996651832979378318849943741662110395995778429270819222431610927356005913836932462099770076239554042855287138026806960470277326229482818003962004453764400995790974042663675692120758726145869061236443893509136147942414445551848162391468541444355707785697825741856849161233887307017428371823608125699892904960841221593344499088996021883972185241854777608212592397013510086894908468466292313
    )
    assert (
        msg.public_key
        == 5704885921161305204062286453104607919457992927353423073733430775789858496179130688612797173128744245915638749285001365389666398628213879947801588663753164579318944467717026038784117675067248922438216443819787917524104523712708262452393840096093436355765031795113819575193160867788883459494877281145141827767886732955150877747794489653818702322115914625862335942729341854451475767409522001908542192343439374586040439834199899031631166319847176777504380608639274486108367307182844033431414378380156678122207936287391923825983630503829617043562049870198440347689535112361024113575576761204481698354807673154816364980520
    )


def test_ffc_dh_key_invalid_magic() -> None:
    data = b"\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="Failed to unpack FFCDHKey as magic identifier is invalid"):
        gkdi.FFCDHKey.unpack(data)


def test_ecdh_key_pack() -> None:
    expected = get_test_data("ecdh_key")

    msg = gkdi.ECDHKey(
        curve_name="P256",
        key_length=32,
        x=25243830316603712129559807215192800963817053918117758232684283953073092162706,
        y=5597696687659389228845157203945777531845995814681629604081047981407116394432,
    )
    actual = msg.pack()
    assert actual == expected


def test_ecdh_key_pack_small_int() -> None:
    expected = b"\x45\x43\x4B\x31\x20\x00\x00\x00" + (b"\x00" * 64)
    msg = gkdi.ECDHKey(
        curve_name="P256",
        key_length=32,
        x=0,
        y=0,
    )
    actual = msg.pack()
    assert actual == expected


def test_ecdh_key_pack_invalid_curve() -> None:
    with pytest.raises(ValueError, match="Unknown curve 'test', cannot pack"):
        gkdi.ECDHKey(curve_name="test", key_length=0, x=0, y=0).pack()


def test_ecdh_key_unpack() -> None:
    data = get_test_data("ecdh_key")

    msg = gkdi.ECDHKey.unpack(data)
    assert msg.key_length == 32
    assert msg.curve_name == "P256"
    assert msg.curve_and_hash
    assert msg.x == 25243830316603712129559807215192800963817053918117758232684283953073092162706
    assert msg.y == 5597696687659389228845157203945777531845995814681629604081047981407116394432


def test_ecdh_key_unpack_invalid_curve() -> None:
    data = b"\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="Failed to unpack ECDHKey with unknown curve 0x00000000"):
        gkdi.ECDHKey.unpack(data)


def test_group_key_envelope_pack() -> None:
    expected = get_test_data("group_key_envelope")
    l1 = (
        b"\x9C\x8F\x03\x85\xD7\x46\x06\x2A"
        b"\xFB\x90\xBA\x9D\x02\x3A\x3A\x5C"
        b"\x24\x2E\xB5\x33\x43\x41\xBE\xFA"
        b"\xDC\x49\xE2\x7A\x90\x8F\xC3\x39"
        b"\x3B\xAC\x40\x14\x56\xA8\x65\x61"
        b"\x04\xC8\x72\xD0\xC9\x96\xAA\x25"
        b"\x9A\x95\x4B\xF5\xA3\x8B\x8D\x6E"
        b"\xC7\xCD\xBA\xC1\x35\x9E\x5A\x09"
    )
    l2 = (
        b"\x1B\xAC\x68\xA1\xA7\xC8\xB9\xAC"
        b"\x94\x4C\x8E\xB1\xEA\x39\x6C\xC3"
        b"\x66\x68\x5E\x17\xA4\x11\x0A\x1F"
        b"\xB5\x5E\x7C\x44\x11\xA6\xFA\xA5"
        b"\x8F\x8E\x5B\xE1\x25\x24\xFA\xBB"
        b"\xC3\x44\xC5\x9B\xEA\xF9\xB3\xEC"
        b"\xE2\x18\xEA\x8E\x4F\x81\x1B\x6C"
        b"\xAF\xEA\x4B\x77\xE7\xEF\x0A\xED"
    )

    msg = gkdi.GroupKeyEnvelope(
        version=1,
        flags=2,
        l0=361,
        l1=17,
        l2=8,
        root_key_identifier=uuid.UUID("d778c271-9025-9a82-f6dc-b8960b8ad8c5"),
        kdf_algorithm="SP800_108_CTR_HMAC",
        kdf_parameters=(
            b"\x00\x00\x00\x00\x01\x00\x00\x00"
            b"\x0E\x00\x00\x00\x00\x00\x00\x00"
            b"\x53\x00\x48\x00\x41\x00\x35\x00"
            b"\x31\x00\x32\x00\x00\x00"
        ),
        secret_algorithm="DH",
        secret_parameters=get_test_data("ffc_dh_parameters"),
        private_key_length=512,
        public_key_length=2048,
        domain_name="domain.test",
        forest_name="domain.test",
        l1_key=l1,
        l2_key=l2,
    )
    actual = msg.pack()
    assert actual == expected


def test_group_key_envelope_unpack() -> None:
    data = get_test_data("group_key_envelope")
    expected_l1 = (
        b"\x9C\x8F\x03\x85\xD7\x46\x06\x2A"
        b"\xFB\x90\xBA\x9D\x02\x3A\x3A\x5C"
        b"\x24\x2E\xB5\x33\x43\x41\xBE\xFA"
        b"\xDC\x49\xE2\x7A\x90\x8F\xC3\x39"
        b"\x3B\xAC\x40\x14\x56\xA8\x65\x61"
        b"\x04\xC8\x72\xD0\xC9\x96\xAA\x25"
        b"\x9A\x95\x4B\xF5\xA3\x8B\x8D\x6E"
        b"\xC7\xCD\xBA\xC1\x35\x9E\x5A\x09"
    )
    expected_l2 = (
        b"\x1B\xAC\x68\xA1\xA7\xC8\xB9\xAC"
        b"\x94\x4C\x8E\xB1\xEA\x39\x6C\xC3"
        b"\x66\x68\x5E\x17\xA4\x11\x0A\x1F"
        b"\xB5\x5E\x7C\x44\x11\xA6\xFA\xA5"
        b"\x8F\x8E\x5B\xE1\x25\x24\xFA\xBB"
        b"\xC3\x44\xC5\x9B\xEA\xF9\xB3\xEC"
        b"\xE2\x18\xEA\x8E\x4F\x81\x1B\x6C"
        b"\xAF\xEA\x4B\x77\xE7\xEF\x0A\xED"
    )

    msg = gkdi.GroupKeyEnvelope.unpack(data)
    assert msg.version == 1
    assert msg.flags == 2
    assert msg.is_public_key is False
    assert msg.l0 == 361
    assert msg.l1 == 17
    assert msg.l2 == 8
    assert msg.root_key_identifier == uuid.UUID("d778c271-9025-9a82-f6dc-b8960b8ad8c5")
    assert msg.kdf_algorithm == "SP800_108_CTR_HMAC"
    assert msg.kdf_parameters == (
        b"\x00\x00\x00\x00\x01\x00\x00\x00"
        b"\x0E\x00\x00\x00\x00\x00\x00\x00"
        b"\x53\x00\x48\x00\x41\x00\x35\x00"
        b"\x31\x00\x32\x00\x00\x00"
    )
    assert msg.secret_algorithm == "DH"
    assert msg.secret_parameters == get_test_data("ffc_dh_parameters")
    assert msg.private_key_length == 512
    assert msg.public_key_length == 2048
    assert msg.domain_name == "domain.test"
    assert msg.forest_name == "domain.test"
    assert msg.l1_key == expected_l1
    assert msg.l2_key == expected_l2


def test_group_key_envelope_invalid_magic() -> None:
    data = b"\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="Failed to unpack GroupKeyEnvelope as magic identifier is invalid"):
        gkdi.GroupKeyEnvelope.unpack(data)


def test_group_key_envelope_get_kek_is_public() -> None:
    envelope = gkdi.GroupKeyEnvelope(
        version=1,
        flags=1,
        l0=0,
        l1=0,
        l2=0,
        root_key_identifier=uuid.UUID(int=0),
        kdf_algorithm="",
        kdf_parameters=b"",
        secret_algorithm="",
        secret_parameters=b"",
        private_key_length=0,
        public_key_length=0,
        domain_name="",
        forest_name="",
        l1_key=b"",
        l2_key=b"",
    )

    with pytest.raises(ValueError, match="Current user is not authorized to retrieve the KEK information"):
        envelope.get_kek(blob.KeyIdentifier(1, 1, 0, 0, 0, uuid.UUID(int=0), b"", "", ""))


def test_group_key_envelope_get_kek_l0_mismatch() -> None:
    envelope = gkdi.GroupKeyEnvelope(
        version=1,
        flags=0,
        l0=1,
        l1=0,
        l2=0,
        root_key_identifier=uuid.UUID(int=0),
        kdf_algorithm="test",
        kdf_parameters=b"",
        secret_algorithm="",
        secret_parameters=b"",
        private_key_length=0,
        public_key_length=0,
        domain_name="",
        forest_name="",
        l1_key=b"",
        l2_key=b"",
    )

    with pytest.raises(ValueError, match="L0 index 1 does not match the requested L0 index 0"):
        envelope.get_kek(blob.KeyIdentifier(1, 1, 0, 0, 0, uuid.UUID(int=0), b"", "", ""))


def test_group_key_envelope_get_kek_invalid_kdf() -> None:
    envelope = gkdi.GroupKeyEnvelope(
        version=1,
        flags=0,
        l0=0,
        l1=0,
        l2=0,
        root_key_identifier=uuid.UUID(int=0),
        kdf_algorithm="test",
        kdf_parameters=b"",
        secret_algorithm="",
        secret_parameters=b"",
        private_key_length=0,
        public_key_length=0,
        domain_name="",
        forest_name="",
        l1_key=b"",
        l2_key=b"",
    )

    with pytest.raises(NotImplementedError, match="Unknown KDF algorithm 'test'"):
        envelope.get_kek(blob.KeyIdentifier(1, 1, 0, 0, 0, uuid.UUID(int=0), b"", "", ""))


# See tests/integration/files/generate_seed_keys.py on how to generate the
# known values from the L1 seed key.
@pytest.mark.parametrize(
    "l1, l2, l1_key, l2_key",
    [
        (
            0,
            0,
            b"",
            (
                b"\x1B\x0F\x11\x3F\x01\x93\x10\xE5"
                b"\xA8\x4E\xA3\x0B\x3A\xCB\xC6\x58"
                b"\x21\x79\xC9\xB0\x49\x2B\xA8\x4A"
                b"\xF6\xA2\x5D\xE3\xCA\x42\x82\xC9"
                b"\x1B\x50\x3B\x7E\x01\x15\x1E\x29"
                b"\x27\x72\x93\x07\xDA\x8E\x60\xC6"
                b"\x4E\x3D\x3A\xFB\x66\x80\x06\xE2"
                b"\x2F\x2B\xFF\x7F\x7C\x14\xAA\x18"
            ),
        ),
        (
            0,
            31,
            (
                b"\xC7\xA2\x2B\x5B\x09\x70\x53\x80"
                b"\xB4\x5C\xDD\x29\x33\xE0\xFA\xA6"
                b"\x8E\xA2\xC9\x8A\x3E\x50\x47\x27"
                b"\x5D\xD3\xB2\xE2\xDC\xCF\x55\x86"
                b"\xD7\x2A\x58\xA0\x76\x2D\x2E\x5A"
                b"\x53\x42\x99\xF5\x40\x5E\x31\xEE"
                b"\x51\x4B\xD4\xE1\x3A\xA2\xF5\x4A"
                b"\xF0\xC3\x0C\xDB\xC9\xCC\x03\x01"
            ),
            b"",
        ),
        (
            31,
            31,
            (
                b"\x60\xE0\xA8\x1F\x93\x16\x4F\x5D"
                b"\xC3\xAB\xE9\x81\xE1\xEE\x54\xC1"
                b"\xA6\xB9\xB0\xED\xB6\xFF\x82\x74"
                b"\x64\x27\x58\xD2\x9B\xBC\x66\x55"
                b"\x9D\x11\xF1\x87\x1A\x82\xA6\xE3"
                b"\xF2\x32\xC4\x24\x90\xD7\xC4\x1C"
                b"\x6A\xD2\xB8\xB1\x89\xFE\x27\x52"
                b"\xA8\x8C\xEC\x2E\xA4\xB2\x02\x1C"
            ),
            b"",
        ),
        (
            2,
            6,
            (
                b"\x58\xC8\xE7\xF9\xC2\xB7\x26\x0B"
                b"\xE8\x8F\xB1\x88\xEB\x62\x1A\x60"
                b"\x91\x97\x74\xB9\x30\x6F\xCF\xE4"
                b"\x5B\x6C\x17\xD0\x49\x4A\x43\xD5"
                b"\x55\xA2\x74\xE6\xDD\x79\x5C\xF0"
                b"\xA6\x81\x92\x63\xDD\x3E\xC9\x12"
                b"\x5E\xB9\xC5\xB6\x2F\xBE\x04\x1A"
                b"\x51\x33\xC1\xA2\xCB\x0A\x58\x92"
            ),
            b"",
        ),
    ],
    ids=[
        "ExactValue",
        "FromL1Seed",
        "FromRootSeed",
        "L1AndL2Different",
    ],
)
def test_compute_l2_key(
    l1: int,
    l2: int,
    l1_key: bytes,
    l2_key: bytes,
) -> None:
    expected = (
        b"\x1B\x0F\x11\x3F\x01\x93\x10\xE5"
        b"\xA8\x4E\xA3\x0B\x3A\xCB\xC6\x58"
        b"\x21\x79\xC9\xB0\x49\x2B\xA8\x4A"
        b"\xF6\xA2\x5D\xE3\xCA\x42\x82\xC9"
        b"\x1B\x50\x3B\x7E\x01\x15\x1E\x29"
        b"\x27\x72\x93\x07\xDA\x8E\x60\xC6"
        b"\x4E\x3D\x3A\xFB\x66\x80\x06\xE2"
        b"\x2F\x2B\xFF\x7F\x7C\x14\xAA\x18"
    )
    l0 = 361
    key_id = uuid.UUID("2e1b932a-4e21-ced3-0b7b-8815aff8335d")

    actual = gkdi.compute_l2_key(
        hashes.SHA512(),
        0,
        0,
        gkdi.GroupKeyEnvelope(
            version=1,
            flags=0,
            l0=l0,
            l1=l1,
            l2=l2,
            root_key_identifier=key_id,
            kdf_algorithm="",
            kdf_parameters=b"",
            secret_algorithm="",
            secret_parameters=b"",
            private_key_length=0,
            public_key_length=0,
            domain_name="",
            forest_name="",
            l1_key=l1_key,
            l2_key=l2_key,
        ),
    )
    assert actual == expected


def test_compute_kek_invalid_algorithm() -> None:
    with pytest.raises(NotImplementedError, match="Unknown secret agreement algorithm 'test'"):
        gkdi.compute_kek_from_public_key(hashes.SHA256(), b"", "test", None, b"", 0)
