# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import uuid

import pytest

from dpapi_ng import _gkdi as gkdi


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
