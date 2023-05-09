# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import re
import typing as t
import uuid

import pytest

from dpapi_ng import _security_descriptor as security_descriptor

from .conftest import get_test_data


def test_sid_to_bytes() -> None:
    expected = (
        b"\x01\x05\x00\x00\x00\x00\x00\x05"
        b"\x15\x00\x00\x00\x1D\x93\x77\xF7"
        b"\x44\x35\x7A\xCC\x8C\xD3\x7B\xA9"
        b"\x50\x04\x00\x00"
    )
    actual = security_descriptor.sid_to_bytes("S-1-5-21-4151808797-3430561092-2843464588-1104")

    assert actual == expected


@pytest.mark.parametrize(
    "value",
    [
        "S-1-5",
        "S-1-51",
        "S-1-5-",
        "Z-1-5-1",
        "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
    ],
)
def test_sid_to_bytes_invalid(value: str) -> None:
    expected = re.escape(f"Input string '{value}' is not a valid SID string")
    with pytest.raises(ValueError, match=expected):
        security_descriptor.sid_to_bytes(value)


def test_sd_to_bytes_no_sacl() -> None:
    expected = (
        b"\x01\x00\x04\x80\x30\x00\x00\x00"
        b"\x3C\x00\x00\x00\x00\x00\x00\x00"
        b"\x14\x00\x00\x00\x02\x00\x1C\x00"
        b"\x01\x00\x00\x00\x00\x00\x14\x00"
        b"\x01\x00\x00\x00\x01\x01\x00\x00"
        b"\x00\x00\x00\x05\x12\x00\x00\x00"
        b"\x01\x01\x00\x00\x00\x00\x00\x05"
        b"\x12\x00\x00\x00\x01\x01\x00\x00"
        b"\x00\x00\x00\x05\x12\x00\x00\x00"
    )
    actual = security_descriptor.sd_to_bytes(
        "S-1-5-18",
        "S-1-5-18",
        dacl=[security_descriptor.ace_to_bytes("S-1-5-18", 1)],
    )
    assert actual == expected


def test_sd_to_bytes_no_dacl() -> None:
    expected = (
        b"\x01\x00\x10\x80\x30\x00\x00\x00"
        b"\x3C\x00\x00\x00\x14\x00\x00\x00"
        b"\x00\x00\x00\x00\x02\x00\x1C\x00"
        b"\x01\x00\x00\x00\x00\x00\x14\x00"
        b"\x01\x00\x00\x00\x01\x01\x00\x00"
        b"\x00\x00\x00\x05\x12\x00\x00\x00"
        b"\x01\x01\x00\x00\x00\x00\x00\x05"
        b"\x12\x00\x00\x00\x01\x01\x00\x00"
        b"\x00\x00\x00\x05\x12\x00\x00\x00"
    )
    actual = security_descriptor.sd_to_bytes(
        "S-1-5-18",
        "S-1-5-18",
        sacl=[security_descriptor.ace_to_bytes("S-1-5-18", 1)],
    )
    assert actual == expected
