# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import uuid

from dpapi_ng import _blob as blob

from .conftest import get_test_data


def test_blob_unpack() -> None:
    data = get_test_data("dpapi_ng_blob")

    msg = blob.DPAPINGBlob.unpack(data)
    assert msg.key_identifier.version == 1
    assert msg.key_identifier.flags == 3
    assert msg.key_identifier.is_public_key
    assert msg.key_identifier.l0 == 361
    assert msg.key_identifier.l1 == 16
    assert msg.key_identifier.l2 == 3
    assert msg.key_identifier.root_key_identifier == uuid.UUID("d778c271-9025-9a82-f6dc-b8960b8ad8c5")
    assert msg.key_identifier.key_info == get_test_data("ffc_dh_key")
    assert msg.key_identifier.domain_name == "domain.test"
    assert msg.key_identifier.forest_name == "domain.test"
    assert isinstance(msg.protection_descriptor, blob.SIDDescriptor)
    assert msg.protection_descriptor.value == "S-1-5-21-3337337973-3297078028-437386066-512"
    assert msg.enc_cek == (
        b"\x89\x7F\xC4\x3F\x74\x8E\xFD\x09"
        b"\x57\x27\xDD\xE9\x8F\x4E\x1A\x6F"
        b"\xFB\x9D\x41\x63\xD3\x9F\xB3\x74"
        b"\xD0\x49\xC7\x3D\x89\x69\x0C\x7E"
        b"\xFA\x45\xE6\xBE\x11\x9E\x0D\x6B"
    )
    assert msg.enc_cek_algorithm == "2.16.840.1.101.3.4.1.45"
    assert msg.enc_cek_parameters is None
    assert msg.enc_content == (
        b"\xE4\xCD\xF6\x54\x72\x2A\x49\xD5"
        b"\x5F\x53\x08\x55\x0E\xC4\xE8\xAA"
        b"\xC6\xD0\xBE\x49\x51\x16\xF6\x13"
        b"\x2A\x4D\x59\x17\x9F\xD7\x13\x8E"
        b"\xC9\x4B\x53\x6E\x25\x11\xD5\xCA"
        b"\x0D\x37\x8D\xEC\x3C\x42\x3D\x55"
        b"\xC5\x0A\x60\xDC\x41\x8F\x90\x17"
        b"\x82\x48\x46\xE0\x2B\x62\x04\xC8"
        b"\xB3\x27\x3C\x9F\xC4\x43\x37\x63"
        b"\x94\x47\x3B\xF9\x7B\xDC\x55\x80"
        b"\x09\x51\xAD\xF9\x23\x8D\x8A\x02"
        b"\xFF\xE0\x38\xCD\x4D\x7B\x16\x01"
        b"\x2F\x7A\xE8\xB8\x79\x03\xE0\x50"
        b"\x00\xD8\xE3\x10\xDE\x1B\x2D\x1C"
        b"\xA3\x44\xB2\xF2\x67\x3A\x3D\x5A"
        b"\x5C\x4D\xE4\x63\x26\x4B\x95\x64"
        b"\xEB\x9E\xB0\x4C\x52\x71\x1C\x33"
        b"\xC5\xA7\xA9\x74\x0D\x66\x54\x88"
        b"\x55\xB6"
    )
    assert msg.enc_content_algorithm == "2.16.840.1.101.3.4.1.46"
    assert msg.enc_content_parameters == b"\x30\x11\x04\x0C\x9E\x5B\x2E\x17\xC2\x3F\x04\xFC\x35\x25\xE1\x18\x02\x01\x10"
