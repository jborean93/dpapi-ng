# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import re

import pytest

import dpapi_ng._asn1 as asn1


class EnumeratedEnum(enum.IntEnum):
    ENUM0 = 0
    ENUM1 = 1
    ENUM2 = 2
    ENUM3 = 3


ASN1_TAG_TESTS = [
    # Simple universal
    (asn1.TagClass.UNIVERSAL, False, asn1.TypeTagNumber.OCTET_STRING, b"\x00", b"\x04\x01\x00"),
    # Constructed value
    (asn1.TagClass.UNIVERSAL, True, asn1.TypeTagNumber.OCTET_STRING, b"\x00\x00", b"\x24\x02\x00\x00"),
    # Large tag number
    (asn1.TagClass.APPLICATION, True, 1024, b"\x00\x00", b"\x7F\x88\x00\x02\x00\x00"),
    (asn1.TagClass.APPLICATION, True, 1048576, b"\x00\x00", b"\x7F\xC0\x80\x00\x02\x00\x00"),
    # Long length
    (asn1.TagClass.UNIVERSAL, False, asn1.TypeTagNumber.OCTET_STRING, b"\x00" * 127, b"\x04\x7F" + (b"\x00" * 127)),
    (asn1.TagClass.UNIVERSAL, False, asn1.TypeTagNumber.OCTET_STRING, b"\x00" * 128, b"\x04\x81\x80" + (b"\x00" * 128)),
    (
        asn1.TagClass.UNIVERSAL,
        False,
        asn1.TypeTagNumber.OCTET_STRING,
        b"\x00" * 1024,
        b"\x04\x82\x04\x00" + (b"\x00" * 1024),
    ),
]

# openssl asn1parse -genstr 'INTEGER:<val>' -out test && hexdump -C test && rm test
INTEGER_TESTS = [  # INTEGER has weird rules that I don't fully understand, use a test of test cases.
    (-748591, b"\x02\x03\xF4\x93\xD1"),
    (-32769, b"\x02\x03\xFF\x7F\xFF"),
    (-32768, b"\x02\x02\x80\x00"),
    (-32767, b"\x02\x02\x80\x01"),
    (-257, b"\x02\x02\xFE\xFF"),
    (-256, b"\x02\x02\xFF\x00"),
    (-255, b"\x02\x02\xFF\x01"),
    (-129, b"\x02\x02\xFF\x7F"),
    (-128, b"\x02\x01\x80"),
    (-127, b"\x02\x01\x81"),
    (-17, b"\x02\x01\xEF"),
    (-16, b"\x02\x01\xF0"),
    (-10, b"\x02\x01\xF6"),
    (-1, b"\x02\x01\xFF"),
    (0, b"\x02\x01\x00"),
    (1, b"\x02\x01\x01"),
    (10, b"\x02\x01\x0A"),
    (16, b"\x02\x01\x10"),
    (17, b"\x02\x01\x11"),
    (127, b"\x02\x01\x7F"),
    (128, b"\x02\x02\x00\x80"),
    (129, b"\x02\x02\x00\x81"),
    (255, b"\x02\x02\x00\xFF"),
    (256, b"\x02\x02\x01\x00"),
    (257, b"\x02\x02\x01\x01"),
    (32767, b"\x02\x02\x7F\xFF"),
    (32768, b"\x02\x03\x00\x80\x00"),
    (32769, b"\x02\x03\x00\x80\x01"),
    (748591, b"\x02\x03\x0B\x6C\x2F"),
]


@pytest.mark.parametrize("tag_class, constructed, tag_number, data, expected", ASN1_TAG_TESTS)
def test_pack_asn1_tlv(
    tag_class: asn1.TagClass,
    constructed: bool,
    tag_number: int,
    data: bytes,
    expected: bytes,
) -> None:
    actual = asn1._pack_asn1(tag_class, constructed, tag_number, data)
    assert actual == expected


@pytest.mark.parametrize("tag_class, constructed, tag_number, data, value", ASN1_TAG_TESTS)
def test_unpack_asn1_tlv(
    tag_class: asn1.TagClass,
    constructed: bool,
    tag_number: int,
    data: bytes,
    value: bytes,
) -> None:
    actual = asn1._read_asn1_header(value)

    assert actual.tag.tag_class == tag_class
    assert actual.tag.is_constructed == constructed
    assert actual.tag.tag_number == tag_number
    assert actual.tag_length == len(value) - len(data)
    assert actual.length == len(data)


@pytest.mark.parametrize("value, expected", INTEGER_TESTS)
def test_pack_asn1_integer(value: int, expected: bytes) -> None:
    actual = asn1._pack_asn1_integer(value)
    assert actual == expected


@pytest.mark.parametrize("expected, value", INTEGER_TESTS)
def test_unpack_asn1_integer(expected: int, value: bytes) -> None:
    actual, consumed = asn1._read_asn1_integer(value)
    assert actual == expected
    assert consumed == len(value)


@pytest.mark.parametrize(
    "expected, value",
    [
        (True, b"\x01\x01\x01"),
        (True, b"\x01\x01\x02"),
        (True, b"\x01\x01\xFF"),
        (True, b"\x01\x02\x00\x01"),
        (True, b"\x01\x02\x01\x00"),
        (False, b"\x01\x01\x00"),
        (False, b"\x01\x02\x00\x00"),
    ],
)
def test_unpack_asn1_boolean(expected: bool, value: bytes) -> None:
    actual = asn1.ASN1Reader(value).read_boolean()
    assert actual == expected


@pytest.mark.parametrize(
    "expected, value",
    [
        (EnumeratedEnum.ENUM0, b"\x0a\x01\x00"),
        (EnumeratedEnum.ENUM1, b"\x0a\x01\x01"),
        (EnumeratedEnum.ENUM2, b"\x0a\x01\x02"),
    ],
)
def test_unpack_asn1_enumerator(expected: EnumeratedEnum, value: bytes) -> None:
    actual = asn1.ASN1Reader(value).read_enumerated(EnumeratedEnum)
    assert actual == expected


@pytest.mark.parametrize(
    "expected, value",
    [
        ("19851106210627.3", b"\x18\x1019851106210627.3"),
        ("19851106210627.3Z", b"\x18\x1119851106210627.3Z"),
        ("19851106210627.3-0500", b"\x18\x1519851106210627.3-0500"),
    ],
)
def test_unpack_asn1_generalized_time(expected: str, value: bytes) -> None:
    actual = asn1.ASN1Reader(value).read_generalized_time()
    assert actual == expected


def test_reader_skip_value() -> None:
    with asn1.ASN1Writer() as writer:
        with writer.push_set_of() as w:
            w.write_octet_string(b"value 1")
            w.write_octet_string(b"value 2")

    reader = asn1.ASN1Reader(writer.get_data())
    set_reader = reader.read_set_of()

    next_header = set_reader.peek_header()
    set_reader.skip_value(next_header)
    assert set_reader.read_octet_string() == b"value 2"
    assert set_reader.get_remaining_data() == b""


def test_reader_get_remaining() -> None:
    with asn1.ASN1Writer() as writer:
        with writer.push_set_of() as w:
            w.write_octet_string(b"value 1")
            w.write_octet_string(b"value 2")

    reader = asn1.ASN1Reader(writer.get_data())
    set_reader = reader.read_set_of()
    assert reader.get_remaining_data() == b""

    assert set_reader.read_octet_string() == b"value 1"
    assert set_reader.get_remaining_data() == b"\x04\x07value 2"


def test_writer_push_sequence() -> None:
    expected = b"\x30\x0A\x02\x01\x01\x04\x05\x76\x61\x6C\x75\x65"
    with asn1.ASN1Writer() as writer:
        with writer.push_sequence() as w:
            w.write_integer(1)
            w.write_octet_string(b"value")

    actual = writer.get_data()
    assert actual == expected


def test_writer_push_sequence_with_tag() -> None:
    expected = b"\xA0\x0A\x02\x01\x01\x04\x05\x76\x61\x6C\x75\x65"
    with asn1.ASN1Writer() as writer:
        with writer.push_sequence(asn1.ASN1Tag(asn1.TagClass.CONTEXT_SPECIFIC, 0, True)) as w:
            w.write_integer(1)
            w.write_octet_string(b"value")

    actual = writer.get_data()
    assert actual == expected


def test_writer_push_set() -> None:
    expected = b"\x31\x06\x01\x01\x00\x01\x01\xFF"
    with asn1.ASN1Writer() as writer:
        with writer.push_set() as w:
            w.write_boolean(False)
            w.write_boolean(True)

    actual = writer.get_data()
    assert actual == expected


def test_writer_push_set_with_tag() -> None:
    expected = b"\xA0\x06\x01\x01\x00\x01\x01\xFF"
    with asn1.ASN1Writer() as writer:
        with writer.push_set(asn1.ASN1Tag(asn1.TagClass.CONTEXT_SPECIFIC, 0, True)) as w:
            w.write_boolean(False)
            w.write_boolean(True)

    actual = writer.get_data()
    assert actual == expected


def test_writer_write_bool() -> None:
    expected = b"\x01\x01\xFF"
    with asn1.ASN1Writer() as writer:
        writer.write_boolean(True)

    actual = writer.get_data()
    assert actual == expected


def test_writer_write_bool_with_tag() -> None:
    expected = b"\xA0\x01\xFF"
    with asn1.ASN1Writer() as writer:
        writer.write_boolean(True, asn1.ASN1Tag(asn1.TagClass.CONTEXT_SPECIFIC, 0, True))

    actual = writer.get_data()
    assert actual == expected


def test_writer_write_octet_string() -> None:
    expected = b"\x04\x01\xFF"
    with asn1.ASN1Writer() as writer:
        writer.write_octet_string(b"\xFF")

    actual = writer.get_data()
    assert actual == expected


def test_writer_write_octet_with_tag() -> None:
    expected = b"\xA0\x01\xFF"
    with asn1.ASN1Writer() as writer:
        writer.write_octet_string(b"\xFF", asn1.ASN1Tag(asn1.TagClass.CONTEXT_SPECIFIC, 0, True))

    actual = writer.get_data()
    assert actual == expected


def test_writer_write_object_identifier() -> None:
    expected = b"\x06\t*\x86H\x86\xf7\r\x01\x07\x03"
    with asn1.ASN1Writer() as writer:
        writer.write_object_identifier("1.2.840.113549.1.7.3")

    actual = writer.get_data()
    assert actual == expected


def test_fail_pack_invalid_object_identifier() -> None:
    with pytest.raises(ValueError, match="Illegal object identifier"):
        asn1._encode_object_identifier("40.50.1.2.3")


def test_writer_write_enumerated() -> None:
    expected = b"\x0A\x01\x01"
    with asn1.ASN1Writer() as writer:
        writer.write_enumerated(EnumeratedEnum.ENUM1)

    actual = writer.get_data()
    assert actual == expected


def test_writer_write_enumerated_with_tag() -> None:
    expected = b"\xA0\x01\x01"
    with asn1.ASN1Writer() as writer:
        writer.write_enumerated(EnumeratedEnum.ENUM1, asn1.ASN1Tag(asn1.TagClass.CONTEXT_SPECIFIC, 0, True))

    actual = writer.get_data()
    assert actual == expected


def test_fail_get_data_on_inner_writer() -> None:
    with asn1.ASN1Writer() as writer:
        with writer.push_set_of() as w:
            with pytest.raises(TypeError, match="Cannot get_data\\(\\) on child ASN1 writer"):
                w.get_data()


def test_fail_pack_invalid_class() -> None:
    with pytest.raises(ValueError, match="tag_class must be between 0 and 3"):
        asn1._pack_asn1(4, True, 0, b"")  # type: ignore[arg-type]  # For test


def test_fail_read_header_not_enough_for_tag_class() -> None:
    with pytest.raises(asn1.NotEnougData):
        asn1._read_asn1_header(b"")


def test_fail_read_header_not_enough_for_tag_length() -> None:
    with pytest.raises(asn1.NotEnougData):
        asn1._read_asn1_header(b"\xFF")


def test_fail_read_header_not_enough_for_length() -> None:
    with pytest.raises(asn1.NotEnougData):
        asn1._read_asn1_header(b"\x01")


def test_fail_read_header_with_indefinite_length() -> None:
    expected = "Received BER indefinite encoded value which is unsupported by LDAP messages"

    with pytest.raises(ValueError, match=expected):
        asn1._read_asn1_header(b"\x01\x80")


def test_fail_read_header_not_enough_for_length_octets() -> None:
    with pytest.raises(asn1.NotEnougData):
        asn1._read_asn1_header(b"\x04\x81")


def test_fail_unpack_not_enough_for_value() -> None:
    with pytest.raises(asn1.NotEnougData):
        asn1._read_asn1_boolean(b"\x01\x01")


def test_fail_invalid_tag() -> None:
    expected = "Expected tag ASN1Tag(tag_class=<TagClass.UNIVERSAL: 0>, tag_number=<TypeTagNumber.BOOLEAN: 1>, is_constructed=False) but got ASN1Tag(tag_class=<TagClass.CONTEXT_SPECIFIC: 2>, tag_number=0, is_constructed=False)"

    with pytest.raises(ValueError, match=re.escape(expected)):
        asn1._read_asn1_boolean(b"\x80\x01\x00")


@pytest.mark.parametrize(
    "expected, value",
    [
        (False, b"\x01\x01\x00"),
        (True, b"\x01\x01\xFF"),
    ],
)
def test_read_asn1_boolean(expected: bool, value: bytes) -> None:
    actual, consumed = asn1._read_asn1_boolean(value)
    assert actual == expected
    assert consumed == 3


@pytest.mark.parametrize(
    "expected, value",
    [
        (False, b"\x80\x01\x00"),
        (True, b"\x80\x01\xFF"),
    ],
)
def test_read_asn1_boolean_with_tag(expected: bool, value: bytes) -> None:
    actual, consumed = asn1._read_asn1_boolean(
        value,
        tag=asn1.ASN1Tag(asn1.TagClass.CONTEXT_SPECIFIC, 0, False),
    )
    assert actual == expected
    assert consumed == 3


@pytest.mark.parametrize(
    "expected, value",
    [
        (0, b"\x0A\x01\x00"),
        (1, b"\x0A\x01\x01"),
    ],
)
def test_read_asn1_enumerated(expected: int, value: bytes) -> None:
    actual, consumed = asn1._read_asn1_enumerated(value)
    assert actual == expected
    assert consumed == 3


@pytest.mark.parametrize(
    "expected, value",
    [
        (0, b"\x80\x01\x00"),
        (1, b"\x80\x01\x01"),
    ],
)
def test_read_asn1_enumerated_with_tag(expected: int, value: bytes) -> None:
    actual, consumed = asn1._read_asn1_enumerated(
        value,
        tag=asn1.ASN1Tag(asn1.TagClass.CONTEXT_SPECIFIC, 0, False),
    )
    assert actual == expected
    assert consumed == 3
