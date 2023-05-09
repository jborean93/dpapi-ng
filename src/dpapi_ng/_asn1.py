# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import struct
import typing as t
from types import TracebackType

T = t.TypeVar("T", bound=int)


class NotEnougData(Exception):
    "There is not enough data available to unpack ASN.1 value"


class TagClass(enum.IntEnum):
    """The ASN.1 tag class types."""

    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT_SPECIFIC = 2
    PRIVATE = 3


class TypeTagNumber(enum.IntEnum):
    """The ASN.1 tag numbers for universal classes."""

    END_OF_CONTENT = 0
    BOOLEAN = 1
    INTEGER = 2
    BIT_STRING = 3
    OCTET_STRING = 4
    NULL = 5
    OBJECT_IDENTIFIER = 6
    OBJECT_DESCRIPTOR = 7
    EXTERNAL = 8
    REAL = 9
    ENUMERATED = 10
    EMBEDDED_PDV = 11
    UTF8_STRING = 12
    RELATIVE_OID = 13
    TIME = 14
    RESERVED = 15
    SEQUENCE = 16
    SEQUENCE_OF = 16
    SET = 17
    SET_OF = 17
    NUMERIC_STRING = 18
    PRINTABLE_STRING = 19
    T61_STRING = 20
    VIDEOTEX_STRING = 21
    IA5_STRING = 22
    UTC_TIME = 23
    GENERALIZED_TIME = 24
    GRAPHIC_STRING = 25
    VISIBLE_STRING = 26
    GENERAL_STRING = 27
    UNIVERSAL_STRING = 28
    CHARACTER_STRING = 29
    BMP_STRING = 30
    DATE = 31
    TIME_OF_DAY = 32
    DATE_TIME = 33
    DURATION = 34
    OID_IRL = 35
    RELATIVE_OID_IRL = 36


class ASN1Tag(t.NamedTuple):
    """ASN.1 tag information.

    Defines the explicit ASN.1 tag used in a value which includes the tag class,
    tag number, and whether it is a constructed or primitive value.

    Args:
        tag_class: The tag class the value represents.
        tag_number: The tag number of the value.
        is_constructed: Whether the value is constructed (True) or primitive
            (False).
    """

    tag_class: TagClass
    "The tag class."

    tag_number: t.Union[int, TypeTagNumber]
    "The tag number, will be TypeTagNumber if the tag_class is UNIVERSAL."

    is_constructed: bool
    "Whether the value is marked as constructed or primitive."

    @classmethod
    def universal_tag(
        cls,
        number: TypeTagNumber,
        is_constructed: bool = False,
    ) -> ASN1Tag:
        """Generates a universal tag with the type specified."""
        return ASN1Tag(
            tag_class=TagClass.UNIVERSAL,
            tag_number=number,
            is_constructed=is_constructed,
        )


class ASN1Header(t.NamedTuple):
    """A representation of an ASN.1 TLV as a tuple.

    Defines the ASN.1 Type Length Value (TLV) values as separate objects for
    easier parsing. This is returned by :func:`ASN1Reader.peek_header`.

    Args:
        tag: The tag details, including the class and tag number.
        tag_length: The length of the encoded tag.
        length: The length of the value the tag represents.
    """

    tag: ASN1Tag
    "The ASN.1 tag details for the current entry."

    tag_length: int
    "The length of the tag/length ASN.1 octets."

    length: int
    "The length of the ASN.1 value."


class ASN1Reader:
    """ASN.1 value reader.

    Class used to read ASN.1 data that is passed in. It provides a an easy way
    to stream through the data as well as peek as the subsequent entries.

    Args:
        data: The data to read from.
    """

    def __init__(
        self,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> None:
        self._data = data
        self._view = memoryview(self._data)

    def __bool__(self) -> bool:
        return bool(self._view)

    def peek_header(self) -> ASN1Header:
        """Get the next value header.

        Gets the header for the next value. This will not read the value so it
        will still be at the same position once run.

        Returns:
            ASN1Header: The header information including the tag information as
            well as the length of the next value.
        """
        return _read_asn1_header(self._view)

    def skip_value(
        self,
        header: ASN1Header,
    ) -> None:
        """Skips the next value.

        Skips the next value as indicated by the header.

        Args:
            header: The header which contains the metadata of the next value to
                skip.
        """
        self._view = self._view[header.tag_length + header.length :]

    def get_remaining_data(self) -> bytes:
        """Gets the remaining data in the reader."""
        data = self._view.tobytes()
        self._view = memoryview(b"")
        return data

    def read_boolean(
        self,
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> bool:
        """Reads an ASN.1 BOOLEAN value.

        Args:
            tag: The tag to validate with, defaults to the BOOLEAN universal
                tag.
            header: Optional header from :func:`peek_header` to make the
                extraction more efficient.
            hint: A hint used in error messages to display what this step was
                used for.

        Returns:
            bool: The bool value.
        """
        val, consumed = _read_asn1_boolean(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return val

    def read_enumerated(
        self,
        enum_type: t.Type[T],
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> T:
        """Reads an ASN.1 ENUMERATED value.

        Args:
            enum_type: The enum.IntEnum type to cast the integer value to.
            tag: The tag to validate with, defaults to the ENUMERATED universal
                tag.
            header: Optional header from :func:`peek_header` to make the
                extraction more efficient.
            hint: A hint used in error messages to display what this step was
                used for.

        Returns:
            T: The instance of enum_type that the value represents.
        """
        val, consumed = _read_asn1_enumerated(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return enum_type(val)

    def read_generalized_time(
        self,
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> str:
        val, consumed = _read_asn1_generalized_time(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return val

    def read_integer(
        self,
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> int:
        """Reads an ASN.1 INTEGER value.

        Args:
            tag: The tag to validate with, defaults to the INTEGER universal
                tag.
            header: Optional header from :func:`peek_header` to make the
                extraction more efficient.
            hint: A hint used in error messages to display what this step was
                used for.

        Returns:
            int: The int value.
        """
        val, consumed = _read_asn1_integer(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return val

    def read_object_identifier(
        self,
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> str:
        val, consumed = _read_asn1_object_identifier(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return val

    def read_octet_string(
        self,
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> bytes:
        """Reads an ASN.1 OCTET_STRING value.

        As this returns a bytes string, it is useful to extract the raw ASN.1
        value as long as the correct tag or header is provided.

        Args:
            tag: The tag to validate with, defaults to the OCTET_STRING
                universal tag (primitive).
            header: Optional header from :func:`peek_header` to make the
                extraction more efficient.
            hint: A hint used in error messages to display what this step was
                used for.

        Returns:
            bytes: The octet string bytes.
        """
        val, consumed = _read_asn1_octet_string(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return val.tobytes()

    def read_set(
        self,
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> ASN1Reader:
        """Reads an ASN.1 SET or SET_OF value.

        The returned reader can be used to then read the values inside the set.

        Args:
            tag: The tag to validate with, defaults to the SET/SET_OF universal
                tag.
            header: Optional header from :func:`peek_header` to make the
                extraction more efficient.
            hint: A hint used in error messages to display what this step was
                used for.

        Returns:
            ASN1Reader: The ASN.1 reader object that can be used to read the
                set elements.
        """
        new_view, consumed = _read_asn1_set(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return ASN1Reader(new_view)

    read_set_of = read_set

    def read_sequence(
        self,
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> ASN1Reader:
        """Reads an ASN.1 SEQUENCE or SEQUENCE_OF value.

        The returned reader can be used to then read the values inside the
        sequence.

        Args:
            tag: The tag to validate with, defaults to the SEQUENCE/SEQUENCE_OF
                universal tag.
            header: Optional header from :func:`peek_header` to make the
                extraction more efficient.
            hint: A hint used in error messages to display what this step was
                used for.

        Returns:
            ASN1Reader: The ASN.1 reader object that can be used to read the
                sequence elements.
        """
        new_view, consumed = _read_asn1_sequence(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return ASN1Reader(new_view)

    read_sequence_of = read_sequence

    def read_utf8_string(
        self,
        tag: t.Optional[ASN1Tag] = None,
        header: t.Optional[ASN1Header] = None,
        hint: t.Optional[str] = None,
    ) -> str:
        val, consumed = _read_asn1_utf8_string(
            self._view,
            tag=tag,
            header=header,
            hint=hint,
        )
        self._view = self._view[consumed:]

        return val


class ASN1Writer:
    """ASN.1 value writer.

    Class used to write ASN.1 data into an internal buffer. This data can then
    be retrieved using :func:`get_data`. It provides a nice helper to easily
    accumulate multiple values in one object.

    Args:
        tag: Optional tag to used when in a sequence/set writer.
        parent: The parent writer used when in a sequence/set writer.
    """

    def __init__(
        self,
        *,
        tag: t.Optional[ASN1Tag] = None,
        parent: t.Optional[ASN1Writer] = None,
    ) -> None:
        self._data = bytearray()
        self._tag = tag
        self._parent = parent

    def __enter__(self) -> ASN1Writer:
        return self

    def __exit__(
        self,
        exc_type: t.Optional[t.Type[BaseException]] = None,
        exc_val: t.Optional[BaseException] = None,
        exc_tb: t.Optional[TracebackType] = None,
    ) -> None:
        if not self._parent or not self._tag:
            return

        data = _pack_asn1(
            self._tag.tag_class,
            self._tag.is_constructed,
            self._tag.tag_number,
            self._data,
        )
        self._parent._data.extend(data)

    def push_sequence(
        self,
        tag: t.Optional[ASN1Tag] = None,
    ) -> ASN1Writer:
        """Get new writer for a SEQUENCE or SEQUENCE_OF value.

        Gets a new writer to start writing values inside a sequence or sequence
        of object. Make sure to wrap the writer in a with statement to ensure
        the sequence is closed and written back to the parent writer.

        Examples:
            .. code-block:: python

                with writer.push_sequence() as seq_writer:
                    seq_writer.write_octet_string(b"foo")

        Args:
            tag: Optional tag to mark the sequence/sequence_of with.

        Returns:
            ASN1Writer: The writer object that can be used to write the
            sequence elements.
        """
        if not tag:
            tag = ASN1Tag.universal_tag(TypeTagNumber.SEQUENCE, is_constructed=True)
        return ASN1Writer(tag=tag, parent=self)

    push_sequence_of = push_sequence

    def push_set(
        self,
        tag: t.Optional[ASN1Tag] = None,
    ) -> ASN1Writer:
        """Get new writer for a SET or SET_OF value.

        Gets a new writer to start writing values inside a set or set of
        object. Make sure to wrap the writer in a with statement to ensure
        the sequence is closed and written back to the parent writer.

        Examples:
            .. code-block:: python

                with writer.push_set() as seq_writer:
                    seq_writer.write_octet_string(b"foo")

        Args:
            tag: Optional tag to mark the sequence/sequence_of with.

        Returns:
            ASN1Writer: The writer object that can be used to write the
            set elements.
        """
        if not tag:
            tag = ASN1Tag.universal_tag(TypeTagNumber.SET, is_constructed=True)
        return ASN1Writer(tag=tag, parent=self)

    push_set_of = push_set

    def write_boolean(
        self,
        value: bool,
        tag: t.Optional[ASN1Tag] = None,
    ) -> None:
        """Write an ASN.1 BOOLEAN value.

        Writes a boolean value to the current writer.

        Args:
            value: The bool to write.
            tag: Optional tag to use with the value, defaults to the BOOLEAN
                universal tag.
        """
        self._data.extend(_pack_asn1_boolean(value, tag=tag))

    def write_enumerated(
        self,
        value: int,
        tag: t.Optional[ASN1Tag] = None,
    ) -> None:
        """Write an ASN.1 ENUMEATES value.

        Writes a enumerated value to the current writer.

        Args:
            value: The enumerated/int to write.
            tag: Optional tag to use with the value, defaults to the ENUMERATED
                universal tag.
        """
        self._data.extend(_pack_asn1_enumerated(value, tag=tag))

    def write_integer(
        self,
        value: int,
        tag: t.Optional[ASN1Tag] = None,
    ) -> None:
        """Write an ASN.1 INTEGER value.

        Writes an int value to the current writer.

        Args:
            value: The int to write.
            tag: Optional tag to use with the value, defaults to the INTEGER
                universal tag.
        """
        self._data.extend(_pack_asn1_integer(value, tag=tag))

    def write_octet_string(
        self,
        value: bytes,
        tag: t.Optional[ASN1Tag] = None,
    ) -> None:
        """Write an ASN.1 OCTET_STRING value.

        Writes a bytes string value to the current writer.

        Args:
            value: The bool to write.
            tag: Optional tag to use with the value, defaults to the
                OCTET_STRING universal tag.
        """
        self._data.extend(_pack_asn1_octet_string(value, tag=tag))

    def get_data(self) -> bytearray:
        """Gets the data written to the writer.

        This is used to get the final ASN.1 value after all the values have
        been written to it. It cannot be called on a child writer returned by
        push_sequence or push_set.

        Returns:
            bytearray: The data that has been written.
        """
        if self._parent or self._tag:
            raise TypeError("Cannot get_data() on child ASN1 writer")

        return self._data


def _pack_asn1(
    tag_class: TagClass,
    constructed: bool,
    tag_number: t.Union[TypeTagNumber, int],
    data: t.Union[bytes, bytearray, memoryview],
) -> bytes:
    """Pack the ASN.1 value into the ASN.1 bytes.

    Will pack the raw bytes into an ASN.1 Type Length Value (TLV) value. A TLV
    is in the form:

    | Identifier Octet(s) | Length Octet(s) | Data Octet(s) |

    Args:
        tag_class: The tag class of the data.
        constructed: Whether the data is constructed (True), i.e. contains 0,
            1, or more element encodings, or is primitive (False).
        tag_number: The type tag number if tag_class is universal else the
            explicit tag number of the TLV.
        b_data: The encoded value to pack into the ASN.1 TLV.

    Returns:
        bytes: The ASN.1 value as raw bytes.
    """
    b_asn1_data = bytearray()

    # ASN.1 Identifier octet is
    #
    # |             Octet 1             |  |              Octet 2              |
    # | 8 | 7 |  6  | 5 | 4 | 3 | 2 | 1 |  |   8   | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
    # | Class | P/C | Tag Number (0-30) |  | More  | Tag number                |
    #
    # If Tag Number is >= 31 the first 5 bits are 1 and the 2nd octet is used
    # to encode the length.
    if tag_class < 0 or tag_class > 3:
        raise ValueError("tag_class must be between 0 and 3")

    identifier_octets = tag_class << 6
    identifier_octets |= (1 if constructed else 0) << 5

    if tag_number < 31:
        identifier_octets |= tag_number
        b_asn1_data.append(identifier_octets)
    else:
        # Set the first 5 bits of the first octet to 1 and encode the tag
        # number in subsequent octets.
        identifier_octets |= 31
        b_asn1_data.append(identifier_octets)
        b_asn1_data.extend(_pack_asn1_octet_number(tag_number))

    # ASN.1 Length octet for DER encoding is always in the definite form. This
    # form packs the lengths in the following octet structure:
    #
    # |                       Octet 1                       |  |            Octet n            |
    # |     8     |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
    # | Long form | Short = length, Long = num octets       |  | Big endian length for long    |
    #
    # Basically if the length < 127 it's encoded in the first octet, otherwise
    # the first octet 7 bits indicates how many subsequent octets were used to
    # encode the length.
    length = len(data)
    if length < 128:
        b_asn1_data.append(length)
    else:
        length_octets = bytearray()
        while length:
            length_octets.append(length & 0b11111111)
            length >>= 8

        # Reverse the octets so the higher octets are first, add the initial
        # length octet with the MSB set and add them all to the main ASN.1 byte
        # array.
        length_octets.reverse()
        b_asn1_data.append(len(length_octets) | 0b10000000)
        b_asn1_data.extend(length_octets)

    return bytes(b_asn1_data) + bytes(data)


def _pack_asn1_boolean(
    value: bool,
    tag: t.Optional[ASN1Tag] = None,
) -> bytes:
    """Packs an int into an ASN.1 BOOLEAN byte value with optional universal tagging."""
    if not tag:
        tag = ASN1Tag.universal_tag(TypeTagNumber.BOOLEAN)

    return _pack_asn1(tag.tag_class, tag.is_constructed, tag.tag_number, b"\xFF" if value else b"\x00")


def _pack_asn1_enumerated(
    value: int,
    tag: t.Optional[ASN1Tag] = None,
) -> bytes:
    """Packs an int into an ASN.1 ENUMERATED byte value with optional universal tagging."""
    return _pack_asn1_integer(value, tag=tag or ASN1Tag.universal_tag(TypeTagNumber.ENUMERATED))


def _pack_asn1_integer(
    value: int,
    tag: t.Optional[ASN1Tag] = None,
) -> bytes:
    """Packs an int value into an ASN.1 INTEGER byte value with optional universal tagging."""
    if not tag:
        tag = ASN1Tag.universal_tag(TypeTagNumber.INTEGER)

    # Thanks to https://github.com/andrivet/python-asn1 for help with the negative value logic.
    is_negative = False
    limit = 0x7F
    if value < 0:
        value = -value
        is_negative = True
        limit = 0x80

    b_int = bytearray()
    while value > limit:
        val = value & 0xFF

        if is_negative:
            val = 0xFF - val

        b_int.append(val)
        value >>= 8

    b_int.append(((0xFF - value) if is_negative else value) & 0xFF)

    if is_negative:
        # The nocover is here because it's reporting no coverage for the no
        # enumerate branch. We don't care about that.
        for idx, val in enumerate(b_int):  # pragma: nocover
            if val < 0xFF:
                b_int[idx] += 1
                break

            b_int[idx] = 0

    if is_negative and b_int[-1] == 0x7F:  # Two's complement corner case
        b_int.append(0xFF)

    b_int.reverse()

    return _pack_asn1(tag.tag_class, tag.is_constructed, tag.tag_number, b_int)


def _pack_asn1_octet_string(
    b_data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
) -> bytes:
    """Packs an bytes value into an ASN.1 OCTET STRING byte value with optional universal tagging."""
    if not tag:
        tag = ASN1Tag.universal_tag(TypeTagNumber.OCTET_STRING)

    return _pack_asn1(tag.tag_class, tag.is_constructed, tag.tag_number, b_data)


def _read_asn1_header(
    data: t.Union[bytes, bytearray, memoryview],
) -> ASN1Header:
    """Reads the ASN.1 Tag and Length octets

    Reads the raw ASN.1 value to retrieve the tag and length values.

    Args:
      data: The raw bytes to read.

    Returns:
        ASN1Value: A tuple containing the tag and length information.
    """
    view = memoryview(data)

    if not view:
        raise NotEnougData()

    octet1 = struct.unpack("B", view[:1])[0]
    tag_class = TagClass((octet1 & 0b11000000) >> 6)
    constructed = bool(octet1 & 0b00100000)
    tag_number = octet1 & 0b00011111

    tag_octets = 1
    if tag_number == 31:
        tag_number, octet_count = _unpack_asn1_octet_number(view[1:])
        tag_octets += octet_count

    if tag_class == TagClass.UNIVERSAL:
        tag_number = TypeTagNumber(tag_number)

    view = view[tag_octets:]

    if not view:
        raise NotEnougData()

    length = struct.unpack("B", view[:1])[0]
    length_octets = 1

    if length == 0b10000000:
        # Indefinite length, the length is not known and will be marked by two
        # NULL octets known as end-of-content octets later in the stream. It is
        # not meant to be sent in LDAP so fail here.
        # https://www.rfc-editor.org/rfc/rfc4511#section-5.1
        raise ValueError("Received BER indefinite encoded value which is unsupported by LDAP messages")

    elif length & 0b10000000:
        # If the MSB is set then the length octet just contains the number of
        # octets that encodes the actual length.
        length_octets += length & 0b01111111
        length = 0

        for idx in range(1, length_octets):
            if len(view) < (idx + 1):
                raise NotEnougData()

            octet_val = struct.unpack("B", view[idx : idx + 1])[0]
            length += octet_val << (8 * (length_octets - 1 - idx))

    return ASN1Header(
        tag=ASN1Tag(
            tag_class=tag_class,
            tag_number=tag_number,
            is_constructed=constructed,
        ),
        tag_length=tag_octets + length_octets,
        length=length,
    )


def _read_asn1_boolean(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[bool, int]:
    """Unpacks an ASN.1 BOOLEAN value."""
    raw_bool, consumed = _validate_tag(
        data,
        tag,
        ASN1Tag.universal_tag(TypeTagNumber.BOOLEAN, False),
        header=header,
        hint=hint,
    )

    return raw_bool.tobytes().replace(b"\x00", b"") != b"", consumed


def _read_asn1_enumerated(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[int, int]:
    """Unpacks an ASN.1 ENUMERATED value."""
    if not tag:
        tag = header.tag if header else ASN1Tag.universal_tag(TypeTagNumber.ENUMERATED, False)
    return _read_asn1_integer(data, tag, header=header, hint=hint)


def _read_asn1_generalized_time(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[str, int]:
    """Unpacks an ASN.1 GENERALIZED_TIME value."""
    raw_time, consumed = _validate_tag(
        data,
        tag,
        ASN1Tag.universal_tag(TypeTagNumber.GENERALIZED_TIME, False),
        header=header,
        hint=hint,
    )
    return raw_time.tobytes().decode("utf-8"), consumed


def _read_asn1_integer(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[int, int]:
    """Unpacks an ASN.1 INTEGER value."""
    raw_int, consumed = _validate_tag(
        data,
        tag,
        ASN1Tag.universal_tag(TypeTagNumber.INTEGER, False),
        header=header,
        hint=hint,
    )
    b_int = bytearray(raw_int)

    is_negative = b_int[0] & 0b10000000
    if is_negative:
        # Get the two's compliment.
        for i in range(len(b_int)):
            b_int[i] = 0xFF - b_int[i]

        # Coverage is skipped because branch will not occur with no loop
        for i in range(len(b_int) - 1, -1, -1):  # pragma: nocover
            if b_int[i] == 0xFF:
                b_int[i - 1] += 1
                b_int[i] = 0
                break

            else:
                b_int[i] += 1
                break

    int_value = 0
    for val in b_int:
        int_value = (int_value << 8) | val

    if is_negative:
        int_value *= -1

    return int_value, consumed


def _read_asn1_object_identifier(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[str, int]:
    """Unpacks an ASN.1 OBJECT_IDENTIFIER value."""
    raw_oid, consumed = _validate_tag(
        data,
        tag,
        ASN1Tag.universal_tag(TypeTagNumber.OBJECT_IDENTIFIER, False),
        header=header,
        hint=hint,
    )

    first_element = struct.unpack("B", raw_oid[:1])[0]
    second_element = first_element % 40
    ids = [(first_element - second_element) // 40, second_element]

    idx = 1
    while idx != len(raw_oid):
        oid, octet_len = _unpack_asn1_octet_number(raw_oid[idx:])
        ids.append(oid)
        idx += octet_len

    return ".".join([str(i) for i in ids]), consumed


def _read_asn1_octet_string(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[memoryview, int]:
    """Unpacks an ASN.1 OCTET_STRING value."""
    return _validate_tag(
        data,
        tag,
        ASN1Tag.universal_tag(TypeTagNumber.OCTET_STRING, False),
        header=header,
        hint=hint,
    )


def _read_asn1_sequence(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[memoryview, int]:
    """Unpacks an ASN.1 SEQUENCE value."""
    return _validate_tag(
        data,
        tag,
        ASN1Tag.universal_tag(TypeTagNumber.SEQUENCE, True),
        header=header,
        hint=hint,
    )


def _read_asn1_set(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[memoryview, int]:
    """Unpacks an ASN.1 SET value."""
    return _validate_tag(
        data,
        tag,
        ASN1Tag.universal_tag(TypeTagNumber.SET, True),
        header=header,
        hint=hint,
    )


def _read_asn1_utf8_string(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[str, int]:
    """Unpacks an ASN.1 UTF8_STRING value."""
    raw_str, consumed = _validate_tag(
        data,
        tag,
        ASN1Tag.universal_tag(TypeTagNumber.UTF8_STRING, False),
        header=header,
        hint=hint,
    )
    return raw_str.tobytes().decode("utf-8"), consumed


def _validate_tag(
    data: t.Union[bytes, bytearray, memoryview],
    expected_tag: t.Optional[ASN1Tag],
    type_tag: ASN1Tag,
    header: t.Optional[ASN1Header] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[memoryview, int]:
    view = memoryview(data)

    if header:
        actual_tag, tag_length, data_length = header
    else:
        actual_tag, tag_length, data_length = _read_asn1_header(view)

    hint_str = f" for {hint}" if hint else ""

    if not expected_tag:
        expected_tag = header.tag if header else type_tag

    if actual_tag != expected_tag:
        raise ValueError(f"Expected tag {expected_tag}{hint_str} but got {actual_tag}")

    view = view[tag_length:]
    if len(view) < data_length:
        raise NotEnougData(f"Not enough data{hint_str}: expecting {data_length} but got {len(view)}")

    return view[:data_length], tag_length + data_length


def _unpack_asn1_octet_number(
    data: memoryview,
) -> t.Tuple[int, int]:
    """Unpacks an ASN.1 INTEGER value that can span across multiple octets."""
    i = 0
    idx = 0
    while True:
        if len(data) < (idx + 1):
            raise NotEnougData()

        element = struct.unpack("B", data[idx : idx + 1])[0]
        idx += 1

        i = (i << 7) + (element & 0b01111111)
        if not element & 0b10000000:
            break

    return i, idx  # int value and the number of octets used.


def _pack_asn1_octet_number(
    num: int,
) -> bytes:
    """Packs an int number into an ASN.1 integer value that spans multiple octets."""
    num_octets = bytearray()

    while num:
        # Get the 7 bit value of the number.
        octet_value = num & 0b01111111

        # Set the MSB if this isn't the first octet we are processing (overall last octet)
        if len(num_octets):
            octet_value |= 0b10000000

        num_octets.append(octet_value)

        # Shift the number by 7 bits as we've just processed them.
        num >>= 7

    # Finally we reverse the order so the higher octets are first.
    num_octets.reverse()

    return num_octets


__all__ = [
    "ASN1Reader",
    "ASN1Writer",
    "ASN1Header",
    "ASN1Tag",
    "NotEnougData",
    "TagClass",
    "TypeTagNumber",
]
