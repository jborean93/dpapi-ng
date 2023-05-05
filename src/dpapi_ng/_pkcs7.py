# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from ._asn1 import ASN1Header, ASN1Reader, ASN1Tag, TagClass, TypeTagNumber


@dataclasses.dataclass
class ContentInfo:
    content_type: str
    content: bytes

    # https://www.rfc-editor.org/rfc/rfc5652#section-3
    #   ContentInfo ::= SEQUENCE {
    #     contentType ContentType,
    #     content [0] EXPLICIT ANY DEFINED BY contentType }

    #   ContentType ::= OBJECT IDENTIFIER

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        header: t.Optional[ASN1Header] = None,
    ) -> ContentInfo:
        reader = ASN1Reader(data).read_sequence(header=header)
        content_type = reader.read_object_identifier(
            hint="ContentInfo.contentType",
        )

        content_tag = ASN1Tag(
            tag_class=TagClass.CONTEXT_SPECIFIC,
            tag_number=0,
            is_constructed=True,
        )
        content = reader.read_octet_string(
            tag=content_tag,
            hint="ContentInfo.content",
        )

        return ContentInfo(content_type, content)


@dataclasses.dataclass
class EnvelopedData:
    content_type = "1.2.840.113549.1.7.3"

    version: int
    recipient_infos: t.List[RecipientInfo]
    encrypted_content_info: EncryptedContentInfo

    # https://www.rfc-editor.org/rfc/rfc5652#section-6.1
    #   EnvelopedData ::= SEQUENCE {
    #     version CMSVersion,
    #     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
    #     recipientInfos RecipientInfos,
    #     encryptedContentInfo EncryptedContentInfo,
    #     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

    #   OriginatorInfo ::= SEQUENCE {
    #     certs [0] IMPLICIT CertificateSet OPTIONAL,
    #     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }

    #   RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

    #   EncryptedContentInfo ::= SEQUENCE {
    #     contentType ContentType,
    #     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    #     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

    #   EncryptedContent ::= OCTET STRING

    #   UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EnvelopedData:
        reader = ASN1Reader(data).read_sequence()

        version = reader.read_integer(hint="EnvelopedData.version")
        if version != 2:
            raise NotImplementedError("Cannot unpack EnvelopedData that is not version 2")

        recipient_infos: t.List[RecipientInfo] = []
        recipient_infos_reader = reader.read_set_of(hint="EnvelopedData.recipientInfos")
        while recipient_infos_reader:
            info = RecipientInfo.unpack(recipient_infos_reader)
            recipient_infos.append(info)

        enc_content = EncryptedContentInfo.unpack(reader)

        return EnvelopedData(
            version=version,
            recipient_infos=recipient_infos,
            encrypted_content_info=enc_content,
        )


@dataclasses.dataclass
class RecipientInfo:
    choice: int

    # https://www.rfc-editor.org/rfc/rfc5652#section-6.2
    # RecipientInfo ::= CHOICE {
    #     ktri KeyTransRecipientInfo,
    #     kari [1] KeyAgreeRecipientInfo,
    #     kekri [2] KEKRecipientInfo,
    #     pwri [3] PasswordRecipientinfo,
    #     ori [4] OtherRecipientInfo }

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
    ) -> RecipientInfo:
        header = reader.peek_header()
        tag = header.tag

        if tag.tag_class == TagClass.CONTEXT_SPECIFIC and tag.tag_number == 2:
            return KEKRecipientInfo.unpack(reader, header=header)

        raise NotImplementedError(f"Unimplemented RecipientInfo choice {tag}")


@dataclasses.dataclass
class KEKRecipientInfo(RecipientInfo):
    choice: int = dataclasses.field(init=False, repr=False, default=2)

    version: int
    kekid: KEKIdentifier
    key_encryption_algorithm: AlgorithmIdentifier
    encrypted_key: bytes

    # https://www.rfc-editor.org/rfc/rfc5652#section-6.2.3
    # KEKRecipientInfo ::= SEQUENCE {
    #     version CMSVersion,  -- always set to 4
    #     kekid KEKIdentifier,
    #     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    #     encryptedKey EncryptedKey }

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        header: t.Optional[ASN1Header] = None,
    ) -> KEKRecipientInfo:
        reader = reader.read_sequence(header=header)

        version = reader.read_integer(hint="KEKRecipientInfo.version")
        kekid = KEKIdentifier.unpack(reader)
        key_encryption_algorithm = AlgorithmIdentifier.unpack(reader)
        encrypted_key = reader.read_octet_string(hint="KEKRecipientInfo.encryptedKey")

        return KEKRecipientInfo(
            version=version,
            kekid=kekid,
            key_encryption_algorithm=key_encryption_algorithm,
            encrypted_key=encrypted_key,
        )


@dataclasses.dataclass
class KEKIdentifier:
    key_identifier: bytes
    date: t.Optional[str] = None
    other: t.Optional[OtherKeyAttribute] = None

    # https://www.rfc-editor.org/rfc/rfc5652#section-6.2.3
    # KEKIdentifier ::= SEQUENCE {
    #     keyIdentifier OCTET STRING,
    #     date GeneralizedTime OPTIONAL,
    #     other OtherKeyAttribute OPTIONAL }

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
    ) -> KEKIdentifier:
        reader = reader.read_sequence()

        key_identifier = reader.read_octet_string(hint="KEKIdentifier.keyIdentifier")
        header = reader.peek_header()

        date = None
        if header.tag.tag_class == TagClass.UNIVERSAL and header.tag.tag_number == TypeTagNumber.GENERALIZED_TIME:
            date = reader.read_generalized_time(header=header, hint="KEKIdentifier.date")
            header = reader.peek_header()

        other = None
        if header.tag.tag_class == TagClass.UNIVERSAL and header.tag.tag_number == TypeTagNumber.SEQUENCE:
            other = OtherKeyAttribute.unpack(reader, header=header)

        return KEKIdentifier(
            key_identifier=key_identifier,
            date=date,
            other=other,
        )


@dataclasses.dataclass
class OtherKeyAttribute:
    key_attr_id: str
    key_attr: t.Optional[bytes]

    # https://www.rfc-editor.org/rfc/rfc5652#section-10.2.7
    # OtherKeyAttribute ::= SEQUENCE {
    #     keyAttrId OBJECT IDENTIFIER,
    #     keyAttr ANY DEFINED BY keyAttrId OPTIONAL }

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        header: t.Optional[ASN1Header] = None,
    ) -> OtherKeyAttribute:
        reader = reader.read_sequence(header=header)

        key_attr_id = reader.read_object_identifier(hint="OtherKeyAttribute.keyAttrId")
        key_attr = None
        if reader:
            key_attr = reader.get_remaining_data()

        return OtherKeyAttribute(
            key_attr_id=key_attr_id,
            key_attr=key_attr,
        )


@dataclasses.dataclass
class EncryptedContentInfo:
    content_type: str
    algorithm: AlgorithmIdentifier
    content: t.Optional[bytes]

    # EncryptedContentInfo ::= SEQUENCE {
    #     contentType ContentType,
    #     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    #     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

    # ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
    ) -> EncryptedContentInfo:
        reader = reader.read_sequence()

        content_type = reader.read_object_identifier(hint="EncryptedContentInfo.contentType")
        content_encryption_algorithm = AlgorithmIdentifier.unpack(reader)
        enc_content = None
        if reader:
            enc_tag = ASN1Tag(
                tag_class=TagClass.CONTEXT_SPECIFIC,
                tag_number=0,
                is_constructed=False,
            )
            enc_content = reader.read_octet_string(
                enc_tag,
                hint="EncryptedContentInfo.encryptedContent",
            )

        return EncryptedContentInfo(
            content_type=content_type,
            algorithm=content_encryption_algorithm,
            content=enc_content,
        )


@dataclasses.dataclass
class AlgorithmIdentifier:
    algorithm: str
    parameters: t.Optional[bytes] = None

    # AlgorithmIdentifier ::= SEQUENCE {
    #   algorithm       OBJECT IDENTIFIER,
    #   parameters      ANY DEFINED BY algorithm OPTIONAL
    # }

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
    ) -> AlgorithmIdentifier:
        reader = reader.read_sequence()

        algorithm = reader.read_object_identifier()
        parameters = None
        if reader:
            parameters = reader.get_remaining_data()

        return AlgorithmIdentifier(
            algorithm=algorithm,
            parameters=parameters,
        )


@dataclasses.dataclass
class NCryptProtectionDescriptor:
    content_type: str
    type: str
    value: str

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> NCryptProtectionDescriptor:
        reader = ASN1Reader(data).read_sequence()
        content_type = reader.read_object_identifier()

        reader = reader.read_sequence().read_sequence().read_sequence()
        value_type = reader.read_utf8_string()
        value = reader.read_utf8_string()

        return NCryptProtectionDescriptor(
            content_type=content_type,
            type=value_type,
            value=value,
        )
