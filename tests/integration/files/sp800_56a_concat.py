import base64
import dataclasses
import hashlib
import sys
import typing as t

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash


@dataclasses.dataclass(frozen=True)
class FFCDHKey:
    # MS-GKDI 2.2.3.1 FFC DH Key:
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/f8770f01-036d-4bf6-a4cf-1bd0e3913404

    magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x44\x48\x50\x42")
    key_length: int
    field_order: int
    generator: int
    public_key: int

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> "FFCDHKey":
        view = memoryview(data)

        if view[:4].tobytes() != cls.magic:
            raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

        key_length = int.from_bytes(view[4:8], byteorder="little")

        field_order = view[8 : 8 + key_length].tobytes()
        view = view[8 + key_length :]

        generator = view[:key_length].tobytes()
        view = view[key_length:]

        public_key = view[:key_length].tobytes()

        return FFCDHKey(
            key_length=key_length,
            field_order=int.from_bytes(field_order, byteorder="big"),
            generator=int.from_bytes(generator, byteorder="big"),
            public_key=int.from_bytes(public_key, byteorder="big"),
        )


@dataclasses.dataclass(frozen=True)
class ECDHKey:
    # MS-GKDI 2.2.3.2 ECDH Key:
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/24876a37-9a92-4187-9052-222bb6f85d4a

    curve_name: str
    key_length: int
    x: int
    y: int

    @property
    def curve_and_hash(self) -> tuple[ec.EllipticCurve, hashes.HashAlgorithm]:
        return {
            "P256": (ec.SECP256R1(), hashes.SHA256()),
            "P384": (ec.SECP384R1(), hashes.SHA384()),
            "P521": (ec.SECP521R1(), hashes.SHA512()),
        }[self.curve_name]

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> "ECDHKey":
        view = memoryview(data)

        curve_id = int.from_bytes(view[:4], byteorder="little")
        curve = {
            0x314B4345: "P256",
            0x334B4345: "P384",
            0x354B4345: "P521",
        }.get(curve_id, None)
        if not curve:
            raise ValueError(f"Failed to unpack {cls.__name__} with unknown curve 0x{curve_id:08X}")

        length = int.from_bytes(view[4:8], byteorder="little")

        x = view[8 : 8 + length].tobytes()
        view = view[8 + length :]

        y = view[:length].tobytes()

        return ECDHKey(
            curve_name=curve,
            key_length=length,
            x=int.from_bytes(x, byteorder="big"),
            y=int.from_bytes(y, byteorder="big"),
        )


scenarios = {
    "DH": {
        "KeyLength": 2048,
        "SecretParams": "0C0200004448504D0001000087A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A15973FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659",
        "PublicKey": "444850420001000087A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A15973FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659535CC9DB0F3BE1D18BA5D691DCBD7ADFC2A3F331E8875264BDB99B71F0DD0715ED1002DFFDC00BEA4A252738BFD027B283C0A61C3BA7A060732B2DBEC520BCA23941810CBC555A4C69F45F35C05EE02E71E3ACB6ED5B9B55F0DC408E13640CDC58A04900E73018ADBD7D5840DD29CB6482AF75483C22AF35A48AD0D166FADED4C1C58F749CD130BDB4726938FC6A90E17726D75B2284592AA292B52A97807B80355705794340702333C9558EC671DD206D9C796BC26953D7F7261776E69A2DA8496E3AD04877D645571BBCCE655CD57C53BFE3406B457B807BB497B79C99D0766DD3D19B594E98D5B685302171A02313DA5BE5F5F6D1B98BC6B9BF5B68992C1C",
        "PrivateKey": "8844C8622AF1CC0D2ACF6581CD4F03DBDA3C97C08E37C97CA6E8C30C0B4E27926C6726FF6EF74EFA6D7F9AF818564A73D511A661E37CB41D07098B0F4D0D5B80",
        "ExpectedSecretAgreement": "2F3ED6CECAFBDF3E386240FCFB5B499310015243651BC97AEFF9EE23E760100E3A825814CCBD7B064339B9105512CEA22D6E9C0FEFBBDADCC26E01BD8F286BD9993F0068B3CFEF9113311BBAA7B37D05462E2B740259CC211E75260708706A98B3FB967C45109FDABF6589312490B6F03AA65F0E4C882317865C55708916D82B962912909F6ED6E85EDEB7CB2CC1AC8C812A390A23B4E2DB645D17BF7417BF9F176CE807366A46A5797E7F5828B64389ADAEDDED099A9BC634C037315D0389B008C5D3CB966AF458FC524F8C7FBF814DD93117979F5410952510BED6B5BA4A7DBCA10FFDC4B7A5709C223C9A1AF9C9B36BF92883333417A3606CC59A200B12D1",
        "ExpectedSecret": "CAF41BA47887FB04AC7B80B6FF1BD15C5135500372B889A143C3AAC7D695955E",
    },
    "ECDH_P256": {
        "KeyLength": 256,
        "SecretParams": "",
        "PublicKey": "45434B31200000005AFBDDBB412E39B367302AEDF04A8F8D184D9801FA4A560BF35AB0FD83E5C93CB5EE98D8B938672442C1CFCDFAADADA31A014776F9B72C2CA9F06E5B6DDA2218",
        "PrivateKey": "B65D20E0916BE7C6A9F865826432C4F3B5347FAA07271D675C065EE2BA34AA13",
        "ExpectedSecretAgreement": "98E13228F67F865CB9A699679F37C394BCA0DF718AF71C9F9E97B7108C16D74B",
        "ExpectedSecret": "37208B86DC931C2F5FB4E5A0295B877D0AE98B8F4CE79F6B407B5926B519AF6C",
    },
    "ECDH_P384": {
        "KeyLength": 384,
        "SecretParams": "",
        "PublicKey": "45434B3330000000519FB25DB5692BADEE44DE4044EC0F0AAF4BD86F9D3F1967031AD2E7B7A656EEE7E114EFFCF0D83E682C246F3E04119FED903CE810FC060F6DCA3E4901E20DFA5EE82AE9DCB237102892E8A2997BFF0CC9C755541F066E83550FD200B3D4B50E",
        "PrivateKey": "1D94E9DE911B17981356E4464B691FDAB12AE822ECC152C2D786CD060CA32255ACE7B1EB0F3644AAE19AF5F75D03FFC3",
        "ExpectedSecretAgreement": "2441392B082A8A8AD52BE6707517DA5CF19A629B4AF177B19FF03D13BF6CBA2D0A06A98259C16F6A3CDDD29EE50B72FC",
        "ExpectedSecret": "8A10120B4DD74F21DA5C79917E993DBC5DE1A8346112A33300C8F30CCC77E5F1DEAD404BBDA472E6CB42D6A448872425",
    },
}

scenario = sys.argv[1]
key_length = scenarios[scenario]["KeyLength"]
secret_params = base64.b16decode(str(scenarios[scenario]["SecretParams"]))
public_key = base64.b16decode(str(scenarios[scenario]["PublicKey"]))
private_key = base64.b16decode(str(scenarios[scenario]["PrivateKey"]))
expected_secret_agreement = base64.b16decode(str(scenarios[scenario]["ExpectedSecretAgreement"]))
expected_secret = base64.b16decode(str(scenarios[scenario]["ExpectedSecret"]))

secret_hash_algorithm: hashes.HashAlgorithm
if scenario == "DH":
    dh_pub_key = FFCDHKey.unpack(public_key)
    shared_secret_int = pow(
        dh_pub_key.public_key,
        int.from_bytes(private_key, byteorder="big"),
        dh_pub_key.field_order,
    )
    shared_secret = shared_secret_int.to_bytes(dh_pub_key.key_length, byteorder="big")
    secret_hash_algorithm = hashes.SHA256()

else:
    ecdh_pub_key_info = ECDHKey.unpack(public_key)
    curve, secret_hash_algorithm = ecdh_pub_key_info.curve_and_hash

    ecdh_pub_key = ec.EllipticCurvePublicNumbers(ecdh_pub_key_info.x, ecdh_pub_key_info.y, curve).public_key()
    ecdh_private = ec.derive_private_key(
        int.from_bytes(private_key, byteorder="big"),
        curve,
    )
    shared_secret = ecdh_private.exchange(ec.ECDH(), ecdh_pub_key)


shared_secret1 = hashlib.sha256(shared_secret).digest()
print(f"Actual Secret Agreement  : {base64.b16encode(shared_secret).decode()}")
print(f"Expected Secret Agreement: {base64.b16encode(expected_secret_agreement).decode()}")

algorithm_id = "SHA512\0"
party_uinfo = "KDS public key\0"
party_vinfo = "KDS service\0"

otherinfo = f"{algorithm_id}{party_uinfo}{party_vinfo}".encode("utf-16-le")
actual = ConcatKDFHash(
    secret_hash_algorithm,
    length=secret_hash_algorithm.digest_size,
    otherinfo=otherinfo,
).derive(shared_secret)

print(f"Actual Secret  : {base64.b16encode(actual).decode()}")
print(f"Expected Secret: {base64.b16encode(expected_secret).decode()}")
