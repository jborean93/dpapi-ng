[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $Scenario
)

$scenarios = @{
    DH = @{
        KeyLength = 2048
        SecretParams = '0C0200004448504D0001000087A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A15973FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659'
        PublicKey = '444850420001000087A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A15973FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659535CC9DB0F3BE1D18BA5D691DCBD7ADFC2A3F331E8875264BDB99B71F0DD0715ED1002DFFDC00BEA4A252738BFD027B283C0A61C3BA7A060732B2DBEC520BCA23941810CBC555A4C69F45F35C05EE02E71E3ACB6ED5B9B55F0DC408E13640CDC58A04900E73018ADBD7D5840DD29CB6482AF75483C22AF35A48AD0D166FADED4C1C58F749CD130BDB4726938FC6A90E17726D75B2284592AA292B52A97807B80355705794340702333C9558EC671DD206D9C796BC26953D7F7261776E69A2DA8496E3AD04877D645571BBCCE655CD57C53BFE3406B457B807BB497B79C99D0766DD3D19B594E98D5B685302171A02313DA5BE5F5F6D1B98BC6B9BF5B68992C1C'
        PrivateKey = '8844C8622AF1CC0D2ACF6581CD4F03DBDA3C97C08E37C97CA6E8C30C0B4E27926C6726FF6EF74EFA6D7F9AF818564A73D511A661E37CB41D07098B0F4D0D5B80'
        ExpectedSecretAgreement = '2F3ED6CECAFBDF3E386240FCFB5B499310015243651BC97AEFF9EE23E760100E3A825814CCBD7B064339B9105512CEA22D6E9C0FEFBBDADCC26E01BD8F286BD9993F0068B3CFEF9113311BBAA7B37D05462E2B740259CC211E75260708706A98B3FB967C45109FDABF6589312490B6F03AA65F0E4C882317865C55708916D82B962912909F6ED6E85EDEB7CB2CC1AC8C812A390A23B4E2DB645D17BF7417BF9F176CE807366A46A5797E7F5828B64389ADAEDDED099A9BC634C037315D0389B008C5D3CB966AF458FC524F8C7FBF814DD93117979F5410952510BED6B5BA4A7DBCA10FFDC4B7A5709C223C9A1AF9C9B36BF92883333417A3606CC59A200B12D1'
        ExpectedSecret = 'CAF41BA47887FB04AC7B80B6FF1BD15C5135500372B889A143C3AAC7D695955E'
    }
    ECDH_P256 = @{
        KeyLength = 256
        SecretParams = ''
        PublicKey = '45434B31200000005AFBDDBB412E39B367302AEDF04A8F8D184D9801FA4A560BF35AB0FD83E5C93CB5EE98D8B938672442C1CFCDFAADADA31A014776F9B72C2CA9F06E5B6DDA2218'
        PrivateKey = 'B65D20E0916BE7C6A9F865826432C4F3B5347FAA07271D675C065EE2BA34AA13'
        ExpectedSecretAgreement = '98E13228F67F865CB9A699679F37C394BCA0DF718AF71C9F9E97B7108C16D74B'
        ExpectedSecret = '37208B86DC931C2F5FB4E5A0295B877D0AE98B8F4CE79F6B407B5926B519AF6C'
    }
    ECDH_P384 = @{
        KeyLength = 384
        SecretParams = ''
        PublicKey = '45434B3330000000519FB25DB5692BADEE44DE4044EC0F0AAF4BD86F9D3F1967031AD2E7B7A656EEE7E114EFFCF0D83E682C246F3E04119FED903CE810FC060F6DCA3E4901E20DFA5EE82AE9DCB237102892E8A2997BFF0CC9C755541F066E83550FD200B3D4B50E'
        PrivateKey = '1D94E9DE911B17981356E4464B691FDAB12AE822ECC152C2D786CD060CA32255ACE7B1EB0F3644AAE19AF5F75D03FFC3'
        ExpectedSecretAgreement = '2441392B082A8A8AD52BE6707517DA5CF19A629B4AF177B19FF03D13BF6CBA2D0A06A98259C16F6A3CDDD29EE50B72FC'
        ExpectedSecret = '8A10120B4DD74F21DA5C79917E993DBC5DE1A8346112A33300C8F30CCC77E5F1DEAD404BBDA472E6CB42D6A448872425'
    }
}

$pubKeyLength = $scenarios.$scenario.KeyLength
$secretParams = [System.Convert]::FromHexString($scenarios.$scenario.SecretParams)
$rawPubkey = [System.Convert]::FromHexString($scenarios.$scenario.PublicKey)
$rawPrivKey = [System.Convert]::FromHexString($scenarios.$scenario.PrivateKey)
$expectedSecretAgreement = [System.Convert]::FromHexString($scenarios.$scenario.ExpectedSecretAgreement)
$expectedSecret = [System.Convert]::FromHexString($scenarios.$scenario.ExpectedSecret)

ctypes_struct BCryptBufferDesc {
    [int]$Version
    [int]$BufferCount
    [IntPtr]$Buffers
}

ctypes_struct BCryptBuffer {
    [int]$BufferLength
    [int]$BufferType
    [IntPtr]$Buffer
}

$bcrypt = New-CtypesLib Bcrypt.dll
$ntdll = New-CtypesLib Ntdll.dll

$algo = [IntPtr]::Zero
$res = $bcrypt.CharSet("Unicode").BCryptOpenAlgorithmProvider(
    [ref]$algo,
    $bcrypt.MarshalAs($scenario, "LPWStr"),
    $null,
    0)
if ($res) {
    throw ("BCryptOpenAlgorithmProvider failed 0x{0:X8}" -f $res)
}

$pubKey = [IntPtr]::Zero
$privKey = [IntPtr]::Zero
$agreedSecret = [IntPtr]::Zero
$parameterList = [IntPtr]::Zero
$derivedKey = [IntPtr]::Zero
try {
    $res = $bcrypt.CharSet("Unicode").BCryptImportKeyPair(
        $algo,
        $null,
        $bcrypt.MarshalAs("PUBLICBLOB", "LPWStr"),
        [ref]$pubKey,
        $bcrypt.MarshalAs($rawPubKey, "LPArray"),
        $rawPubKey.Length,
        0)
    if ($res) {
        $res = $ntdll.RtlNtStatusToDosError($res)
        $msg = ([System.ComponentModel.Win32Exception]$res).Message
        throw ("BCryptImportKeyPair(PUBLICBLOB) failed 0x{0:X8}: {1}" -f $res, $msg)
    }

    $res = $bcrypt.BCryptGenerateKeyPair(
        $algo,
        [ref]$privKey,
        $pubKeyLength,
        0)
    if ($res) {
        $res = $ntdll.RtlNtStatusToDosError($res)
        $msg = ([System.ComponentModel.Win32Exception]$res).Message
        throw ("BCryptGenerateKeyPair failed 0x{0:X8}: {1}" -f $res, $msg)
    }

    if ($secretParams) {
        $res = $bcrypt.CharSet('Unicode').BCryptSetProperty(
            $privKey,
            $bcrypt.MarshalAs("SecretAgreementParam", "LPWStr"),
            $bcrypt.MarshalAs($secretParams, "LPArray"),
            $secretParams.Length,
            0)
        if ($res) {
            $res = $ntdll.RtlNtStatusToDosError($res)
            $msg = ([System.ComponentModel.Win32Exception]$res).Message
            throw ("BCryptSetProperty(SecretAgreementParam) failed 0x{0:X8}: {1}" -f $res, $msg)
        }
    }

    $res = $bcrypt.CharSet('Unicode').BCryptSetProperty(
        $privKey,
        $bcrypt.MarshalAs("PrivKeyVal", "LPWStr"),
        $bcrypt.MarshalAs($rawPrivKey, "LPArray"),
        $rawPrivKey.Length,
        0)
    if ($res) {
        $res = $ntdll.RtlNtStatusToDosError($res)
        $msg = ([System.ComponentModel.Win32Exception]$res).Message
        throw ("BCryptSetProperty(PrivKeyVal) failed 0x{0:X8}: {1}" -f $res, $msg)
    }

    $res = $bcrypt.BCryptFinalizeKeyPair(
        $privKey,
        0)
    if ($res) {
        $res = $ntdll.RtlNtStatusToDosError($res)
        $msg = ([System.ComponentModel.Win32Exception]$res).Message
        throw ("BCryptFinalizeKeyPair failed 0x{0:X8}: {1}" -f $res, $msg)
    }

    $res = $bcrypt.BCryptSecretAgreement(
        $privKey,
        $pubKey,
        [ref]$agreedSecret,
        0)
    if ($res) {
        $res = $ntdll.RtlNtStatusToDosError($res)
        $msg = ([System.ComponentModel.Win32Exception]$res).Message
        throw ("BCryptSecretAgreement failed 0x{0:X8}: {1}" -f $res, $msg)
    }

    $outLength = 0
    $res = $bcrypt.CharSet('Unicode').BCryptDeriveKey(
        $agreedSecret,
        $bcrypt.MarshalAs('TRUNCATE', 'LPWStr'),
        $null,
        $null,
        0,
        [ref]$outLength,
        0)
    if ($res) {
        $res = $ntdll.RtlNtStatusToDosError($res)
        $msg = ([System.ComponentModel.Win32Exception]$res).Message
        throw ("BCryptDeriveKey(TRUNCATE) (GetLength) failed 0x{0:X8}: {1}" -f $res, $msg)
    }

    $sharedSecretPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($outLength)
    try {
        $res = $bcrypt.CharSet('Unicode').BCryptDeriveKey(
            $agreedSecret,
            $bcrypt.MarshalAs('TRUNCATE', 'LPWStr'),
            $null,
            $sharedSecretPtr,
            $outLength,
            [ref]$outLength,
            0)
        if ($res) {
            throw ("BCryptDeriveKey(TRUNCATE) failed 0x{0:X8}" -f $res)
        }

        $secretAgreement = [byte[]]::new($outLength)
        [System.Runtime.InteropServices.Marshal]::Copy($sharedSecretPtr, $secretAgreement, 0, $secretAgreement.Length)

        # Windows returns this as little endian but we are comparing the big
        # endian value.
        [Array]::Reverse($secretAgreement)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($sharedSecretPtr)
    }
    "Expected Secret Agreement: $([System.Convert]::ToHexString($expectedSecretAgreement))"
    "Actual Secret Agreement  : $([System.Convert]::ToHexString($secretAgreement))"

    $algoId = [System.Convert]::FromHexString('5300480041003500310032000000')
    $partyUI = [System.Convert]::FromHexString('4B004400530020007000750062006C006900630020006B00650079000000')
    $partyVI = [System.Convert]::FromHexString('4B0044005300200073006500720076006900630065000000')
    $bufferDescLength = [System.Runtime.InteropServices.Marshal]::SizeOf([type][BCryptBufferDesc])
    $bufferLength = [System.Runtime.InteropServices.Marshal]::SizeOf([type][BCryptBuffer])
    $buffersLength = $bufferLength * 3
    $parameterList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(
        $bufferDescLength +
        $buffersLength +
        $algoId.Length +
        $partyUI.Length +
        $partyVI.Length
    )

    $bufferPtr = [IntPtr]::Add($parameterList, $bufferDescLength)
    $dataPtr = [IntPtr]::Add($bufferPtr, $buffersLength)

    $bufferDesc = [BCryptBufferDesc]@{
        Version = 0
        BufferCount = 3
        Buffers = $bufferPtr
    }
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($bufferDesc, $parameterList, $false)

    $algoIdBuffer = [BCryptBuffer]@{
        BufferLength = $algoId.Length
        BufferType = 8  #  KDF_ALGORITHMID
        Buffer = $dataPtr
    }
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($algoIdBuffer, $bufferPtr, $false)
    [System.Runtime.InteropServices.Marshal]::Copy($algoId, 0, $dataPtr, $algoId.Length)
    $bufferPtr = [IntPtr]::Add($bufferPtr, $bufferLength)
    $dataPtr = [IntPtr]::Add($dataPtr, $algoId.Length)

    $partyUIBuffer = [BCryptBuffer]@{
        BufferLength = $partyUI.Length
        BufferType = 9  # KDF_PARTYUINFO
        Buffer = $dataPtr
    }
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($partyUIBuffer, $bufferPtr, $false)
    [System.Runtime.InteropServices.Marshal]::Copy($partyUI, 0, $dataPtr, $partyUI.Length)
    $bufferPtr = [IntPtr]::Add($bufferPtr, $bufferLength)
    $dataPtr = [IntPtr]::Add($dataPtr, $partyUI.Length)

    $partyVIBuffer = [BCryptBuffer]@{
        BufferLength = $partyVI.Length
        BufferType = 10  # KDF_PARTYVINFO
        Buffer = $dataPtr
    }
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($partyVIBuffer, $bufferPtr, $false)
    [System.Runtime.InteropServices.Marshal]::Copy($partyVI, 0, $dataPtr, $partyVI.Length)

    $res = $bcrypt.CharSet('Unicode').BCryptDeriveKey(
        $agreedSecret,
        $bcrypt.MarshalAs('SP800_56A_CONCAT', 'LPWStr'),
        $parameterList,
        $null,
        $null,
        [ref]$outLength,
        0)
    if ($res) {
        $res = $ntdll.RtlNtStatusToDosError($res)
        $msg = ([System.ComponentModel.Win32Exception]$res).Message
        throw ("BCryptDeriveKey(SP800_56A_CONCAT) (GetLength) failed 0x{0:X8}: {1}" -f $res, $msg)
    }

    $derivedKey = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($outLength)
    $res = $bcrypt.CharSet('Unicode').BCryptDeriveKey(
        $agreedSecret,
        $bcrypt.MarshalAs('SP800_56A_CONCAT', 'LPWStr'),
        $parameterList,
        $derivedKey,
        $outLength,
        [ref]$outLength,
        0)
    if ($res) {
        $res = $ntdll.RtlNtStatusToDosError($res)
        $msg = ([System.ComponentModel.Win32Exception]$res).Message
        throw ("BCryptDeriveKey(SP800_56A_CONCAT) failed 0x{0:X8}: {1}" -f $res, $msg)
    }

    $secret = [byte[]]::new($outLength)
    [System.Runtime.InteropServices.Marshal]::Copy($derivedKey, $secret, 0, $secret.Length)
}
finally {
    if ($pubKey -ne [IntPtr]::Zero) {
        $bcrypt.BCryptDestroyKey[void]($pubKey)
    }
    if ($privKey -ne [IntPtr]::Zero) {
        $bcrypt.BCryptDestroyKey[void]($privKey)
    }
    if ($agreedSecret -ne [IntPtr]::Zero) {
        $bcrypt.BCryptDestroyKey[void]($agreedSecret)
    }
    if ($parameterList -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($parameterList)
    }
    if ($derivedKey -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($derivedKey)
    }
}

"Expected Secret: $([System.Convert]::ToHexString($expectedSecret))"
"Actual Secret  : $([System.Convert]::ToHexString($secret))"
