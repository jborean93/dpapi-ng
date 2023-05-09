[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet("SHA1", "SHA256", "SHA384", "SHA512")]
    [string]
    $KdfHashAlgorithm = "SHA512",

    [Parameter()]
    [ValidateSet("DH", "ECDH_P256", "ECDH_P384")]
    [string]
    $SecretAgreementAlgorithm = "DH"
)

$ErrorActionPreference = 'Stop'

$kdfHashName = [System.Text.Encoding]::Unicode.GetBytes($KdfHashAlgorithm)

$kdsParams = @{
    KdfParameters = [byte[]]@(
        @(0, 0, 0, 0, 1, 0, 0, 0)
        [System.BitConverter]::GetBytes(($kdfHashName.Length + 2))
        @(0, 0, 0, 0)
        $kdfHashName
        @(0, 0)
    )
}

$kdsParams.SecretAgreementAlgorithm = $SecretAgreementAlgorithm
if ($SecretAgreementAlgorithm -eq "DH") {
    $keyLength = 256
    $fieldOrder = [System.Numerics.BigInteger]::Parse("17125458317614137930196041979257577826408832324037508573393292981642667139747621778802438775238728592968344613589379932348475613503476932163166973813218698343816463289144185362912602522540494983090531497232965829536524507269848825658311420299335922295709743267508322525966773950394919257576842038771632742044142471053509850123605883815857162666917775193496157372656195558305727009891276006514000409365877218171388319923896309377791762590614311849642961380224851940460421710449368927252974870395873936387909672274883295377481008150475878590270591798350563488168080923804611822387520198054002990623911454389104774092183").ToByteArray($true, $true)
    $generator = [System.Numerics.BigInteger]::Parse("8041367327046189302693984665026706374844608289874374425728797669509435881459140662650215832833471328470334064628508692231999401840332046192569287351991689963279656892562484773278584208040987631569628520464069532361274047374444344996651832979378318849943741662110395995778429270819222431610927356005913836932462099770076239554042855287138026806960470277326229482818003962004453764400995790974042663675692120758726145869061236443893509136147942414445551848162391468541444355707785697825741856849161233887307017428371823608125699892904960841221593344499088996021883972185241854777608212592397013510086894908468466292313").ToByteArray($true, $true)

    $kdsParams.SecretAgreementParameters = [byte[]]@(
        [System.BitConverter]::GetBytes(12 + $fieldOrder.Length + $generator.Length)
        @(0x44, 0x48, 0x50, 0x4D)
        [System.BitConverter]::GetBytes($keyLength)
        $fieldOrder
        $generator
    )
}
else {
    # ECDH_P521 is also meant to work but I keep on getting errors setting it
    $kdsParams.SecretAgreementAlgorithm = $SecretAgreementAlgorithm
    $kdsParams.SecretAgreementParameters = $null
    $kdsParams.SecretAgreementPublicKeyLength = $kdsParams.SecretAgreementPrivateKeyLength = switch ($SecretAgreementAlgorithm) {
        ECDH_P256 { 256 }
        ECDH_P384 { 384 }
    }
}
$null = Set-KdsConfiguration @kdsParams

$newKey = Add-KdsRootKey -EffectiveImmediately
$cryptoKeysPath = "$env:LOCALAPPDATA\Microsoft\Crypto\KdsKey"
if (Test-Path -LiteralPath $cryptoKeysPath) {
    Get-ChildItem -LiteralPath $cryptoKeysPath | Remove-Item -Force -Recurse
}
Restart-Service -Name KdsSvc

$configurationContext = (Get-ADRootDSE).configurationNamingContext
$kdsBase = "CN=Group Key Distribution Service,CN=Services,$configurationContext"
$getParams = @{
    LDAPFilter = "(&(cn=$($newKey.Guid))(objectClass=msKds-ProvRootKey))"
    SearchBase = "CN=Master Root Keys,$kdsBase"
    SearchScope = 'OneLevel'
    Properties = @(
        'cn'
        'msKds-KDFAlgorithmID'
        'msKds-KDFParam'
        'msKds-SecretAgreementAlgorithmID'
        'msKds-SecretAgreementParam'
        'msKds-PrivateKeyLength'
        'msKds-PublicKeyLength'
        'msKds-RootKeyData'
    )
}
Get-ADObject @getParams | ForEach-Object {
    $secretParams = if ($_.'msKds-SecretAgreementParam') {
        $_.'msKds-SecretAgreementParam'
    }
    else {
        , [byte[]]::new(0)
    }
    [PSCustomObject]@{
        Version = 1
        RootKeyId = [Guid]::new($_.cn)
        KdfAlgorithm = $_.'msKds-KDFAlgorithmID'
        KdfParameters = [System.Convert]::ToHexString($_.'msKds-KDFParam')
        SecretAgreementAlgorithm = $_.'msKds-SecretAgreementAlgorithmID'
        SecretAgreementParameters = [System.Convert]::ToHexString($secretParams)
        PrivateKeyLength = $_.'msKds-PrivateKeyLength'
        PublicKeyLength = $_.'msKds-PublicKeyLength'
        RootKeyData = [System.Convert]::ToHexString($_.'msKds-RootKeyData')
    }
} | ConvertTo-Json
