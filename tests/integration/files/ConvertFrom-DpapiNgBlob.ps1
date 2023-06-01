#Requires -Module Ctypes

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [byte[]]
    $InputObject
)

$ncrypt = New-CtypesLib ncrypt.dll

$outData = [IntPtr]::Zero
$descriptorHandle = [IntPtr]::Zero
try {
    $outDataLength = 0

    $res = $ncrypt.NCryptUnprotectSecret(
        [ref]$descriptorHandle,
        0x40, # NCRYPT_SILENT_FLAG,
        $ncrypt.MarshalAs($InputObject, 'LPArray'),
        $InputObject.Length,
        $null,
        $null,
        [ref]$outData,
        [ref]$outDataLength)
    if ($res) {
        throw [System.ComponentModel.Win32Exception]$res
    }

    $rawValue = [byte[]]::new($outDataLength)
    [System.Runtime.InteropServices.Marshal]::Copy($outData, $rawValue, 0, $rawValue.Length)
    $rawValue
}
finally {
    if ($outData -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($outData)
        $outData = [IntPtr]::Zero
    }
    if ($descriptorHandle -ne [IntPtr]::Zero) {
        $ncrypt.Returns([void]).NCryptCloseProtectionDescriptor($descriptorHandle)
        $descriptorHandle = [IntPtr]::Zero
    }
}