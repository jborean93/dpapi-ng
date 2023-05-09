#Requires -Module Ctypes

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [byte[]]
    $InputObject,

    [Parameter()]
    [string]
    $ProtectionDescriptor
)

$ncrypt = New-CtypesLib ncrypt.dll

if (-not $ProtectionDescriptor) {
    $ProtectionDescriptor = "SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
}

$descriptor = [IntPtr]::Zero
$res = $ncrypt.NCryptCreateProtectionDescriptor(
    $ncrypt.MarshalAs($ProtectionDescriptor, "LPWStr"),
    0,
    [ref]$descriptor)
if ($res) {
    throw [System.ComponentModel.Win32Exception]$res
}

$blob = [IntPtr]::Zero
$blobLength = 0
$res = $ncrypt.NCryptProtectSecret(
    $descriptor,
    0x40, # NCRYPT_SILENT_FLAG
    $ncrypt.MarshalAs($InputObject, 'LPArray'),
    $InputObject.Length,
    $null,
    $null,
    [ref]$blob,
    [ref]$blobLength)
if ($res) {
    throw [System.ComponentModel.Win32Exception]$res
}

try {
    $encBlob = [byte[]]::new($blobLength)
    [System.Runtime.InteropServices.Marshal]::Copy($blob, $encBlob, 0, $encBlob.Length)
    $encBlob
}
finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($blob)
}
