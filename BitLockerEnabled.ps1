<#
	Created By - Collin Johnson
	Created On - 
	Modified On - Apr 14 2021

.SYNOPSIS
    This provisions an endpoint to prepare it for BitLocker
.DESCRIPTION
    This script checks if it has a BitLocker enabled drive, but if it's compatible it provisions a BitLocker drive.
    It then checks to see if it has received BitLocker settings via GPO, if not, it manually sets them.
    It then attempts to begin encrypting the drive using BitLocker with TPM as the only authenticator - AES256 encryption.
    It then checks for all BitLocker recovery keys & attempts to back up to a Domain Controller.
.NOTES
    TPM is a requirement.
    BitLocker will attempt to store all keys on any BitLocker enabled drive in Active Directory
#>

$TPMNotEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | where {$_.IsEnabled_InitialValue -eq $false} -ErrorAction SilentlyContinue
$TPMEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | where {$_.IsEnabled_InitialValue -eq $true} -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
$BitLockerDecrypted = Get-BitLockerVolume -MountPoint $env:SystemDrive | where {$_.VolumeStatus -eq "FullyDecrypted"} -ErrorAction SilentlyContinue
$BitLockerVolumeSecure = Get-BitlockerVolume | Where-Object{$_.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}} -ErrorAction SilentlyContinue


<# If the TPM is not Enabled, Enable it.  Disabled for now as it requires user intervention on reboot. #>
<# 

if($TPMNotEnabled){

    Initialize-TPM -AllowClear -AllowPhysicalPresence -ErrorAction SilentlyContinue

}


#>


<# If TPM is enabled and the BitLocker partition is not provisioned, then provision the Bitlocker Partition by shrinking the system drive#>
IF ($TPMEnabled -and !$BitLockerReadyDrive) {

    Get-Service -Name defragsvc -ErrorAction SilentlyContinue | Set-SErvice -Status Running -ErrorAction SilentlyContinue

    BdeHdCfg -target $env:SystemDrive shrink -size 300 -quiet

}

<# Checks to see if Bitlocker Registry Keys have been created, if it does not, create with settings.  Commented out sections are other potential settings.#>

$BitLockerRegLoc = 'HKLM:\SOFTWARE\Policies\Microsoft'

IF (Test-Path "$BitLockerRegLoc\FVE") {

    Write-Verbose '$BitLockerRegLoc\FVE Key Already Exists' -Verbose

} ELSE {

    New-Item -Path "$BitlockerRegLoc" -Name 'FVE'

    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'ActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'ActiveDirectoryInfoToStore' -Value '00000002' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'EncryptionMethod' -Value '00000004' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'EncryptionMethodNoDiffuser' -Value '00000000' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsFdv' -Value '00000007' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsOs' -Value '00000007' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsRdv' -Value '00000004' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVRecovery' -Value '00000001' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVManageDRA' -Value '00000000' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVRecoveryPassword' -Value '00000002' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVRecoveryKey' -Value '00000002' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVHideRecoveryPage' -Value '00000001' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'FDVEncryptionType' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSActiveDirectoryInfoToStore' -Value '00000002' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSAllowSecureBootForIntegrity' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSEncryptionType' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSHideRecoveryPage' -Value '00000000' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSManageDRA' -Value '00000000' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSRecovery' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSRecoveryKey' -Value '00000002' -PropertyType DWORD
    #New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSRecoveryPage' -Value '00000000' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSRecoveryPassword' -Value '00000002' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'OSRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitlockerRegLoc\FVE" -Name 'RequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD

}

<# If the device has an enabled TPM, a Bitlocker Ready System Drive, and the drive is not encrypted.  Attempts to enable Bitlocker on drives#>
IF ($TPMEnabled -and $BitLockerReadyDrive -and $BitLockerDecrypted) {
    
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector

    Enable-BitLocker -MountPoint $env:SystemDrive -RecoveryPasswordProtector -EncryptionMethod XtsAes256 -ErrorAction SilentlyContinue

}

$BitLockerVolumeSecure = Get-BitlockerVolume | Where-Object {$_.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}} -ErrorAction SilentlyContinue

<# Attempts to backup all BitLocker Recovery Keys to AD if they exist#>
IF ($BitLockerVolumeSecure){

    FOREACH ($BLV in $BitLockerVolumeSecure) {

        $Key = $BLV | Select-Object -ExpandProperty KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}

        FOREACH ($obj in $key) {

            Backup-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorID $obj.KeyProtectorId

        }
    }
}