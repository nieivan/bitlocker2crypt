<#	
	.NOTES
	===========================================================================
   Created by:   	Johnny Ramos
   Revised by:    Ivan Nie
	 Filename:     	bitlocker2crypt.ps1
	===========================================================================
	.DESCRIPTION
    Method to escrow a Windows Bitlocker key to Crypt-Server.
    Revision: Escrow all fixed drives recovery keys to Crypt-Server
#>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$crypt_url = 'http://10.95.55.114:8000/checkin/'

$serial = (Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber

$username = (& "$PSScriptRoot\Get-LoggedOnUser.ps1" -ComputerName $env:COMPUTERNAME).UserName

$macname = $env:COMPUTERNAME

#Obtain the list of fixed drive letters
$FixedDrives = Get-WmiObject win32_diskdrive | Where-Object{$_.mediatype -eq "Fixed hard disk media"} | ForEach-Object{Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($_.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"} |  ForEach-Object{Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($_.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"} | ForEach-Object{$_.deviceid}

$bitLocker = Get-WmiObject `
               -Namespace "Root\cimv2\Security\MicrosoftVolumeEncryption" `
               -Class "Win32_EncryptableVolume" `

$protector_id = $bitLocker.GetKeyProtectors("0").volumekeyprotectorID

Foreach ($FixedDrive in $FixedDrives){

  Foreach ($item in $protector_id) {
  $data = manage-bde -protectors -get $FixedDrive -id $item
  $key = ($data | Select-String -Pattern 'Password:' -Context 0,1 | ForEach-Object {$_.Context.PostContext})

  if ($null -eq $key) {
    continue
  } else {
    $rec_key = $key[1] -replace ' ',''
    $postData = "recovery_password=$rec_key&serial=$serial&username=$username&macname=$macname"
    if ($rec_key.length -eq 55) {
      curl `
        -UseBasicParsing `
        -Uri $crypt_url `
        -Method Post `
        -Body $postData `
        -ContentType application/x-www-form-urlencoded `
        -Verbose
      }
    }
  }
}