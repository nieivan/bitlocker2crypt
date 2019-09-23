Function Get-LoggedOnUser {

<#
.Synopsis
Queries a computer to check for interactive sessions

.DESCRIPTION
This script takes the output from the quser program and parses this to PowerShell objects

.NOTES   
Name: Get-LoggedOnUser
Author: Jaap Brasser
Version: 1.2.1
DateUpdated: 2015-09-23

.LINK
http://www.jaapbrasser.com

.PARAMETER ComputerName
The string or array of string for which a query will be executed

.EXAMPLE
.\Get-LoggedOnUser.ps1 -ComputerName server01,server02

Description:
Will display the session information on server01 and server02

.EXAMPLE
'server01','server02' | .\Get-LoggedOnUser.ps1

Description:
Will display the session information on server01 and server02
#>
    param(
        [CmdletBinding()] 
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = 'localhost'
    )

    begin {
        $ErrorActionPreference = 'Stop'
    }

    process {
        foreach ($Computer in $ComputerName) {
            try {
                    quser /server:$Computer 2>&1 | Select-Object -Skip 1 | ForEach-Object {
                        $CurrentLine = $_.Trim() -Replace '\s+',' ' -Split '\s'
                        $HashProps = @{
                            UserName = $CurrentLine[0]
                            ComputerName = $Computer
                        }

                # If session is disconnected different fields will be selected
                    if ($CurrentLine[2] -eq 'Disc') {
                            $HashProps.SessionName = $null
                            $HashProps.Id = $CurrentLine[1]
                            $HashProps.State = $CurrentLine[2]
                            $HashProps.IdleTime = $CurrentLine[3]
                            $HashProps.LogonTime = $CurrentLine[4..6] -join ' '
                            $HashProps.LogonTime = $CurrentLine[4..($CurrentLine.GetUpperBound(0))] -join ' '
                    } else {
                            $HashProps.SessionName = $CurrentLine[1]
                            $HashProps.Id = $CurrentLine[2]
                            $HashProps.State = $CurrentLine[3]
                            $HashProps.IdleTime = $CurrentLine[4]
                            $HashProps.LogonTime = $CurrentLine[5..($CurrentLine.GetUpperBound(0))] -join ' '
                    }

                    New-Object -TypeName PSCustomObject -Property $HashProps |
                    Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
                }
            } catch {
                New-Object -TypeName PSCustomObject -Property @{
                    ComputerName = $Computer
                    Error = $_.Exception.Message
                } | Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
            }
        }
    }
}

<#	
	.NOTES
	===========================================================================
    Created by:   	Johnny Ramos
    Revised by:     Ivan Nie
	Filename:     	bitlocker2crypt.ps1
	===========================================================================
	.DESCRIPTION
    Method to escrow a Windows Bitlocker key to Crypt-Server.
    Revision: Escrow all fixed drives recovery keys to Crypt-Server
#>


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$crypt_url = 'https://rkvault.bytedance.net/checkin/'

$serial = (Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber

$username = (Get-LoggedOnUser -ComputerName $env:COMPUTERNAME).UserName

$macname = $env:COMPUTERNAME

#Obtain the list of fixed drive letters
$FixedDrives = Get-WmiObject win32_diskdrive | Where-Object{$_.mediatype -eq "Fixed hard disk media"} | ForEach-Object{Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($_.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"} |  ForEach-Object{Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($_.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"} | ForEach-Object{$_.deviceid}

$bitLocker = Get-WmiObject `
               -Namespace "Root\cimv2\Security\MicrosoftVolumeEncryption" `
               -Class "Win32_EncryptableVolume" `

$protector_id = $bitLocker.GetKeyProtectors("0").volumekeyprotectorID


Foreach ($FixedDrive in $FixedDrives){

  Foreach ($item in $protector_id) {

    [String]$data = manage-bde -protectors -get $FixedDrive -id $item
    [Regex]$RegEx = '(?:\d{6}-){7}\d{6}'
    [Boolean]$MatchTest = $data -match $RegEx
    [String]$key = $matches.values

  if ($MatchTest) { 

    if ($key.Length -eq 55) {
        
        $postData = "recovery_password=$key&serial=$serial&username=$username&macname=$macname"
    
        curl `
            -UseBasicParsing `
            -Uri $crypt_url `
            -Method Post `
            -Body $postData `
            -ContentType application/x-www-form-urlencoded `
            -Verbose
      }
    } 

  else {
    continue
    }
  }
}

