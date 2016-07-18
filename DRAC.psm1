<#
cd wsman:\localhost
Set-Item .\MaxBatchItems –Value 100
cd wsman:\localhost\Client
Set-Item AllowUnencrypted –Value True
Set-Item TrustedHosts –Value *
cd wsman:\localhost\Client\Auth
Set-Item Basic –Value True
#>

#Import-Module -Prefix DRAC
[System.Collections.ArrayList]$CimSession = @()

function Invoke-CIM {
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [string[]] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [Parameter(ParameterSetName='Class')]
        [string] $CimClass,
        [Parameter(ParameterSetName='Class')]
        [string] $Filter,
        [Parameter(Mandatory,ParameterSetName='Query')]
        [string] $Query,
        [Parameter(Mandatory,ParameterSetName='Query')]
        [ValidateSet('WQL','CQL')]
        [string] $QueryDialect = 'CQL',
        [string] $MethodName,
        [hashtable] $MethodParameters,
        [switch] $KeepSession,
		[switch] $CMC
    )
	Process {
		foreach ($CN in $ComputerName) {
			$CimSession = $Script:CimSession.Where({$_.ComputerName -eq $CN})[0]
			if (-not $CimSession) {
				$CimOptions = New-CimSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -Encoding Utf8 -UseSsl
				$CimSession = New-CimSession -ComputerName $CN -Port 443 -Credential $Credential -Authentication Basic -SessionOption $CimOptions
			}
			#$BaseUri = 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2'
			#-ResourceUri "$BaseUri/$CimClass"
			$Param = @{
				CimSession = $CimSession
				Namespace = if ($CMC) { 'root/dell/cmc' } else { 'root/dcim' }
				ClassName = $CimClass
			}
			$CimInstance = switch ($PSCmdlet.ParameterSetName) {
				Class {
					if ($Filter) { $Param.Filter = $Filter }
					Get-CimInstance @Param
				}
				Query {
					Get-CimInstance @Param -Query $Query -QueryDialect $QueryDialect
				}
			}
			if ($MethodName) {
				$Job = $CimInstance | Invoke-CimMethod -CimSession $CimSession -MethodName $MethodName -Arguments $MethodParameters
				?? { $Job.Job.EndpointReference.InstanceID } { $Job }
			} else { $CimInstance }

			if ($KeepSession.IsPresent) {
				if ($CimOptions) { # was created
					[void]$Script:CimSession.Add($CimSession)
				}
			} else {
				$CimSession | Remove-CimSession
				[void]$Script:CimSession.Remove($CimSession)
			}
		}
	}
}

function Get-FwInfo {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    Invoke-CIM @PSBoundParameters -CimClass DCIM_SoftwareIdentity
}

function Get-SystemInfo {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
	)
    Invoke-CIM @PSBoundParameters -CimClass DCIM_SystemView
}

function Get-FcWwn {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    Invoke-CIM @PSBoundParameters -CimClass DCIM_FCView
}

function Get-SEL {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    Invoke-CIM @PSBoundParameters -CimClass DCIM_SELLogEntry
}

function Set-EmbeddedNic {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [Parameter(Mandatory,ParameterSetName='Enable')]
        [switch] $Enabled,
        [Parameter(Mandatory,ParameterSetName='Disable')]
        [switch] $Disabled,
        [switch] $KeepSession
    )
    $MethodParam = @{
        Target = 'BIOS.Setup.1-1'
        AttributeName = 'EmbNic1Nic2','EmbNic3Nic4'
    }
    if ($Enabled.IsPresent) {
        $MethodParam.AttributeValue = 'Enabled','Enabled'
    } else {
        $MethodParam.AttributeValue = 'DisabledOs','DisabledOs'
    }
	$Param = @{
		ComputerName = $ComputerName
		Credential = $Credential
		CimClass = 'DCIM_BIOSService'
	}
    Invoke-CIM @Param -MethodName SetAttributes -MethodParameters $MethodParam
    Invoke-CIM @Param -MethodName CreateTargetedConfigJob -MethodParameters @{
        Target = 'BIOS.Setup.1-1'
        RebootJobType = 2
        #1 - PowerCycle
        #2 - Graceful Reboot without forced shutdown
        #3 - Graceful Reboot with forced shutdown
        ScheduledStartTime = 'TIME_NOW'
        #UntilTime = 'TIME_NOW'
    }
}

function Update-Fw {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [Parameter(Mandatory)]
		[uri] $Url
    )
    # detect DC -> NFS node, protocol, file based on server generation
    $PSBoundParameters.Remove('Url')
    $DracFw = Invoke-CIM @PSBoundParameters -CimClass DCIM_SoftwareIdentity -KeepSession |
	? {	$_.Status -eq 'Installed' -and $_.ElementName -match 'iDRAC' }
    $Job = Invoke-CIM @PSBoundParameters -CimClass DCIM_SoftwareInstallationService -KeepSession -MethodName InstallFromURI -MethodParameters @{
        URI = $Url
        Target = [ref]$DracFw
    }
	# monitor job
	Invoke-CIM @PSBoundParameters -CimClass DCIM_SoftwareInstallationService -MethodName CreateRebootJob -MethodParameters @{
        RebootStartTime = 'TIME_NOW'
        RebootJobType = 2
        #1 - PowerCycle
        #2 - Graceful Reboot without forced shutdown
        #3 - Graceful Reboot with forced shutdown
    }
}

function Reboot-Device {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    #DCIM_JobControlService, only RebootJobType
	#DCIM_LifecycleJob
    Invoke-CIM @PSBoundParameters -CimClass DCIM_JobControlService -MethodName CreateRebootJob -MethodParameters @{
        #RebootStartTime = 'TIME_NOW'
        RebootJobType = 2
        #1 - PowerCycle
        #2 - Graceful Reboot without forced shutdown
        #3 - Graceful Reboot with forced shutdown
    }
}

function Get-Job {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [string] $InstanceID,
        [switch] $KeepSession
    )
	$Param = @{
		ComputerName = $ComputerName
		Credential = $Credential
		CimClass = 'DCIM_LifecycleJob'
	}
	if ($Filter) {
		$Param.Filter = "InstanceID = '$InstanceID'"
	}
    Invoke-CIM @Param -KeepSession:$KeepSession.IsPresent
}

function Mount-Image {
	[CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [Parameter(Mandatory)]
        [uri] $Unc, # NFS host:/mount/point/image.iso or CIFS \\host\share\image.iso
		[pscredential] $UncCredential # for CIFS only
    )
	if ($Unc.IsUnc) { # CIFS
		$MethodParam = @{
			IPAddress = $Unc.Host
			ShareName = $Unc.Segments[1].Trim('/')
			ImageName = $Unc.Segments[-1]
			ShareType = 2
		}
		if ($UncCredential) {
			$MethodParam.UserName = $UncCredential.UserName
			$MethodParam.Password = $UncCredential.GetNetworkCredential().Password
		}
	} else { # NFS
		$ParsedUnc = $Unc -split '/'
		$MethodParam = @{
			IPAddress = $ParsedUnc[0].TrimEnd(':')
			ShareName = '/' + ($ParsedUnc[1..($ParsedUnc.Count - 2)] -join '/')
			ImageName = $ParsedUnc[-1]
			ShareType = 0
		}
	}

	# REF returned to started CIM_ConcreteJob
	$Param = @{
		ComputerName = $ComputerName
		Credential = $Credential
		CimClass = 'DCIM_OSDeploymentService'
		MethodName = 'ConnectNetworkISOImage'
		MethodParameters = $MethodParam
	}
    Invoke-CIM @Param -KeepSession
}

function Dismount-Image {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    Invoke-CIM @PSBoundParameters -CimClass DCIM_OSDeploymentService -MethodName DisconnectNetworkISOImage
}

# boot to Virtual Floppy in UEFI mode
function BootTo-Device {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [Parameter(Mandatory)]
        #[ValidateSet()]
        [string] $Device,
        [ValidateSet('BIOS','UEFI')]
        [string] $BootMode,
        [switch] $KeepSession
    )
	$Param = @{
		ComputerName = $ComputerName
		Credential = $Credential
        CimClass = 'DCIM_BootConfigSetting'
	}
    if ($BootMode) {
        Invoke-CIM @Param -MethodName SetAttribute -MethodParameters @{
            AttributeName = 'BootMode'
            AttributeValue = $BootMode
        }
    }

    Invoke-CIM @Param -MethodName ChangeBootOrderByInstanceID -MethodParameters @{
        EnabledState = 'BIOS.Setup.1-1'
        Source = #UEFI:Disk.USBFront.2-1:3156051d1529b8f4f88c99f54b895350 (boot source belongs to UEFI bootlist) array of DCIM_BootSourceSetting.InstanceID
        #1 - PowerCycle
        #2 - Graceful Reboot without forced shutdown
        #3 - Graceful Reboot with forced shutdown
        ScheduledStartTime = 'TIME_NOW'
        #UntilTime = 'TIME_NOW'
    }
	Invoke-CIM @Param -MethodName ChangeBootOrderByInstanceID -MethodParameters @{
		# UEFI
		#InstanceID = 'OneTime'
		Source = 'UEFI'
	}
}

# DCIM_BIOSEnumeration
function Set-TpmModule {
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [Parameter(Mandatory,ParameterSetName='Enable')]
        [switch] $Enabled,
        [Parameter(Mandatory,ParameterSetName='Disable')]
        [switch] $Disabled,
        [switch] $KeepSession
    )
	$TpmSecurity = @{
        Target = 'BIOS.Setup.1-1'
        AttributeName = 'TpmSecurity'
    }
    $TpmCommand = @{
        Target = 'BIOS.Setup.1-1'
        AttributeName = 'TpmCommand'
    }
    if ($Enabled.IsPresent) {
		$TpmSecurity.AttributeValue = 'OnPbm'
        $TpmCommand.AttributeValue = 'Activate'
    } else {
		$TpmSecurity.AttributeValue = 'Off'
        $TpmCommand.AttributeValue = 'Deactivate'
    }
	$Param = @{
		ComputerName = $ComputerName
		Credential = $Credential
		CimClass = 'DCIM_BIOSService'
	}
    Invoke-CIM @Param -MethodName SetAttributes -MethodParameters $TpmSecurity
    Invoke-CIM @Param -MethodName SetAttributes -MethodParameters $TpmCommand
    Invoke-CIM @Param -MethodName CreateTargetedConfigJob -MethodParameters @{
        Target = 'BIOS.Setup.1-1'
        RebootJobType = 2
        #1 - PowerCycle
        #2 - Graceful Reboot without forced shutdown
        #3 - Graceful Reboot with forced shutdown
        ScheduledStartTime = 'TIME_NOW'
        #UntilTime = 'TIME_NOW'
    }
}

# enable tpm
<#
$query="select * from DCIM_iDRACCardEnumeration WHERE GroupID='Users.1'"
$queryDialect="http://schemas.microsoft.com/wbem/wsman/1/WQL"
$resourceUri="http://schemas.dell.com/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_iDRACCardEnumeration"
Get-CimInstance -Query $query -CimSession $session -Namespace root/dcim -QueryDialect $queryDialect -ResourceUri $resourceUri

$queryDialect = 'http://schemas.microsoft.com/wbem/wsman/1/WQL'
$query = "SELECT ElementName FROM DCIM_SoftwareIdentity" # WHERE ElementName LIKE 'HBA'"

DCIM_PCIDeviceView -Filter 'FQDD like "FC.Slot.%"'

winrm e http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_FCView
-u:root -p:calvin -r:https://<IPAddress>/wsman -SkipCNcheck -SkipCAcheck -encoding:utf-8 -a:basic

DCIM_BootConfigSetting
BootSeq
HddSeq
UefiBootSeq
OneTimeBootMode
vFlash Boot Configuration



OneTimeBootMode
OneTimeBootSeqDev
OneTimeHddSeqDev

#>
# SIG # Begin signature block
# MIIXkgYJKoZIhvcNAQcCoIIXgzCCF38CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUBx6iT9PEc9aq+EOVtfQ09J50
# 82igghJVMIIEFDCCAvygAwIBAgILBAAAAAABL07hUtcwDQYJKoZIhvcNAQEFBQAw
# VzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNV
# BAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0
# MTMxMDAwMDBaFw0yODAxMjgxMjAwMDBaMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBDQSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlO9l
# +LVXn6BTDTQG6wkft0cYasvwW+T/J6U00feJGr+esc0SQW5m1IGghYtkWkYvmaCN
# d7HivFzdItdqZ9C76Mp03otPDbBS5ZBb60cO8eefnAuQZT4XljBFcm05oRc2yrmg
# jBtPCBn2gTGtYRakYua0QJ7D/PuV9vu1LpWBmODvxevYAll4d/eq41JrUJEpxfz3
# zZNl0mBhIvIG+zLdFlH6Dv2KMPAXCae78wSuq5DnbN96qfTvxGInX2+ZbTh0qhGL
# 2t/HFEzphbLswn1KJo/nVrqm4M+SU4B09APsaLJgvIQgAIMboe60dAXBKY5i0Eex
# +vBTzBj5Ljv5cH60JQIDAQABo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBRG2D7/3OO+/4Pm9IWbsN1q1hSpwTBHBgNV
# HSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFs
# c2lnbi5jb20vcmVwb3NpdG9yeS8wMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLm5ldC9yb290LmNybDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQ
# L30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEATl5WkB5GtNlJMfO7FzkoG8IW
# 3f1B3AkFBJtvsqKa1pkuQJkAVbXqP6UgdtOGNNQXzFU6x4Lu76i6vNgGnxVQ380W
# e1I6AtcZGv2v8Hhc4EvFGN86JB7arLipWAQCBzDbsBJe/jG+8ARI9PBw+DpeVoPP
# PfsNvPTF7ZedudTbpSeE4zibi6c1hkQgpDttpGoLoYP9KOva7yj2zIhd+wo7AKvg
# IeviLzVsD440RZfroveZMzV+y5qKu0VN5z+fwtmK+mWybsd+Zf/okuEsMaL3sCc2
# SI8mbzvuTXYfecPlf5Y1vC0OzAGwjn//UYCAp5LUs0RGZIyHTxZjBzFLY7Df8zCC
# BJkwggOBoAMCAQICEHGgtzaV3bGvwjsrmhjuVMswDQYJKoZIhvcNAQELBQAwgakx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xKDAmBgNVBAsTH0Nl
# cnRpZmljYXRpb24gU2VydmljZXMgRGl2aXNpb24xODA2BgNVBAsTLyhjKSAyMDA2
# IHRoYXd0ZSwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MR8wHQYDVQQD
# ExZ0aGF3dGUgUHJpbWFyeSBSb290IENBMB4XDTEzMTIxMDAwMDAwMFoXDTIzMTIw
# OTIzNTk1OVowTDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEm
# MCQGA1UEAxMddGhhd3RlIFNIQTI1NiBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbVQJMFwXp0GbD/Cit08D+7+DpftQe9qob
# kUb99RbtmAdT+rqHG32eHwEnq7nSZ8q3ECVT9OO+m5C47SNcQu9kJVjliCIavvXH
# rvW+irEREZMaIql0acF0tmiHp4Mw+WTxseM4PvTWwfwS/nNXFzVXit1QjQP4Zs3K
# doMTyNcOcR3kY8m6F/jRueSI0iwoyCEgDUG3C+IvwoDmiHtTbMNEY4F/aEeMKyrP
# W/SMSWG6aYX9awB4BSZpEzCAOE7xWlXJxVDWqjiJR0Nc/k1zpUnFk2n+d5aar/OM
# Dle6M9kOxkLTA3fEuzmtkfnz95ZcOmSm7SdXwehA81Pyvik0/l/5AgMBAAGjggEX
# MIIBEzAvBggrBgEFBQcBAQQjMCEwHwYIKwYBBQUHMAGGE2h0dHA6Ly90Mi5zeW1j
# Yi5jb20wEgYDVR0TAQH/BAgwBgEB/wIBADAyBgNVHR8EKzApMCegJaAjhiFodHRw
# Oi8vdDEuc3ltY2IuY29tL1RoYXd0ZVBDQS5jcmwwHQYDVR0lBBYwFAYIKwYBBQUH
# AwIGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIBBjApBgNVHREEIjAgpB4wHDEaMBgG
# A1UEAxMRU3ltYW50ZWNQS0ktMS01NjgwHQYDVR0OBBYEFFeGm1S4vqYpiuT2wuIT
# GImFzdy3MB8GA1UdIwQYMBaAFHtbRc+vzst6/TGSGmq280brV0hQMA0GCSqGSIb3
# DQEBCwUAA4IBAQAkO/XXoDYTx0P+8AmHaNGYMW4S5D8eH5Z7a0weh56LxWyjsQx7
# UJLVgZyxjywpt+75kQW5jkHxLPbQWS2Y4LnqgAFHQJW4PZ0DvXm7NbatnEwn9mdF
# EMnFvIdOVXvSh7vd3DDvxtRszJk1bRzgYNPNaI8pWUuJlghGyY78dU/F3AnMTieL
# RM0HvKwE4LUzpYef9N1zDJHqEoFv43XwHrWTbEQX1T6Xyb0HLFZ3H4XdRui/3iyB
# lKP35benwTefdcpVd01eNinKhdhFQXJXdcB5W/o0EAZtZCBCtzrIHx1GZAJfxke+
# 8MQ6KFTa9h5PmqIZQ6RvSfj8XkIgKISLRyBuMIIEnzCCA4egAwIBAgISESHWmadk
# lz7x+EJ+6RnMU0EUMA0GCSqGSIb3DQEBBQUAMFIxCzAJBgNVBAYTAkJFMRkwFwYD
# VQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVz
# dGFtcGluZyBDQSAtIEcyMB4XDTE2MDUyNDAwMDAwMFoXDTI3MDYyNDAwMDAwMFow
# YDELMAkGA1UEBhMCU0cxHzAdBgNVBAoTFkdNTyBHbG9iYWxTaWduIFB0ZSBMdGQx
# MDAuBgNVBAMTJ0dsb2JhbFNpZ24gVFNBIGZvciBNUyBBdXRoZW50aWNvZGUgLSBH
# MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALAXrqLTtgQwVh5YD7Ht
# VaTWVMvY9nM67F1eqyX9NqX6hMNhQMVGtVlSO0KiLl8TYhCpW+Zz1pIlsX0j4waz
# hzoOQ/DXAIlTohExUihuXUByPPIJd6dJkpfUbJCgdqf9uNyznfIHYCxPWJgAa9MV
# VOD63f+ALF8Yppj/1KvsoUVZsi5vYl3g2Rmsi1ecqCYr2RelENJHCBpwLDOLf2iA
# KrWhXWvdjQICKQOqfDe7uylOPVOTs6b6j9JYkxVMuS2rgKOjJfuv9whksHpED1wQ
# 119hN6pOa9PSUyWdgnP6LPlysKkZOSpQ+qnQPDrK6Fvv9V9R9PkK2Zc13mqF5iME
# Qq8CAwEAAaOCAV8wggFbMA4GA1UdDwEB/wQEAwIHgDBMBgNVHSAERTBDMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAJBgNVHRMEAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Mv
# Z3N0aW1lc3RhbXBpbmdnMi5jcmwwVAYIKwYBBQUHAQEESDBGMEQGCCsGAQUFBzAC
# hjhodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RpbWVzdGFt
# cGluZ2cyLmNydDAdBgNVHQ4EFgQU1KKESjhaGH+6TzBQvZ3VeofWCfcwHwYDVR0j
# BBgwFoAURtg+/9zjvv+D5vSFm7DdatYUqcEwDQYJKoZIhvcNAQEFBQADggEBAI+p
# GpFtBKY3IA6Dlt4j02tuH27dZD1oISK1+Ec2aY7hpUXHJKIitykJzFRarsa8zWOO
# sz1QSOW0zK7Nko2eKIsTShGqvaPv07I2/LShcr9tl2N5jES8cC9+87zdglOrGvbr
# +hyXvLY3nKQcMLyrvC1HNt+SIAPoccZY9nUFmjTwC1lagkQ0qoDkL4T2R12WybbK
# yp23prrkUNPUN7i6IA7Q05IqW8RZu6Ft2zzORJ3BOCqt4429zQl3GhC+ZwoCNmSI
# ubMbJu7nnmDERqi8YTNsz065nLlq8J83/rU9T5rTTf/eII5Ol6b9nwm8TcoYdsmw
# TYVQ8oDSHQb1WAQHsRgwggT5MIID4aADAgECAhA25UgNgLhTE6qJjFxm6xUnMA0G
# CSqGSIb3DQEBCwUAMEwxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwx0aGF3dGUsIElu
# Yy4xJjAkBgNVBAMTHXRoYXd0ZSBTSEEyNTYgQ29kZSBTaWduaW5nIENBMB4XDTE1
# MTIyOTAwMDAwMFoXDTE5MDEyNzIzNTk1OVowgZIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRwwGgYDVQQK
# FBNJbnRlcm1lZGlhLm5ldCwgSW5jMRowGAYDVQQLFBFJbnRlcm5ldCBTZXJ2aWNl
# czEcMBoGA1UEAxQTSW50ZXJtZWRpYS5uZXQsIEluYzCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAMCZZZMUuMOfXj33He0GzsA2lBP9CRrvQRzS5weO3juk
# X5AwYyD0YJeb39hmt0xwK/09BvamaSXznLT8ehIVZUENAzokR6tRK9WQD6X+v1vg
# KQmKTrmqWm9KJ+obsr8WWgj4N4/9J8d3QupZbY2Q5PPSeSkxfiCf4N76COtqNRCN
# F/V0w4JdBOQPtITJtx0CBEBwsTTWxB2qr1fkvLDzmdH+SxNscD9ljR1q5x1plxWd
# khJhBkRLKNl2Cnou2rLeiczCQwVPa8HRCU2BwtWOycgFox5muZNfU+YagP9Mup6q
# 5cUBhsHqpNRQo8gz7W91NpNK4MJA0d1PpEuLQ2pOFMMCAwEAAaOCAY4wggGKMAkG
# A1UdEwQCMAAwHwYDVR0jBBgwFoAUV4abVLi+pimK5PbC4hMYiYXN3LcwHQYDVR0O
# BBYEFI2trWtDPkeH/YiSDbpBmcqiHjOyMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6
# Ly90bC5zeW1jYi5jb20vdGwuY3JsMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
# BggrBgEFBQcDAzBzBgNVHSAEbDBqMGgGC2CGSAGG+EUBBzACMFkwJgYIKwYBBQUH
# AgEWGmh0dHBzOi8vd3d3LnRoYXd0ZS5jb20vY3BzMC8GCCsGAQUFBwICMCMMIWh0
# dHBzOi8vd3d3LnRoYXd0ZS5jb20vcmVwb3NpdG9yeTAdBgNVHQQEFjAUMA4wDAYK
# KwYBBAGCNwIBFgMCB4AwVwYIKwYBBQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRw
# Oi8vdGwuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpodHRwOi8vdGwuc3ltY2IuY29t
# L3RsLmNydDANBgkqhkiG9w0BAQsFAAOCAQEAQldghwA5DW+zca++L7Gu1f5d0T4o
# 7Ko5SO4L6CPrW9Wv4zDVMjtQdG/y/s64LP+4KVlfRg/UeftCV1YxDwU7/O0/I+RV
# qkTDw9AhbnUzXVzsFMi2f34ywRKbGucmfKlJM9u8gWFLJBLhPSbxFhiDalCIQG2c
# CCGRIz9EqclDrL/doyT39fmpZ6IcxuDmspWX5cynYxW5tyjIcRztFLxYuhZzp0At
# vIvLAyvUNuPbdAA08wv6u+EJTbieti4nlVNDFm5CDvF8QbdgtJqtmH5GNb0Piqao
# eh76hQmpyEJAdBy1yL10itsGHYc1gCvk9UmH193qQ4ZGbQki5tEIucXtAzGCBKcw
# ggSjAgEBMGAwTDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEm
# MCQGA1UEAxMddGhhd3RlIFNIQTI1NiBDb2RlIFNpZ25pbmcgQ0ECEDblSA2AuFMT
# qomMXGbrFScwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARYwIwYJKoZIhvcNAQkEMRYEFBZ6yTVkAxU5srBg1ewh/ZMNgP3lMA0G
# CSqGSIb3DQEBAQUABIIBAHCk08q99r4v4Lzyid2f1Iat3WmYWLz2VEi1C3Qm4/Fb
# 2xRC9e1rhA3sFIE55N5iGwDYfATaADvFYGYah17jEnMBu59b+YF4pmhzAQX+Gmd+
# gAdnz2oip187S3SyfaYNMQyyWJ6iVUaMkOgMDZmtG4o4YOQx1koLCH/fWlTCij6V
# x50rMIpe6Dur+8dS6ICuXPrPkmh0KtgY4/GzxmrONzHcaBxNzy4Ew02+WsaaFp3K
# lnaQwu/YWJTj3ENlw3j6cIioOizaxRWGal7Fb8pOSVx4NO4i9ZBUp9B9IBygtqNv
# XurqZcY4agLthiIVo0w0g9JFcfybUuRpSm1+SCmP/buhggKiMIICngYJKoZIhvcN
# AQkGMYICjzCCAosCAQEwaDBSMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEoMCYGA1UEAxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0Eg
# LSBHMgISESHWmadklz7x+EJ+6RnMU0EUMAkGBSsOAwIaBQCggf0wGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwNzE4MTQwNzE3WjAj
# BgkqhkiG9w0BCQQxFgQU1WqaDyMrc0JGDoOuZAgTlbqhwAIwgZ0GCyqGSIb3DQEJ
# EAIMMYGNMIGKMIGHMIGEBBRjuC+rYfWDkJaVBQsAJJxQKTPseTBsMFakVDBSMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UEAxMf
# R2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMgISESHWmadklz7x+EJ+6RnM
# U0EUMA0GCSqGSIb3DQEBAQUABIIBAISZHrqOePtL3YDcoibidVNXKHoqBL0zTznb
# oAPLsbJshmP+d+N/3vDFN0k8xYU4VDFba7DFG2lf+/9h5U+KI7EqDGoL3MgqC+Nz
# am/QMBEe41+IXGeL8b2zPMhiA6d/UW2TKkqtYhX4OReFaAJRPwRdTmzamaWLykWH
# jAEK13qbueTmM6fY0Gh7LdPn1ThBlkXoSiK30XBAEJkM/07DTEOpfgsfjAczuyn2
# Zs4Xuqolcapun9ka5Nx2Gq+ciqjOcifvcNvxuabT6vzHMOGAo2L7PsrbNMw8m0pP
# DumwoCay7/1UA0v8pKNtGZ0rR47KAiGFCYfSs3nIy7J7ZwLR/N0=
# SIG # End signature block
