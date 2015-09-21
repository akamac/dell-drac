#Import-Module -Prefix DRAC
[System.Collections.ArrayList]$Script:CimSession = @()

function Invoke-CIM {
    Param (
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [Parameter(Mandatory,ParameterSetName='Class')]
        [string] $CimClass,
        [Parameter(ParameterSetName='Class')]
        [string] $Filter,
        [Parameter(Mandatory,ParameterSetName='Query')]
        [string] $Query,
        [Parameter(Mandatory,ParameterSetName='Query')]
        [ValidateSet('WQL','CQL')]
        [string] $QueryDialect,
        [string] $MethodName,
        [hashtable] $MethodParameters,
        [switch] $KeepSession
    )
    $CimSession = $Script:CimSession.Where({$_.ComputerName -eq $ComputerName})[0]
    if (-not $CimSession) {
        $CimOptions = New-CimSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -Encoding Utf8 -UseSsl
        $CimSession = New-CimSession -ComputerName $ComputerName -Port 443 -Credential $Credential -Authentication Basic -SessionOption $CimOptions
    }
    $BaseUri = 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2'

    $CimInstance = switch ($PSCmdlet.ParameterSetName) {
        Class {
            Get-CimInstance -CimSession $CimSession -ResourceUri "$BaseUri/$CimClass" -Filter $Filter
        }
        Query {
            Get-CimInstance -CimSession $CimSession -ResourceUri "$BaseUri/$CimClass" -Query $Query -QueryDialect $QueryDialect #-Namespace root/dcim 
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

function Get-FwInfo {
    Param (
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    Invoke-CIM @PSBoundParameters -CimClass DCIM_SoftwareIdentity
}

function Get-SystemInfo {
    Param (
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
	)
    Invoke-CIM @PSBoundParameters -CimClass DCIM_SystemView
}

function Get-FcWwn {
    Param (
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    Invoke-CIM @PSBoundParameters -CimClass DCIM_FCView
}

function Get-SEL {
    Param (
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    Invoke-CIM @PSBoundParameters -CimClass DCIM_SELLogEntry
}

function Set-EmbeddedNic {
    Param (
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
    $Param = @{
        Target = 'BIOS.Setup.1-1'
        AttributeName = 'EmbNic1Nic2','EmbNic3Nic4'
    }
    if ($Enabled.IsPresent) {
        $Param.AttributeValue = 'Enabled','Enabled'
    } else {
        $Param.AttributeValue = 'DisabledOs','DisabledOs'
    }
    Invoke-CIM -ComputerName $ComputerName -Credential $Credential `
    -CimClass DCIM_BIOSService -MethodName SetAttributes -MethodParameters $Param
    Invoke-CIM -ComputerName $ComputerName -Credential $Credential `
    -CimClass DCIM_BIOSService -MethodName CreateTargetedConfigJob -MethodParameters @{
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
    Param (
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential
    )
    # detect DC -> NFS node, protocol, file based on server generation
    #'http://10.224.210.41/drac/iDRAC-with-Lifecycle-Controller_Firmware_VN754_WN64_2.15.10.10_A00.EXE' # DUP x64 http/ftp/tftp/cifs/nfs
    $DracFw = Invoke-CIM @PSBoundParameters -CimClass DCIM_SoftwareIdentity -Filter 'InstanceID LIKE "INSTALLED#iDRAC"' -KeepSession
    #? InstanceID -match 'INSTALLED#iDRAC'
    Invoke-CIM @PSBoundParameters -KeepSession -CimClass DCIM_SoftwareInstallationService -MethodName InstallFromURI -MethodParameters @{
        URI = $Url
        Target = [ref]$DracFw
    }
    
    # if reboot is reqired
    # Reboot-Device @PSBoundParameters
}

function Reboot-Device {
    Param (
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [switch] $KeepSession
    )
    #DCIM_JobControlService, only RebootJobType
    Invoke-CIM @PSBoundParameters -CimClass DCIM_LifecycleJob -MethodName CreateRebootJob -MethodParameters @{
        RebootStartTime = 'TIME_NOW'
        RebootJobType = 2
        #1 - PowerCycle
        #2 - Graceful Reboot without forced shutdown
        #3 - Graceful Reboot with forced shutdown
    }
}

function Get-Job {
    Param (
        [Parameter(Mandatory)]
        [string] $ComputerName,
        [Parameter(Mandatory)]
        [pscredential] $Credential,
        [string] $InstanceID,
        [switch] $KeepSession
    )
    Invoke-CIM -ComputerName $ComputerName -Credential $Credential -CimClass DCIM_LifecycleJob `
    -Filter "InstanceID = `"$InstanceID`"" -KeepSession:$KeepSession.IsPresent
}

function Mount-Iso {
	[CmdletBinding()]
    Param (
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
	} else { # NFS
		$ParsedUnc = $Unc -split '/'
		$MethodParam = @{
			IPAddress = $ParsedUnc[0].TrimEnd(':')
			ShareName = '/' + ($ParsedUnc[1..($ParsedUnc.Count - 2)] -join '/')
			ImageName = $ParsedUnc[-1]
			ShareType = 0
		}
	}
	if ($UncCredential) {
		$MethodParam.UserName = $UncCredential.UserName
		$MethodParam.Password = $UncCredential.GetNetworkCredential().Password
	}
	# REF returned to started CIM_ConcreteJob
    Invoke-CIM -ComputerName $ComputerName -Credential $Credential `
    -CimClass DCIM_OSDeploymentService -MethodName ConnectNetworkISOImage -MethodParameters $MethodParam -KeepSession
}

function Dismount-Iso {
    Param (
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
    Param (
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

    if ($BootMode) {
        Invoke-CIM -ComputerName $ComputerName -Credential $Credential `
        -CimClass DCIM_BootConfigSetting -MethodName SetAttribute -MethodParameters @{
            AttributeName = 'BootMode'
            AttributeValue = $BootMode
        }
    }

    Invoke-CIM -ComputerName $ComputerName -Credential $Credential `
    -CimClass DCIM_BootSourceSetting -MethodName ChangeBootOrderByInstanceID -MethodParameters @{
        EnabledState = 'BIOS.Setup.1-1'
        Source = #UEFI:Disk.USBFront.2-1:3156051d1529b8f4f88c99f54b895350 (boot source belongs to UEFI bootlist) array of DCIM_BootSourceSetting.InstanceID
        #1 - PowerCycle
        #2 - Graceful Reboot without forced shutdown
        #3 - Graceful Reboot with forced shutdown
        ScheduledStartTime = 'TIME_NOW'
        #UntilTime = 'TIME_NOW'
    }
}

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
#>