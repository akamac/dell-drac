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
                Namespace = if ($CMC) {
                    'root/dell/cmc' 
                } else {
                    'root/dcim' 
                }
                ClassName = $CimClass
            }
            $CimInstance = switch ($PSCmdlet.ParameterSetName) {
                Class {
                    if ($Filter) {
                        $Param.Filter = $Filter 
                    }
                    Get-CimInstance @Param
                }
                Query {
                    Get-CimInstance @Param -Query $Query -QueryDialect $QueryDialect
                }
            }
            if ($MethodName) {
                $Job = $CimInstance | Invoke-CimMethod -CimSession $CimSession -MethodName $MethodName -Arguments $MethodParameters
                ?? { $Job.Job.EndpointReference.InstanceID } { $Job }
            } else {
                $CimInstance 
            }

            if ($KeepSession.IsPresent) {
                if ($CimOptions) {
                    # was created
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
    ? { $_.Status -eq 'Installed' -and $_.ElementName -match 'iDRAC' }
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
    if ($Unc.IsUnc) {
        # CIFS
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
    } else {
        # NFS
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