<#
    .SYNOPSIS
        Ensure device is Autopilot Ready

    .DESCRIPTION
        To ensure a new or existing device is ready to be Autopilot deployed

    .NOTES
        Author		: Dick Tracy <richard.tracy@hotmail.com>
	    Source		: https://github.com/PowerShellCrack/AutopilotTimeZoneSelectorUI
        Version		: 2.2.0
        README      : Review README.md for more details and configurations
        CHANGELOG   : Review CHANGELOG.md for updates and fixes
        IMPORTANT   : By using this script or parts of it, you have read and accepted the DISCLAIMER.md and LICENSE agreement

    .PARAMETER AzureEnvironment
        Specify the Azure environment for graph

    .PARAMETER Serial
        Specify the serial number of a device.

    .PARAMETER DeviceName
        Specify the deviceName to check against.

    .PARAMETER UserPrincipalName
        Specity the UserPrinciplName

    .PARAMETER CheckUserLicense
        Check user licenses

    .PARAMETER CheckAzureAdvSettings
        Check additional settings in Azure

    .EXAMPLE
       .\AutoPilotReadiness.ps1 -Serial 'N4N0CX11Z173170'

    .EXAMPLE
        .\AutoPilotReadiness.ps1 -DeviceName 'DTOAAD-1Z156178'

    .EXAMPLE
        .\AutoPilotReadiness.ps1 -Serial 'N4N0CX11Z173170' -UserPrincipalName 'tracyr@contoso.com' -CheckUserLicense

    .EXAMPLE
        .\AutoPilotReadiness.ps1 -DeviceName 'DTOAAD-1Z156178' -UserPrincipalName 'tracyr@contoso.com' -CheckUserLicense -CheckAzureAdvSettings
#>
[CmdletBinding()]
Param(
    [ValidateSet('Public','USGov','USDoD')]
    [string]$AzureEnvironment = 'Public',

    [Parameter(Mandatory = $true,ParameterSetName='device')]
    [string]$DeviceName,

    [Parameter(Mandatory = $true,ParameterSetName='serial')]
    [string]$Serial,

    [Parameter(Mandatory = $false,HelpMessage="Please enter a valid user principal name [userid@domain]")]
    [ValidateScript({$_ -match "^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,4}$"})]
    [string]$UserPrincipalName,

    [switch]$CheckUserLicense,

    [switch]$CheckAzureAdvSettings
)

##======================
## VARIABLES
##======================
$ErrorActionPreference = "Stop"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Save current progress preference and hide the progress
$global:ProgressPreference = 'SilentlyContinue'
#Check if verbose is used; if it is don't use the nonewline in output
If($VerbosePreference){$NoNewLine=$False}Else{$NoNewLine=$True}

## ================================
## IMPORT FUNCTIONS
## ================================
Function Get-Symbol{
    <#
    .SYNOPSIS
    Returns a UTF-8 character based on the symbol name

    .DESCRIPTION
    Returns a UTF-8 character based on the symbol name

    .PARAMETER Symbol
    The name of the symbol to return

    .EXAMPLE
    Get-Symbol -Symbol GreenCheckmark

    .EXAMPLE
    Get-Symbol -Symbol RedX
    #>
    Param(
    [ValidateSet(   'AccessDenied',
                    'Alert',
                    'Cloud',
                    'GreenCheckmark',
                    'Hourglass',
                    'Information',
                    'Lightbulb',
                    'Lock',
                    'RedX',
                    'Script',
                    'WarningSign'
    )]
    [string]$Symbol
    )

    switch($Symbol){
       'AccessDenied' { Return [char]::ConvertFromUtf32(0x1F6AB)}
       'Alert' { Return [char]::ConvertFromUtf32(0x1F514)}
       'Cloud' { Return [char]::ConvertFromUtf32(0x2601)}
       'GreenCheckmark' { Return [char]::ConvertFromUtf32(0x2705)}
       'Hourglass' { Return [char]::ConvertFromUtf32(0x231B)}
       'Information' { Return [char]::ConvertFromUtf32(0x2139)}
       'Lightbulb' { Return [char]::ConvertFromUtf32(0x1F4A1)}
       'Lock' { Return [char]::ConvertFromUtf32(0x1F512)}
       'RedX' { Return [char]::ConvertFromUtf32(0x274C)}
       'Script' { Return [char]::ConvertFromUtf32(0x1F4DC)}
       'WarningSign' { Return [char]::ConvertFromUtf32(0x26A0)}
    }

}

Write-Host ("`nPrerequisite check...") -ForegroundColor Cyan

# Determine what environment to use
switch($AzureEnvironment){
    'Public' {$script:GraphEndpoint = 'https://graph.microsoft.com';$GraphEnvironment = "Global"}
    'USgov' {$script:GraphEndpoint = 'https://graph.microsoft.us';$GraphEnvironment = "USgov"
        Write-Host "Autopilot is not available in USgov environment as of 8/2/2023. Exiting script..." -ForegroundColor Red
        Exit
    }
    'USDoD' {$script:GraphEndpoint = 'https://dod-graph.microsoft.us';$GraphEnvironment = "USGovDoD"
        Write-Host "Autopilot is not available in USDod environment as of 8/2/2023. Exiting script..." -ForegroundColor Red
        Exit
}
    default {$script:GraphEndpoint = 'https://graph.microsoft.com';$GraphEnvironment = "Global"}
}

#CONSTANTS
$IntuneEnrolled = $false
$MDMPolicyAssigned = $false
$AssignedToIntuneLicense = $false
$PrimaryAssignedUser = $null
$AssignedToESPApp = $false
$UserAssignedApps = @()
$UserAssignedAppsGroups = @()
$ZTDID = $null
$AutopilotDevice = $null
##*=============================================
##* INSTALL MODULES
##*=============================================
# Get WindowsAutopilotIntune module (and dependencies)
Write-Host ("    |---Checking for module dependencies...")

$Modules =  @(
    'Microsoft.Graph.Authentication'
)

$i=0
Foreach($Module in $Modules){
    $i++
    Write-Host ("        |---[{0} of {1}]: Installing module {2}..." -f $i,$Modules.count,$Module) -NoNewline:$noNewLine
    #Write-Host ('{0}{1}' -f $msg,(Set-GapCharacter -MessageLength $msg.Length)) -NoNewline

    if ( Get-Module -FullyQualifiedName $Module -ListAvailable ) {
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    }
    else {
        Try{
            # Needs to be installed as an admin so that the module will execute
            Install-Module -Name $Module -Scope AllUsers -ErrorAction Stop
            Import-Module -Name $Module -Scope Global
            Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
        }
        Catch {
            Write-Host ("{0}. {1}" -f (Get-Symbol -Symbol RedX),$_.Exception.message)
            exit
        }
    }
}

#Install-Module WindowsAutopilotIntune -MinimumVersion 5.3
## ================================
## MAIN
## ================================
Write-Host ("    |---Connecting to tenant...") -NoNewline:$NoNewLine
#REFERNCE: https://learn.microsoft.com/en-us/graph/permissions-reference
try{
    $Scopes = @(
        'Device.Read.All'
        'Directory.Read.All'
        'GroupMember.Read.All'
        'Group.Read.All'
        'User.Read.All'
        'DeviceManagementApps.Read.All'
        'DeviceManagementConfiguration.Read.All'
        'DeviceManagementManagedDevices.Read.All'
        'DeviceManagementServiceConfig.Read.All'
    )

    If($PSBoundParameters.ContainsKey('CheckUserLicense')){
        $Scopes += @(
            'Organization.Read.All' #Required for graph endpoint: subscribedSkus
            'Policy.Read.All'
        )
    }

    If($PSBoundParameters.ContainsKey('CheckAzureAdvSettings')){
        $Scopes += @(
            #'AuditLog.Read.All' #Required for graph endpoint: directoryAudits
            'Policy.Read.All'
        )
    }


    $null = Connect-MgGraph -Environment $GraphEnvironment -Scopes ($Scopes | Select-Object -Unique) -Verbose:$false
    $MGContext = Get-MgContext
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---Connected as: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $MGContext.Account) -ForegroundColor Cyan

}Catch{

    Write-Host ("{0} " -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red -NoNewline
    Write-Verbose ("{0} " -f $_.Exception.Message)
    Write-Host "`nUnable to connect to tenant. Can't continue!" -ForegroundColor Red
    Exit

}


Write-Host ("`nStarting Autopilot readiness check...") -ForegroundColor Cyan
# 1. Check if device is enrolled as Autopilot Device
#------------------------------------------------------------------------------------------
#check by name
If ($PSCmdlet.ParameterSetName -eq "device")
{
    Write-Host ("    |---Retrieving device name from Azure AD [{0}]..." -f $DeviceName) -NoNewline:$noNewLine
    Try{
        $AzureADDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/devices?`$filter=displayName eq '$DeviceName'").Value
    }Catch{

        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-host ("REASON: Your graph permissions are not allowing you to read policies from Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [Device.Read.All] from graph and rerun script") -ForegroundColor Red
        Exit
    }

    If($AzureADDevice.count -eq 1){
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Host ("        |---AzureAD Object id: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $AzureADDevice.Id) -ForegroundColor Cyan
        
        #iterate through each PhysicalIds to get Autopilot one
        Foreach($PhysicalIds in $AzureADDevice.PhysicalIds | Where-Object {$_ -match 'ZTDID'}){
            $ZTDID = [System.Text.RegularExpressions.Regex]::Match($PhysicalIds,'\[ZTDID\]:(?<ztdid>.*)').Groups['ztdid'].value
        }

    }Else{

        Write-Host ("{0} " -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red -NoNewline
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-Host ("Unable to retrieve device in Azure by device name [{0}]" -f $DeviceName) -ForegroundColor Red
        Write-host ("REASON: If its an new device and it has been imported as Autopilot device, the device name should be the serial number and in Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Upload hash and rerun script!") -ForegroundColor Red
        Exit

    }

    #if the ztdid is there, it should match ap device id
    If($null -ne $ZTDID){
        Write-Host ("`n    |---Retrieving Autopilot ZTDID attribute from device object [{0}]..." -f $AzureADDevice.Id) -NoNewline:$noNewLine
        Try{
            $AutopilotDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/deviceManagement/windowsAutopilotDeviceIdentities/$ZTDID") 
        }Catch{

            Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
            Write-Verbose ("{0} " -f $_.Exception.Message)
            Write-host ("REASON: Your graph permissions are not allowing you to read Autopilot devices from Intune.") -ForegroundColor Red
            Write-host ("`nACTION: Ensure you have permissions [DeviceManagementManagedDevices.Read.All,DeviceManagementServiceConfig.Read.All] from graph and rerun script") -ForegroundColor Red
            Exit
        }

        If($null -ne $AutopilotDevice){
            Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
            Write-Host ("        |---ZTDID: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $ZTDID) -ForegroundColor Cyan
            IF([string]::IsNullOrEmpty($AutopilotDevice.groupTag)){
                Write-Host ("        |---Group tag: ") -ForegroundColor White -NoNewline
                Write-Host ("{0}" -f "none") -ForegroundColor Yellow
            }Else{
                Write-Host ("        |---Group tag: ") -ForegroundColor White -NoNewline
                Write-Host ("{0}" -f $AutopilotDevice.groupTag) -ForegroundColor Green
            }
        }Else{
            Write-Host ("{0} " -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red -NoNewline
            Write-Host ("Unable to determine if the device name [{0}] is registered as an Autopilot device" -f $DeviceName) -ForegroundColor Red
            Write-host ("REASON: If its an new device and it has been imported as Autopilot device, the device name should have a [ZTDID] as a PhysicalId attribute in Azure AD") -ForegroundColor Red
            Write-host ("`nACTION: Ensure device has this attribute and rerun script.") -ForegroundColor Red
            Exit

        }
    }Else{

        Write-Host ("{0} " -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red -NoNewline
        Write-Host ("Device [{0}] is not registered as an Autopilot device" -f $DeviceName) -ForegroundColor Red
        Write-host ("REASON: If its an new device and it has been imported as Autopilot device, the device name should have a [ZTDID] as a PhysicalId attribute in Azure AD") -ForegroundColor Red
        Write-host ("`nACTION: Ensure device has this attribute and rerun script.") -ForegroundColor Red
        Exit
    }


    Write-Host ("`n    |---Retrieving device name from Intune [{0}]..." -f $DeviceName) -NoNewline:$noNewLine
    Try{
        $IntuneDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'").Value
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-host ("REASON: Your graph permissions are not allowing you to read devices from Intune.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [DeviceManagementManagedDevices.Read.All,DeviceManagementConfiguration.Read.All] from graph and rerun script") -ForegroundColor Red
        Exit
    }

    If($IntuneDevice.count -eq 1){
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Host ("        |---Managed device id: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $IntuneDevice.id) -ForegroundColor Cyan
        If($IntuneDevice.ownerType -eq 'company'){
            Write-Host ("        |---Managed device type: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Corporate') -ForegroundColor Cyan
        }
        Else{
            Write-Host ("        |---Managed device Type: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Personal') -ForegroundColor Red
        }
        If( $IntuneDevice.userPrincipalName){
            Write-Host ("        |---Managed primary user: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $IntuneDevice.userPrincipalName) -ForegroundColor Green
        }Else{
            Write-Host ("        |---Managed primary user: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'none') -ForegroundColor Yellow
        }
    }Else{
        Write-Host ("{0} " -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow -NoNewline
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-Host ("Device does not exist in Intune, could be new device...") -ForegroundColor Yellow
    }
}

#check by serial
If ($PSCmdlet.ParameterSetName -eq "serial")
{
    Write-Host ("    |---Retrieving Autopilot device details from serial [{0}]..." -f $Serial) -NoNewline:$noNewLine

    Try{
        $AutopilotDevice = (Invoke-MgGraphRequest -Method GET `
            -Uri "$script:GraphEndpoint/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$Serial')").Value
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-host ("REASON: Your graph permissions are not allowing you to read Autopilot devices from Intune.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [DeviceManagementServiceConfig.Read.All] from graph and rerun script") -ForegroundColor Red
        Exit
    }
    
    If($AutopilotDevice.Count -eq 1){

        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Host ("        |---AzureAD Object Id: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $AutopilotDevice.azureAdDeviceId) -ForegroundColor Cyan
        If($AutopilotDevice.managedDeviceId -eq '00000000-0000-0000-0000-000000000000'){
            Write-Host ("        |---Intune device Id: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Not enrolled') -ForegroundColor Red

        }Else{
            Write-Host ("        |---Intune device Id: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $AutopilotDevice.managedDeviceId) -ForegroundColor Cyan
            $IntuneEnrolled = $true
        }
        IF([string]::IsNullOrEmpty($AutopilotDevice.groupTag)){
            Write-Host ("        |---Group tag: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f "none") -ForegroundColor Yellow
        }Else{
            Write-Host ("        |---Group tag: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $AutopilotDevice.groupTag) -ForegroundColor Green
        }

    }Else{

        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-Host ("`nUnable to retrieve Autopilot device from serial. Make sure the serial is correct and try again") -ForegroundColor Red
        Write-host ("`nACTION: Re-import hardware hash and rerun script.") -ForegroundColor Red
        Exit
    }

    Write-Host ("`n    |---Retrieving Azure AD device id [{0}]..." -f $AutopilotDevice.AzureAdDeviceId) -NoNewline:$noNewLine
    Try{
        $AzureADDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/devices?`$filter=deviceId eq '$($AutopilotDevice.AzureAdDeviceId)'").Value
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-host ("REASON: Your graph permissions are not allowing you to read devices from Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [Device.Read.All] from graph and rerun script") -ForegroundColor Red
        Exit
    }

    If($AzureADDevice.Count -eq 1){
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Host ("        |---Device Name: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f  $AzureADDevice.displayName) -ForegroundColor Cyan
        If( $AzureADDevice.deviceOwnership -eq 'Company'){
            Write-Host ("        |---Device Type: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Corporate') -ForegroundColor Cyan
        }
        Elseif([string]::IsNullOrEmpty($AzureADDevice.deviceOwnership)){
            Write-Host ("        |---Device Type: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Unknown') -ForegroundColor Yellow
        }
        Else{
            Write-Host ("        |---Device Type: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Personal') -ForegroundColor Red
        }
    }Else{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-Host ("Unable to retrieve device in Azure by device id [{0}]" -f $AutopilotDevice.AzureAdDeviceId) -ForegroundColor Red
        Write-host ("REASON: If its an new device and it has been imported as Autopilot device, the device name should be the serial number and in Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Re-import hardware hash and rerun script.") -ForegroundColor Red
        Exit
    }

    If($IntuneEnrolled){

        Write-Host ("`n    |---Retrieving device details from Intune [{0}]..." -f $AutopilotDevice.managedDeviceId) -NoNewline:$noNewLine
        Try{
            $IntuneDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/deviceManagement/managedDevices/$($AutopilotDevice.managedDeviceId)")
        }Catch{
            Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
            Write-Verbose ("{0} " -f $_.Exception.Message)
            Write-host ("REASON: Your graph permissions are not allowing you to read devices from Intune.") -ForegroundColor Red
            Write-host ("`nACTION: Ensure you have permissions [DeviceManagementManagedDevices.Read.All,DeviceManagementConfiguration.Read.All] from graph and rerun script") -ForegroundColor Red
            Exit
        }
        
        If($null -ne $IntuneDevice.count){
            Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
            Write-Host ("        |---Managed device id: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $IntuneDevice.id) -ForegroundColor Cyan
            If($IntuneDevice.ownerType -eq 'company'){
                Write-Host ("        |---Managed device type: ") -ForegroundColor White -NoNewline
                Write-Host ("{0}" -f 'Corporate') -ForegroundColor Green
            }
            Else{
                Write-Host ("        |---Managed device Type: ") -ForegroundColor White -NoNewline
                Write-Host ("{0}" -f 'Personal') -ForegroundColor Red
            }
            If( $IntuneDevice.userPrincipalName){
                Write-Host ("        |---Currently assigned primary user: ") -ForegroundColor White -NoNewline
                Write-Host ("{0}" -f $IntuneDevice.userPrincipalName) -ForegroundColor Green
            }Else{
                Write-Host ("        |---Currently assigned primary user: ") -ForegroundColor White -NoNewline
                Write-Host ("{0}" -f 'none') -ForegroundColor Yellow
            }

        }Else{

            Write-Host ("{0} " -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
            Write-Host ("        |---Managed device status: ") -ForegroundColor White -NoNewline
            Write-Host ("Not found. Could this be a new device?") -ForegroundColor Yellow

        }
    }
}

If($AzureADDevice.count -eq 1){

    # Get all Azure AD group the device is a member of
    #------------------------------------------------------------------------------------------
    Write-Host ("`n    |---Retrieving groups assigned to device object [{0}]..." -f $AzureADDevice.id) -NoNewline:$noNewLine
    $assignedDeviceGroups = @()
    Try{
        #$assignedDeviceGroups += (Invoke-MgGraphRequest -Method GET -Body (@{securityEnabledOnly=$false} | ConvertTo-Json) `
        #                        -Uri "$script:GraphEndpoint/beta/devices/$($AzureADDevice.id)/memberOf").Value
        $assignedDeviceGroups += (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/devices/$($AzureADDevice.id)/memberOf").Value
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-host ("REASON: Your graph permissions are not allowing you to read device groups from Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [Device.Read.All,Group.Read.All,GroupMember.Read.All] from graph and rerun script") -ForegroundColor Red
        Exit
    }

    If($assignedDeviceGroups.count -ge 1){
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
        Write-Host ("        |---Member of groups: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $assignedDeviceGroups.count) -ForegroundColor Cyan

        #iterate through each group id for name
        Foreach($Group in $assignedDeviceGroups){
            Write-Host ("            |---Group: ") -NoNewline -ForegroundColor Gray
            #check to see if any of the groups are dynamic groups using orderid
            If($Group.membershipRule -match '[ZTDID]' -or $Group.membershipRule -match "[OrderID]:$($AutopilotDevice.groupTag)"){
                Write-Host ("{0}" -f $Group.displayName) -ForegroundColor Green
            }Else{
                Write-Host ("{0}" -f $Group.displayName) -ForegroundColor White
            }
        }
    }Else{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    }

}Else{

    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-Host ("Device Name [{0}] was not found in Azure AD." -f $DeviceName) -ForegroundColor Red
    Write-host ("REASON: If the device is new, it should be imported as Autopilot device and the device name should be the serial number.") -ForegroundColor Red
    Write-host ("`nACTION: Ensure device has been registered to Autopilot.") -ForegroundColor Red
    Exit

}



# Get all deployment profiles and asssignments
#------------------------------------------------------------------------------------------
Write-Host ("`n    |---Retrieving all Autopilot deployment profiles and assignments...") -NoNewline:$noNewLine
Try{
    $DeploymentProfiles = (Invoke-MgGraphRequest -Method GET `
                                -Uri "$script:GraphEndpoint/beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$expand=assignments").Value
}Catch{
    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-Verbose ("{0} " -f $_.Exception.Message)
    Write-host ("REASON: Your graph permissions are not allowing you to read device groups from Azure AD.") -ForegroundColor Red
    Write-host ("`nACTION: Ensure you have permissions [DeviceManagementServiceConfig.Read.All] from graph and rerun script") -ForegroundColor Red
    Exit
}
$depProfileAssignments = @()
#TEST  $DepProfile = $DeploymentProfiles[2]
Foreach($DepProfile in $DeploymentProfiles){

    #TEST  $assignmentEntry = $DepProfile.assignments.target[0]
    foreach ($assignmentEntry in $DepProfile.assignments.target)
    {
        $assignmentValue = New-Object pscustomobject
        $assignmentValue | Add-Member -MemberType NoteProperty -Name Name -Value $DepProfile.DisplayName
        $assignmentValue | Add-Member -MemberType NoteProperty -Name profileId -Value $DepProfile.Id
        $assignmentValue | Add-Member -MemberType NoteProperty -Name dataType -Value $assignmentEntry.'@odata.type'
        if ($null -ne $assignmentEntry.deviceAndAppManagementAssignmentFilterType)
        {
            $assignmentValue | Add-Member -MemberType NoteProperty -Name TargetFilterType -Value $assignmentEntry.deviceAndAppManagementAssignmentFilterType.ToString()
        }
        $assignmentValue | Add-Member -MemberType NoteProperty -Name FilterId -Value $assignmentEntry.deviceAndAppManagementAssignmentFilterId
        $assignmentValue | Add-Member -MemberType NoteProperty -Name groupId -Value $assignmentEntry.groupId
        #add to collection
        $depProfileAssignments += $assignmentValue
    }
}

If($depProfileAssignments.count -gt 0){

    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---Deployment Profiles found: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $depProfileAssignments.count) -ForegroundColor Cyan

}Else{

    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-Host ("No Deployment profiles were found!") -ForegroundColor Red
    Write-host ("REASON: If there are no Autopilot deployment profiles created and assigned, the device will not be Autopilot ready!") -ForegroundColor Red
    Write-host ("`nACTION: Create an Autopilot deployment profile, assign it, and rerun script.") -ForegroundColor Red
    Exit

}


<#
Write-Host "    |---Checking if Autopilot device has been deployed before..." -NoNewline
If($AutopilotDevice.EnrollmentState -eq 'enrolled'){
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
}
#>

# Determine if device is assigned to a deployment profile
#------------------------------------------------------------------------------------------
Write-Host ("`n    |---Determining if deployment profile is assigned to device...") -NoNewline:$NoNewLine
$associatedAssignments = @()
#TEST $depProfileAssignment = $depProfileAssignments[0]
Foreach($depProfileAssignment in $depProfileAssignments){
    #determine to add or remove assignment based on target type
    switch($depProfileAssignment.dataType){
        '#microsoft.graph.groupAssignmentTarget' {
            If($depProfileAssignment.groupId -in $assignedDeviceGroups.Id){
                Write-Verbose ("Adding group id [{0}] to associated assignment list" -f $depProfileAssignment.groupId)
                $associatedAssignments += $depProfileAssignment
            }
        }

        '#microsoft.graph.exclusionGroupAssignmentTarget' {
            If($depProfileAssignment.groupId -in $assignedDeviceGroups.Id){
                Write-Verbose ("Excluding group id [{0}] from associated assignment list" -f $depProfileAssignment.groupId)
                $associatedAssignments = $associatedAssignments | Where-Object groupId -NotIn $assignedDeviceGroups.Id
            }
        }

        '#microsoft.graph.allDevicesAssignmentTarget' {
            Write-Verbose ("Adding [All devices] group to associated assignment list")
            $associatedAssignments += $depProfileAssignment
        }
    }#end switch
}

If($associatedAssignments.count -eq 1){
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---Deployment Profile: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $associatedAssignments.Name) -ForegroundColor Cyan
    Write-Host "        |---Deployment Profile join type: " -ForegroundColor White -NoNewline
    $HybridProfile = ($DeploymentProfiles | Where-Object DisplayName -eq $associatedAssignments.Name).AdditionalProperties.'@odata.type' -eq '#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile'
    If($HybridProfile){
        Write-Host "Hybrid Azure AD joined" -ForegroundColor Green
    }Else{
        Write-Host "Azure AD joined" -ForegroundColor Green
    }

}ElseIf($associatedAssignments.count -gt 1){

    Write-Host ("{0} {1} deployment profiles are associated" -f (Get-Symbol -Symbol WarningSign),$associatedAssignments.count) -ForegroundColor Yellow
    Write-Host ("Imported device hash has more than one associated deployment profile!") -ForegroundColor Yellow
    Write-host ("REASON: If a device has more than one deployment profile associated, it can cause an inconsistant Autopilot experience.") -ForegroundColor Yellow
    Write-host ("`nACTION: Assign device to a single deployment profile and rerun script.") -ForegroundColor Yellow

}Else{

    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-Host ("Unable to determine which Deployment profile is assigned!") -ForegroundColor Red
    Write-host ("REASON: If a device has no deployment profile associated, device will not be Autopilot ready.") -ForegroundColor Red
    Write-host ("`nACTION: Assign device to a single deployment profile and rerun script.") -ForegroundColor Red
    Exit
}



# If Hybrid, check to make sure only one domain join profile is assigned to device
#------------------------------------------------------------------------------------------

If($HybridProfile){
    Write-Host ("`n    |---Checking to make sure hybrid configuration profile is assigned...") -NoNewline:$NoNewLine
    Try{
        $domainJoinPolicies = (Invoke-MgGraphRequest -Method GET `
                            -Uri "$script:GraphEndpoint/beta/deviceManagement/deviceConfigurations?`$filter=(isof('microsoft.graph.windowsDomainJoinConfiguration'))&`$expand=assignments").Value
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-host ("REASON: Your graph permissions are not allowing you to read device configurations from Intune.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [DeviceManagementConfiguration.Read.All] from graph and rerun script") -ForegroundColor Red
        Exit
    }


    $hybridJoinPolicyAssignmentList = @()
    Foreach($domainJoinPolicy in $domainJoinPolicies){

        foreach ($assignmentEntry in $domainJoinPolicy.assignments.target)
        {
            $assignmentValue = New-Object pscustomobject
            $assignmentValue | Add-Member -MemberType NoteProperty -Name Name -Value $domainJoinPolicy.displayName
            $assignmentValue | Add-Member -MemberType NoteProperty -Name profileId -Value $domainJoinPolicy.Id
            $assignmentValue | Add-Member -MemberType NoteProperty -Name dataType -Value $assignmentEntry.'@odata.type'
            if ($null -ne $assignmentEntry.deviceAndAppManagementAssignmentFilterType)
            {
                $assignmentValue | Add-Member -MemberType NoteProperty -Name TargetFilterType -Value $assignmentEntry.deviceAndAppManagementAssignmentFilterType.ToString()
            }
            $assignmentValue | Add-Member -MemberType NoteProperty -Name FilterId -Value $assignmentEntry.deviceAndAppManagementAssignmentFilterId
            $assignmentValue | Add-Member -MemberType NoteProperty -Name groupId -Value $assignmentEntry.groupId
            #add to collection
            $hybridJoinPolicyAssignmentList += $assignmentValue
        }
    }

    $associatedAssignments = @()
    Foreach($haadjAssignment in $hybridJoinPolicyAssignmentList){
        #determine to add or remove assignment based on target type
        switch($haadjAssignment.dataType){
            '#microsoft.graph.groupAssignmentTarget' {
                If($haadjAssignment.groupId -in $assignedDeviceGroups.Id){
                    Write-Verbose ("Group id [{0}] is assigned to profile [{1}]" -f $haadjAssignment.groupId,$haadjAssignment.Name)
                    $associatedAssignments += $haadjAssignment
                }
            }

            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                If($haadjAssignment.groupId -in $assignedDeviceGroups.Id){
                    Write-Verbose ("Group id [{0}] is assigned as excluded; not counted for profile [{1}]" -f $haadjAssignment.groupId,$haadjAssignment.Name)
                    $associatedAssignments = $associatedAssignments | Where-Object groupId -NotIn $assignedDeviceGroups.Id
                }
            }

            '#microsoft.graph.allDevicesAssignmentTarget' {
                Write-Verbose ("Group [All devices] is assigned to profile [{0}]" -f $haadjAssignment.Name)
                $associatedAssignments += $haadjAssignment
            }
        }#end switch
    }


    If($associatedAssignments.count -eq 1){

        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
        Write-Host ("        |---Hybrid configuration profile: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $associatedAssignments.Name) -ForegroundColor Cyan

    }ElseIf($associatedAssignments.count -gt 1){

        Write-Host ("{0} {1} hybrid profiles are assigned" -f (Get-Symbol -Symbol WarningSign),$associatedAssignments.count) -ForegroundColor Red
        Write-Host ("Device assigned as Hybrid joined devices can only have one Hybrid join configuration profile assigned!") -ForegroundColor Red
        Write-host ("REASON: If a device has more than one configuration profile assigned, it can cause a conflict during Autopilot domain join process.") -ForegroundColor Red
        Write-host ("`nACTION: Assign device to a single configuration profile and rerun script.") -ForegroundColor Red
        Exit

    }Else{

        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Host ("Unable to determine if a Hybrid Join configuration profile is assigned!") -ForegroundColor Red
        Write-host ("REASON: If a device has no Hybrid Join configuration profile assigned, Autopilot will fail during deployment.") -ForegroundColor Red
        Write-host ("`nACTION: Assign device to a single configuration profile and rerun script.") -ForegroundColor Red
        Exit

    }
}




#5. Check if device is assigned an ESP and what are the apps assigned to it
#------------------------------------------------------------------------------------------
Write-Host ("`n    |---Checking if device is assigned an ESP configuration...") -NoNewline:$NoNewLine
Try{    
    $ESPProfiles = (Invoke-MgGraphRequest -Method GET `
                -Uri "$script:GraphEndpoint/beta/deviceManagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'windows10EnrollmentCompletionPageConfiguration'&`$expand=assignments").Value
    
}Catch{
    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-Verbose ("{0} " -f $_.Exception.Message)
    Write-host ("REASON: Your graph permissions are not allowing you to read device enrollment configurations from Intune.") -ForegroundColor Red
    Write-host ("`nACTION: Ensure you have permissions [DeviceManagementConfiguration.Read.All,DeviceManagementServiceConfig.Read.All] from graph and rerun script") -ForegroundColor Red
    Exit
}

$enrollmentAssignmentList = @()
Foreach($ESPProfile in $ESPProfiles){

    foreach ($assignmentEntry in $ESPProfile.assignments.target)
    {
        $assignmentValue = New-Object pscustomobject
        $assignmentValue | Add-Member -MemberType NoteProperty -Name Name -Value $ESPProfile.displayName
        $assignmentValue | Add-Member -MemberType NoteProperty -Name profileId -Value $ESPProfile.id
        $assignmentValue | Add-Member -MemberType NoteProperty -Name dataType -Value $assignmentEntry.'@odata.type'
        if ($null -ne $assignmentEntry.deviceAndAppManagementAssignmentFilterType)
        {
        $assignmentValue | Add-Member -MemberType NoteProperty -Name TargetFilterType -Value $assignmentEntry.deviceAndAppManagementAssignmentFilterType.ToString()
        }
        $assignmentValue | Add-Member -MemberType NoteProperty -Name FilterId -Value $assignmentEntry.deviceAndAppManagementAssignmentFilterId
        $assignmentValue | Add-Member -MemberType NoteProperty -Name groupId -Value $assignmentEntry.groupId
        #add to collection
        $enrollmentAssignmentList += $assignmentValue
    }
}

#$ESPGroupIds = $enrollmentAssignmentList.groupId | Select -Unique

$associatedAssignments = @()
Foreach($espAssignment in $enrollmentAssignmentList){
    #determine to add or remove assignment based on target type
    switch($espAssignment.dataType){
        '#microsoft.graph.groupAssignmentTarget' {
            If($espAssignment.groupId -in $assignedDeviceGroups.Id){
                Write-Verbose ("Group id [{0}] is assigned to app [{1}]" -f $espAssignment.groupId,$espAssignment.Name)
                $associatedAssignments += $espAssignment
            }
        }

        '#microsoft.graph.exclusionGroupAssignmentTarget' {
            If($espAssignment.groupId -in $assignedDeviceGroups.Id){
                Write-Verbose ("Group id [{0}] is assigned as excluded; not counted for app [{1}]" -f $espAssignment.groupId,$espAssignment.Name)
                $associatedAssignments = $associatedAssignments | Where-Object groupId -NotIn $assignedDeviceGroups.Id
            }
        }

        '#microsoft.graph.allDevicesAssignmentTarget' {
            Write-Verbose ("Group [All devices] is assigned to app [{0}]" -f  $espAssignment.Name)
            $associatedAssignments += $espAssignment
        }
    }#end switch
}

If($associatedAssignments.count -eq 1){
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---ESP: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $associatedAssignments.Name) -ForegroundColor Cyan
    $WinningESP = $ESPProfiles | Where-Object Id -eq $associatedAssignments.profileId
}ElseIf($associatedAssignments.count -ge 1){
    Write-Host ("{0} {1} ESP's are assigned" -f (Get-Symbol -Symbol WarningSign),$associatedAssignments.count) -ForegroundColor Yellow
    #iterate through each group id for name
    Foreach($esp in $associatedAssignments){
        $espDetails = $ESPProfiles | Where-Object Id -eq $esp.profileId
        $LatestPriority = $espDetails.Priority
        Write-Host ("        |---ESP: ") -ForegroundColor Gray -NoNewline
        Write-Host ("{0}" -f $espDetails.displayName) -ForegroundColor Green -NoNewline
        Write-Host (" [priority: ") -ForegroundColor Gray -NoNewline
        Write-Host ("{0}" -f $LatestPriority) -ForegroundColor Green -NoNewline
        Write-Host ("]") -ForegroundColor Gray

        If($espDetails.Priority -gt $LatestPriority){
            $LatestPriority = $espDetails.Priority
        }
    }
    $WinningESP = ($ESPProfiles | Where-Object Priority -eq $LatestPriority)
}Else{
    Write-Host ("{0} No ESP are assigned; using default" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
    $WinningESP = ($ESPProfiles | Where-Object Priority -eq 0)
}

#TEST $WinningESP = $ESPProfiles[1]
$EspAppsIds = $WinningESP.selectedMobileAppIds
Write-Host ("        |---Winning ESP: ") -ForegroundColor White -NoNewline
Write-Host ("{0}" -f $WinningESP.displayName) -ForegroundColor Cyan
If($EspAppsIds.Count -gt 0){
    Write-Host ("            |---Required apps found: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $EspAppsIds.Count) -ForegroundColor Cyan
}Else{
    Write-Host ("            |---No required apps found in ESP") -ForegroundColor White
}


#6. Check to see if one of those groups are assigned to the apps as required.
#------------------------------------------------------------------------------------------

If($EspAppsIds.count -gt 0){
    Write-Host ("`n    |---Checking if apps associated with winning ESP are assigned to Azure AD group(s)...") -NoNewline:$NoNewLine

    $appAssignmentList = @()

    #TEST $AppId = $EspAppsIds[0]
    Foreach($AppId in $EspAppsIds ){
        Try{
            $AppDetails = (Invoke-MgGraphRequest -Method GET `
                                -Uri "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps/$($AppId)?`$expand=assignments")
            
        }Catch{
            Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
            Write-Verbose ("{0} " -f $_.Exception.Message)
            Write-host ("REASON: Your graph permissions are not allowing you to read apps from Intune.") -ForegroundColor Red
            Write-host ("`nACTION: Ensure you have permissions [DeviceManagementApps.Read.All] from graph and rerun script") -ForegroundColor Red
            Exit
        }

        foreach ($assignmentEntry in $AppDetails.assignments)
        {
            $assignmentValue = New-Object pscustomobject
            $assignmentValue | Add-Member -MemberType NoteProperty -Name Name -Value $AppDetails.displayName
            $assignmentValue | Add-Member -MemberType NoteProperty -Name AppId -Value $AppId
            $assignmentValue | Add-Member -MemberType NoteProperty -Name Intent -Value $assignmentEntry.intent
            $assignmentValue | Add-Member -MemberType NoteProperty -Name dataType -Value $assignmentEntry.target.'@odata.type'
            if ($null -ne $assignmentEntry.target.deviceAndAppManagementAssignmentFilterType)
            {
            $assignmentValue | Add-Member -MemberType NoteProperty -Name TargetFilterType -Value $assignmentEntry.target.deviceAndAppManagementAssignmentFilterType.ToString()
            }
            $assignmentValue | Add-Member -MemberType NoteProperty -Name FilterId -Value $assignmentEntry.target.deviceAndAppManagementAssignmentFilterId
            $assignmentValue | Add-Member -MemberType NoteProperty -Name groupId -Value $assignmentEntry.target.groupId
            #add to collection
            $appAssignmentList += $assignmentValue
        }
    }
}


$associatedAssignments = @()
#TEST $appAssignment = $appAssignmentList[-1]
Foreach($appAssignment in $appAssignmentList){

    If($appAssignment.Intent -eq 'required'){
        #determine to add or remove assignment based on target type
        switch($appAssignment.dataType){
            '#microsoft.graph.groupAssignmentTarget' {
                If(-NOT($associatedAssignments | Where-Object Name -eq $appAssignment.Name)){
                    Write-Verbose ("Group id [{0}] is assigned as required for app [{1}]" -f $appAssignment.groupId,$appAssignment.Name)
                    $associatedAssignments += $appAssignment
                }
            }

            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                If($appAssignment.groupId -in $assignedDeviceGroups.Id){
                    Write-Verbose ("Group id [{0}] does not count for app [{1}]" -f $appAssignment.groupId,$appAssignment.Name)
                    $associatedAssignments = $associatedAssignments | Where-Object groupId -NotIn $assignedDeviceGroups.Id
                }
            }

            '#microsoft.graph.allDevicesAssignmentTarget' {
                Write-Verbose ("[All devices] group is assigned as required for app [{0}]" -f $appAssignment.Name)
                If(-NOT($associatedAssignments | Where-Object Name -eq $appAssignment.Name)){
                    $associatedAssignments += $appAssignment
                }
            }

            '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                Write-Verbose ("[All Users] group is assigned as required for app [{0}]" -f $appAssignment.Name)
                If(-NOT($associatedAssignments | Where-Object Name -eq $appAssignment.Name)){
                    $associatedAssignments += $appAssignment
                }
            }
        }#end switch
    }Else{
        Write-Verbose ("Group id [{0}] is assigned as {2} for app [{1}]" -f $appAssignment.groupId,$appAssignment.Name,$appAssignment.Intent)
    }

}


If($associatedAssignments.count -ne $EspAppsIds.count){
    Write-Host ("{0}" -f (Get-Symbol -Symbol WarningSign)) -ForegroundColor Yellow
    #Write-Host ("        |---Apps assigned as required: ") -ForegroundColor White -NoNewline
    #Write-Host ("{0} out of {1}" -f $associatedAssignments.count,$EspAppsIds.count) -ForegroundColor Yellow
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
}


#iterate through each group id for name
#TEST $app = $associatedAssignments[0]
#TEST $app = $associatedAssignments[-1]
Foreach($app in $associatedAssignments){

    Write-Host ("        |---App: ") -ForegroundColor Gray -NoNewline
    Write-Host ("{0}" -f $app.Name) -ForegroundColor Green


    If($app.dataType -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' ){
        Write-Host ("            |---Assigned to user group: ") -ForegroundColor White -NoNewline
        Write-Host ("All Users") -ForegroundColor Cyan
    }ElseIf($app.dataType -eq '#microsoft.graph.allDevicesAssignmentTarget'){
        Write-Host ("            |---Assigned to device group: ") -ForegroundColor White -NoNewline
        Write-Host ("All Devices") -ForegroundColor Cyan
    }
    Else{

        #get group name
        $Group = (Invoke-MgGraphRequest -Method GET `
                    -Uri "$script:GraphEndpoint/beta/groups/$($app.groupId)")

        #get group member types
        $GroupMembers = (Invoke-MgGraphRequest -Method GET `
                    -Uri "$script:GraphEndpoint/beta/groups/$($app.groupId)/members").Value
        If( $GroupMembers[0].'@odata.type' -eq '#microsoft.graph.user'){
            Write-Host ("            |---Assigned to user group: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $Group.displayName) -ForegroundColor Yellow
            $UserAssignedApps += $app
            $UserAssignedAppsGroups += $Group.displayName
        }Else{
            Write-Host ("            |---Assigned to device group: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $Group.displayName) -ForegroundColor Green
        }
    }
}

If($PSBoundParameters.ContainsKey('CheckUserLicense')){
    Write-Host ("`n    |---Attempting to retrieve license display names from Microsoft...") -NoNewline:$noNewLine
    Try{
        #REFERENCE: https://rakhesh.com/azure/m365-licensing-displayname-to-sku-name-mapping/
        $licenseCsvURL = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'

        $licenseHashTable = @{}
        (Invoke-WebRequest -Uri $licenseCsvURL).ToString() | ConvertFrom-Csv | ForEach-Object {
            $licenseHashTable[$_.GUID] = [ordered]@{
                "FriendlyDisplayName" = $_.Service_Plans_Included_Friendly_Names
                "ProductDisplayName" = $_.Product_Display_Name
                "SkuPartNumber" = $_.String_Id
            }
        }
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green

        Write-Host ("        |---Total License Skus found: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $licenseHashTable.count) -ForegroundColor Cyan
    }Catch{
        Write-Host ("{0}. {1}" -f (Get-Symbol -Symbol Information), $_.Exception.Message) -ForegroundColor Yellow
    }

    Write-Host ("`n    |---Retrieving Intune licenses from Azure tenant [{0}]..." -f $MGContext.TenantId) -NoNewline:$noNewLine
    Try{
        $LicenseSkus += (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/subscribedSkus").Value

        $IntuneLicenses = @()
        #test $License = $LicenseSkus[0]
        #test $License = $LicenseSkus[-1]
        Foreach($License in $LicenseSkus){
            $IntuneLicenseAvailable = $false
            $IntuneLicenseAvailable = ($License.servicePlans.servicePlanName -join '|') -match 'Intune'
            If($IntuneLicenseAvailable){
                $IntuneLicenses += $License
                Write-Verbose ("license: {0}" -f $License.skuPartNumber)
                Write-Verbose ("Service Plan: {0}" -f ($License.servicePlans.servicePlanName -join ','))
                Write-Verbose ("Intune Plan: {0}" -f $IntuneLicenseAvailable)
                Write-Verbose ("----------------------")
            }
        }

        If(($IntuneLicenses.skuId | Select-Object -Unique).Count -gt 0){
            Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
            #TEST $IntuneLicense = $IntuneLicenses[0]
            ForEach ($IntuneLicense in $IntuneLicenses){
                # determine license name
                If($licenseHashTable.count -gt 0){
                    $LicenseName = ($licenseHashTable[$IntuneLicense.skuId].GetEnumerator() | Where-Object Name -eq ProductDisplayName).Value
                }Else{
                    $LicenseName = $IntuneLicense.skuPartNumber
                }

                Write-Host ("        |---Available Intune service plan: ") -ForegroundColor Gray -NoNewline
                Write-Host ("{0}" -f $LicenseName ) -ForegroundColor Green

            }

        }Else{
            Write-Host ("{0}" -f (Get-Symbol -Symbol WarningSign)) -ForegroundColor Yellow
            Write-Host ("            |---Available Intune service plan: ") -ForegroundColor Gray -NoNewline
            Write-Host ("{0}" -f 'false') -ForegroundColor Red
        }
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
        Write-Host ("Unable to determine available Intune licenses") -ForegroundColor Yellow
        Write-host ("REASON: Your graph permissions are not allowing you to read licenses from Azure AD.") -ForegroundColor Yellow
        Write-host ("`nACTION: Ensure you have permissions [Directory.Read.All,Organization.Read.All] from graph and rerun script") -ForegroundColor Yellow
    }
}Else{
    #null out hashtable
    $licenseHashTable = @{}
}


If($UserPrincipalName)
{

    Write-Host ("`n    |---Retrieving account details for specified user principal name [{0}]..." -f $UserPrincipalName) -NoNewline:$noNewLine
    Try{
        #$PrimaryAssignedUser = (Invoke-MgGraphRequest -Method GET -Body (@{securityEnabledOnly=$false} | ConvertTo-Json) `
        #                    -Uri "$script:GraphEndpoint/beta/users?`$filter=userPrincipalName eq '$UserPrincipalName'&`$expand=memberOf").Value
        $PrimaryAssignedUser = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/users?`$filter=userPrincipalName eq '$UserPrincipalName'&`$expand=memberOf").Value
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
    }Catch{

        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-host ("REASON: Your graph permissions are not allowing you to read users from Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [User.Read.All] to read users from graph and rerun script") -ForegroundColor Red
        Exit
    }

}
# get details of current primary user if assigned
ElseIf($IntuneDevice.userPrincipalName)
{
    Write-Host ("`n    |---Retrieving account details for current primary user [{0}]..." -f $IntuneDevice.userPrincipalName) -NoNewline:$noNewLine
    Try{
        #$PrimaryAssignedUser = (Invoke-MgGraphRequest -Method GET -Body (@{securityEnabledOnly=$false} | ConvertTo-Json) `
        #                        -Uri "$script:GraphEndpoint/beta/users?`$filter=userPrincipalName eq '$($IntuneDevice.userPrincipalName)'&`$expand=memberOf").Value
        $PrimaryAssignedUser = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/users?`$filter=userPrincipalName eq '$($IntuneDevice.userPrincipalName)'&`$expand=memberOf").Value
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-Host ("Unable to retrieve user principal name from Azure [{0}]" -f $IntuneDevice.userPrincipalName) -ForegroundColor Red
        Write-host ("REASON: Your graph permissions are not allowing you to read users from Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [User.Read.All] to read users from graph and rerun script") -ForegroundColor Red
        Exit
    }

}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
    Write-Host ("`nNo user specified or primary user is found; unable to determine if Intune license is assigned...") -ForegroundColor Yellow
    Write-Host ("Continuing is risky; rerun this script with [-UserPrincipalName] parameter") -ForegroundColor Yellow
}


If($PrimaryAssignedUser.count -gt 0){
    #display user details
    If($PrimaryAssignedUser.onPremisesSamAccountName){
        Write-Host ("        |---SAM Login Name: ") -NoNewline -ForegroundColor Gray
        Write-Host ("{0}" -f $PrimaryAssignedUser.onPremisesSamAccountName) -ForegroundColor Cyan
    }
    Write-Host ("        |---User Display Name: ") -NoNewline -ForegroundColor Gray
    Write-Host ("{0}" -f $PrimaryAssignedUser.displayName) -ForegroundColor Cyan
    Write-Host ("        |---User Email Account: ") -NoNewline -ForegroundColor Gray
    Write-Host ("{0}" -f $PrimaryAssignedUser.mail) -ForegroundColor Cyan
    Write-Host ("        |---User is assigned to: ") -ForegroundColor White -NoNewline
    If($PrimaryAssignedUser.memberOf.count -gt 0){
        Write-Host ("{0}" -f $PrimaryAssignedUser.memberOf.count) -ForegroundColor Cyan -NoNewline
    }Else{
        Write-Host ("{0}" -f $PrimaryAssignedUser.memberOf.count) -ForegroundColor Red -NoNewline
    }
    Write-Host (" groups") -ForegroundColor White

    If($PSBoundParameters.ContainsKey('CheckUserLicense'))
    {
        Write-Host ("        |---User is assigned to ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $PrimaryAssignedUser.assignedLicenses.count) -ForegroundColor Cyan -NoNewline
        Write-Host (" licenses") -ForegroundColor White
    }


    Write-Host ("`n    |---Checking App group assignments for user [{0}]..." -f $PrimaryAssignedUser.userPrincipalName) -NoNewline
    #iterate through each group id for name
    If($UserAssignedApps.count -gt 0){
        Foreach($Group in $PrimaryAssignedUser.memberOf){

            #check to see if any of the groups are dynamic groups using orderid
            If($Group.id -in $appAssignmentList.groupId){
                Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
                Write-Host ("        |---User is assigned to the app assigned group: ") -NoNewline -ForegroundColor Gray
                Write-Host ("{0}" -f $Group.displayName) -ForegroundColor Cyan
                $AssignedToESPApp = $true
            }
        }

        If(!$AssignedToESPApp){
            Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
            Write-Host ("`nThe specified user [{0}] is not assigned to user apps in ESP." -f $PrimaryAssignedUser.userPrincipalName) -ForegroundColor Red
            Write-host ("REASON: If the user is not assigned the ESP apps: [{0}], Autopilot may fail or timeout." -f ($UserAssignedApps.Name -join ',')) -ForegroundColor Red
            Write-host ("`nACTION: Assign user to groups [{0}] and rerun script." -f ($UserAssignedAppsGroups -join ',')) -ForegroundColor Red
            Exit
        }
    }Else{
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
        Write-Host ("        |---ESP user group assignments to check: ") -NoNewline -ForegroundColor White
        Write-Host ("{0}" -f '0') -ForegroundColor Cyan
    }

}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-Host ("`nThe specified user [{0}] is not found in Azure." -f $UserPrincipalName) -ForegroundColor Red
    Write-host ("REASON: If the user doesn't exist, the appropiate user assignments cannot be detemermined and Autopilot will fail.") -ForegroundColor Red
    Write-host ("`nACTION: Change user principal name and rerun script.") -ForegroundColor Red
    Exit
}

If(($PrimaryAssignedUser.assignedLicenses.count -gt 0) -and $PSBoundParameters.ContainsKey('CheckUserLicense')){
    Write-Host ("`n    |---Checking Intune licenses for user [{0}]..." -f $PrimaryAssignedUser.userPrincipalName)
    Foreach($AssignedLicense in $PrimaryAssignedUser.assignedLicenses){

        # determine license name
        If($licenseHashTable.count -gt 0){
            $AssignedLicenseName = ($licenseHashTable[$AssignedLicense.skuId].GetEnumerator() | Where-Object Name -eq ProductDisplayName).Value
        }Else{
            $AssignedLicenseName = ($IntuneLicenses | Where-Object skuId -eq $AssignedLicense.skuId).skuPartNumber
        }

        # check if license is one of the Intune licenses
        If($AssignedLicense.skuId -in ($IntuneLicenses.skuId | Select-Object -Unique)){
            Write-Host ("        |---User is assigned an Intune license: ") -NoNewline -ForegroundColor Gray
            Write-Host ("{0}" -f $AssignedLicenseName) -ForegroundColor Green
            $AssignedToIntuneLicense = $true
        }Else{
            #Write-Host ("        |---Assigned license: ") -NoNewline -ForegroundColor Gray
            #Write-Host ("{0}" -f $AssignedLicenseName) -ForegroundColor White
        }

    }

    If(!$AssignedToIntuneLicense){
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-host ("The MDM Policy assigned group does not include the user [{0}]" -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
        Write-host ("REASON: If the specified user [{0}] is not assigned an Intune license; Autopilot will fail during enrollment" -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
        Write-host ("`nACTION: Assign the user an Intune license and rerun script.") -ForegroundColor Red
        Exit
    }
}

If($PSBoundParameters.ContainsKey('CheckAzureAdvSettings')){
    # Check Azure AD device join settings

    Write-Host ("`n    |---Checking Azure AD device join settings...") -NoNewline:$noNewLine
    Try{
        $AADRegistrationSettings = Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/policies/deviceRegistrationPolicy"
    }Catch{

        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-Host ("Unable to retrieve Join policies from Azure") -ForegroundColor Red
        Write-host ("REASON: Your graph permissions are not allowing you to read policies from Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [Policy.Read.All] from graph and rerun script") -ForegroundColor Red
        Exit
    }

    switch($AADRegistrationSettings.azureADJoin.appliesTo){
        '0' {
            Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
            Write-Host ("        |---Azure AD device join settings: ") -NoNewline -ForegroundColor Gray
            Write-Host ("{0}" -f 'None') -ForegroundColor Red
            $CheckAADGroup = $false
            $AADJoinAllowed = $false
        }

        '1' {
            Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
            Write-Host ("        |---Azure AD device join settings: ") -NoNewline -ForegroundColor Gray
            Write-Host ("{0}" -f 'All') -ForegroundColor Green
            $CheckAADGroup = $false
            $AADJoinAllowed = $true
        }

        '2' {
            Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
            Write-Host ("        |---Azure AD device join settings: ") -NoNewline -ForegroundColor Gray
            Write-Host ("{0}" -f 'Selected') -ForegroundColor Yellow
            $CheckAADGroup = $true
            $AADJoinAllowed = $false
        }
    }

    # check if user is in the allowed group
    If($CheckAADGroup){
        Foreach($Group in $PrimaryAssignedUser.memberOf){
            If($Group.id -in $AADRegistrationSettings.azureADJoin.allowedGroups){
                Write-Host ("        |---User is included in Azure AD join group: ") -ForegroundColor Gray -NoNewline:$noNewLine
                $Group = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/groups/$($Group.id)")
                Write-Host ("{0}" -f $Group.displayName ) -ForegroundColor Green

                $AADJoinAllowed = $true
            }
        }
    }

    If(!$AADJoinAllowed){
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-host ("The MDM Policy assigned group does not include the user [{0}]" -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
        Write-host ("REASON: If the user isn't part of the Azure AD join group, Autopilot device cannot join and will fail with error code: 801c03ed." -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
        Write-host ("`nACTION: Add user to Azure AD group in the device setting's join policy and rerun script." -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
        Exit
    }

    <#
            # Check Azure AD Conditional Access Policy
    Write-Host ("`n    |---Checking Conditional Access policy...") -NoNewline
    $ConditionalAccessPolicies = Invoke-MgGraphRequest -Method GET `
            -Uri "$script:GraphEndpoint/beta/policies/conditionalAccessPolicies"
    #>
}

# check MDM Policy
If($PrimaryAssignedUser -and $PSBoundParameters.ContainsKey('CheckUserLicense')){
    Write-Host ("`n    |---Checking MDM policy for user group...") -NoNewline:$noNewLine
    Try{
        $MDMPolicy = Invoke-MgGraphRequest -Method GET `
                        -Uri "$script:GraphEndpoint/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000?`$expand=includedGroups"
        #$MAMPolicy = Invoke-MgGraphRequest -Method GET `
        #    -Uri "$script:GraphEndpoint/beta/policies/mobileAppManagementPolicies/0000000a-0000-0000-c000-000000000000?`$expand=includedGroups"

    }Catch{

        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-Verbose ("{0} " -f $_.Exception.Message)
        Write-Host ("Unable to retrieve MDM policies from Azure") -ForegroundColor Red
        Write-host ("REASON: Your graph permissions are not allowing you to read policies from Azure AD.") -ForegroundColor Red
        Write-host ("`nACTION: Ensure you have permissions [Policy.Read.All] from graph and rerun script") -ForegroundColor Red
        Exit
    }

    Write-Verbose ("MDM policy assigned as: {0}" -f $MDMPolicy.appliesTo)
    switch ($MDMPolicy.appliesTo){
        'all' {
            Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
            $MDMPolicyAssigned = $true
        }
        'selected' {

            If($PrimaryAssignedUser){
                Foreach($Group in $PrimaryAssignedUser.memberOf){
                    If($Group.id -in $MDMPolicy.includedGroups.id){
                        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
                        Write-Host ("        |---User is included in group: ") -ForegroundColor Gray -NoNewline:$noNewLine
                        $Group = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/groups/$($Group.id)")
                        Write-Host ("{0}" -f $Group.displayName ) -ForegroundColor Green

                        $MDMPolicyAssigned = $true
                    }
                }
            }

            If(!$MDMPolicyAssigned){
                Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
                Write-host ("The MDM Policy assigned group does not include the user [{0}]" -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
                Write-host ("REASON: If the user isn't assigned the MDM policy, the Autopilot device cannot enroll into Intune and will fail." -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
                Write-host ("`nACTION: Add user to MDM policy and rerun script." -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
                Exit
            }
        }
        'none' {
            Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
            Write-host ("MDM Policy is not enabled!" -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
            Write-host ("Autopilot requires the MDM policy to be enabled and assigned" -f $PrimaryAssignedUser.UserPrincipalName) -ForegroundColor Red
            Write-host ("`nACTION: Change the MDM policy to [All] or [Some] and rerun script.") -ForegroundColor Red
            Exit
        }
        default{$MDMPolicyAssigned = $false}

    }

}

Write-Host ("`nAutopilot readiness completed!") -ForegroundColor Cyan -NoNewline
Write-Host ("`nScroll through the output and review any red or yellow!") -ForegroundColor Yellow