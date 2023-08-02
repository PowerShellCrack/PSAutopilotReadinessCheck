<#
    .SYNOPSIS
        Ensure device is Autopilot Ready

    .DESCRIPTION
        Autopilot readiness is to ensure the device is ready to be reset and Autopilot deployed
    
    .NOTES
        Author		: Dick Tracy <richard.tracy@hotmail.com>
	    Source		: https://github.com/PowerShellCrack/AutopilotTimeZoneSelectorUI
        Version		: 2.1.0
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

    .EXAMPLE
       .\AutoPilotReadiness.ps1 -Serial 'N4N0CX11Z173170'
    .EXAMPLE
        .\AutoPilotReadiness.ps1 -DeviceName 'DTOAAD-1Z156178'
    .EXAMPLE
        .\AutoPilotReadiness.ps1 -Serial 'N4N0CX11Z173170' -UserPrincipalName 'tracyr@contoso.com' -CheckUserLicense
    .EXAMPLE
        .\AutoPilotReadiness.ps1 -serial '8099-8675-7986-7060-0472-9892-02' -AzureEnvironment 'USGov'
#>
[CmdletBinding()]
Param(
    [ValidateSet('Public','USGov','USDoD')]
    [string]$AzureEnvironment = 'Public',  

    [Parameter(Mandatory = $true,ParameterSetName='device')]
    [string]$DeviceName,

    [Parameter(Mandatory = $true,ParameterSetName='serial')]
    [string]$Serial,

    [string]$UserPrincipalName,

    [switch]$CheckUserLicense
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
        Write-Error "Autopilot is not available in USgov environment. Exiting script..."
        Exit
    }
    'USDoD' {$script:GraphEndpoint = 'https://dod-graph.microsoft.us';$GraphEnvironment = "USGovDoD"
        Write-Error "Autopilot is not available in USDod environment. Exiting script..."
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
    Write-Host ("        |---[{0} of {1}]: Installing module {2}..." -f $i,$Modules.count,$Module) -NoNewline
    #Write-Host ('{0}{1}' -f $msg,(Set-GapCharacter -MessageLength $msg.Length)) -NoNewline

    if ( Get-Module -FullyQualifiedName $Module -ListAvailable ) {
        Write-Host ("already installed") -ForegroundColor Green
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
        'User.ReadBasic.All'
        'User.Read.All'
        'DeviceManagementApps.Read.All'
        'DeviceManagementConfiguration.Read.All'
        'DeviceManagementManagedDevices.Read.All'
        'DeviceManagementServiceConfig.Read.All'
        'DeviceManagementManagedDevices.Read.All'
        'DeviceManagementRBAC.Read.All'
    )

    If($PSBoundParameters.ContainsKey('CheckUserLicense')){
        $Scopes += @(
            'Organization.Read.All'
            'Policy.Read.All'
        )
    }

    $null = Connect-MgGraph -Environment $GraphEnvironment -Scopes $Scopes -Verbose:$false
    $MGContext = Get-MgContext
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---Connected as: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $MGContext.Account) -ForegroundColor Cyan

}Catch{

    Write-Host ("{0}`n{1}" -f (Get-Symbol -Symbol RedX), $_.Exception.Message) -ForegroundColor Red
    Write-error "        Unable to connect to tenant. Can't continue!"

}


Write-Host ("`nStarting Autopilot readiness check...") -ForegroundColor Cyan
# 1. Check if device is enrolled as Autopilot Device
#------------------------------------------------------------------------------------------
#check by name
If ($PSCmdlet.ParameterSetName -eq "device")
{
    Write-Host ("    |---Retrieving device name from Azure AD [{0}]..." -f $DeviceName) -NoNewline
    $AzureADDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/devices?`$filter=displayName eq '$DeviceName'").Value

    If($null -ne $AzureADDevice){
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Host ("        |---AzureAD Object id: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $AzureADDevice.Id) -ForegroundColor Cyan
        Write-Host ("`n    |---Retrieving Autopilot ZTDID attribute from device object [{0}]..." -f $AzureADDevice.Id) -NoNewline
        #iterate through each PhysicalIds to get Autopilot one
        Foreach($PhysicalIds in $AzureADDevice.PhysicalIds | where {$_ -match 'ZTDID'}){
            $ZTDID = [System.Text.RegularExpressions.Regex]::Match($PhysicalIds,'\[ZTDID\]:(?<ztdid>.*)').Groups['ztdid'].value
        }
        
    }Else{
        
        Write-Host ("{0} " -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red -NoNewline
        Write-Host ("Unable to retrieve device in Azure by device name [{0}] `
        `nIf its an new device and it has been imported as Autopilot device, the device name should be the serial number and in Azure AD. `
        `rACTION: Upload hash and rerun script to continue!" -f $DeviceName) -ForegroundColor Red
        Exit

    }
    
    #if the ztdid is there, it should match ap device id
    If($null -ne $ZTDID){

        Try{

            $AutopilotDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/deviceManagement/windowsAutopilotDeviceIdentities/$ZTDID")
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

        }Catch{

            Write-Host ("{0} " -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red -NoNewline
            Write-Host ("Unable to determine if the device name [{0}] is registered as an Autopilot device `
            `nIf its an new device and it has been imported as Autopilot device, the device name should have a [ZTDID] as a PhysicalId attribute in Azure AD `
            `rACTION: Ensure device has this attribute and rerun script to continue." -f $DeviceName) -ForegroundColor Red
            Exit

        }
     
    }Else{

        Write-Host ("{0} " -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red -NoNewline
        Write-Host ("Device [{0}] is not registered as an Autopilot device `
        `nIf its an new device and it has been imported as Autopilot device, the device name should have a [ZTDID] as a PhysicalId attribute in Azure AD `
        `rACTION: Ensure device has this attribute and rerun script to continue." -f $DeviceName) -ForegroundColor Red
        Exit
    }
    

    Write-Host ("`n    |---Retrieving device name from Intune [{0}]..." -f $DeviceName) -NoNewline
    Try{

        $IntuneDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'").Value
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
            Write-Host ("        |---Managed primary user: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $IntuneDevice.userPrincipalName) -ForegroundColor Green
        }Else{
            Write-Host ("        |---Managed primary user: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'none') -ForegroundColor Yellow
        }

    }Catch{

        Write-Host ("{0} " -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow -NoNewline -NoNewline
        Write-Host ("Device does not exist in Intune, could be new device...") -ForegroundColor Yellow
    }
}

#check by serial
If ($PSCmdlet.ParameterSetName -eq "serial")
{
    Write-Host ("    |---Retrieving Autopilot device details from serial [{0}]..." -f $Serial) -NoNewline

    $AutopilotDevice = (Invoke-MgGraphRequest -Method GET `
                                -Uri "$script:GraphEndpoint/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$Serial')").Value
    If($null -ne $AutopilotDevice){

        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Host ("        |---AzureAD Object Id: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $AutopilotDevice.azureAdDeviceId) -ForegroundColor Cyan
        If($AutopilotDevice.managedDeviceId -eq '00000000-0000-0000-0000-000000000000'){
            Write-Host ("        |---Intune device Id: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Not enrolled') -ForegroundColor Red
            
        }Else{
            Write-Host ("        |---Intune device Id: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $AutopilotDevice.managedDeviceId) -ForegroundColor Green
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

        Write-Host ("{0}`n{1}" -f (Get-Symbol -Symbol RedX), $_.Exception.Message) -ForegroundColor Red
        Write-Host ("`nUnable to retrieve Autopilot device from serial. Make sure the serial is correct and try again `
        `rACTION: Re-import hash and rerun script to continue." -f $AutopilotDevice.AzureAdDeviceId) -ForegroundColor Red
        Exit
    }
    
    Write-Host ("`n    |---Retrieving Azure AD device id [{0}]..." -f $AutopilotDevice.AzureAdDeviceId) -NoNewline
    Try{

        $AzureADDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/devices?`$filter=deviceId eq '$($AutopilotDevice.AzureAdDeviceId)'").Value

        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Host ("        |---Device Name: ") -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f  $AzureADDevice.displayName) -ForegroundColor Cyan
        If( $AzureADDevice.deviceOwnership -eq 'Company'){
            Write-Host ("        |---Device Type: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Corporate') -ForegroundColor Green
        }
        Elseif([string]::IsNullOrEmpty($AzureADDevice.deviceOwnership)){
            Write-Host ("        |---Device Type: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Unknown') -ForegroundColor Yellow
        }
        Else{
            Write-Host ("        |---Device Type: ") -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f 'Personal') -ForegroundColor Red
        }

    }Catch{

        Write-Host ("{0}`n{1}" -f (Get-Symbol -Symbol RedX), $_.Exception.Message) -ForegroundColor Red
        Write-Host ("Unable to retrieve device in Azure by device id [{0}] `
        `nIf its an new device and it has been imported as Autopilot device, the device name should be the serial number and in Azure AD. `
        `rACTION: Re-import hash and rerun script to continue." -f $AutopilotDevice.AzureAdDeviceId) -ForegroundColor Red
        Exit

    }

    If($IntuneEnrolled){

        Write-Host ("`n    |---Retrieving device name from Intune [{0}]..." -f $AutopilotDevice.managedDeviceId) -NoNewline
        Try{
            $IntuneDevice = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/deviceManagement/managedDevices/$($AutopilotDevice.managedDeviceId)")
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

        }Catch{
            
            Write-Host ("{0} " -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow -NoNewline
            Write-Host "Device does not exist in Intune, could be new device..." -ForegroundColor Yellow

        }
    }
}

If($null -ne $AzureADDevice){

    # Get all Azure AD group the device is a member of
    #------------------------------------------------------------------------------------------
    Write-Host ("`n    |---Retrieving groups assigned to device object [{0}]..." -f $AzureADDevice.id) -NoNewline
    $assignedDeviceGroups = @()
    #$assignedDeviceGroups += (Invoke-MgGraphRequest -Method GET -Body (@{securityEnabledOnly=$false} | ConvertTo-Json) `
    #                        -Uri "$script:GraphEndpoint/beta/devices/$($AzureADDevice.id)/memberOf").Value
    $assignedDeviceGroups += (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/devices/$($AzureADDevice.id)/memberOf").Value

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

}ELse{

    Write-Host ("{0} " -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red -NoNewline
    Write-Host ("Device [{0}] is not found in Azure AD. `
    `nIf the device is new, it should be imported as Autopilot device and the device name should be the serial number. `
    `rACTION: Ensure device has been registered to Autopilot." -f $DeviceName) -ForegroundColor Red
    Exit

}



# Get all deployment profiles and asssignments
#------------------------------------------------------------------------------------------
Write-Host "`n    |---Retrieving all Autopilot deployment profiles and assignments..." -NoNewline
$DeploymentProfiles = (Invoke-MgGraphRequest -Method GET `
                        -Uri "$script:GraphEndpoint/beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$expand=assignments").Value

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
    Write-error "No Deployment profiles were found! `
    `nThere must be at least one Deployment profile created and assigned for a device to be Autopilot ready
    `rACTION: Create a Deployment profile, assign it, and rerun script to continue."
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
Write-Host "`n    |---Determining if deployment profile is assigned to device..." -NoNewline:$NoNewLine
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
                $associatedAssignments = $associatedAssignments | Where groupId -NotIn $assignedDeviceGroups.Id 
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
    $HybridProfile = ($DeploymentProfiles | Where DisplayName -eq $associatedAssignments.Name).AdditionalProperties.'@odata.type' -eq '#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile'
    If($HybridProfile){
        Write-Host "Hybrid Azure AD joined" -ForegroundColor Green
    }Else{
        Write-Host "Azure AD joined" -ForegroundColor Green
    }

}ElseIf($associatedAssignments.count -gt 1){
    Write-Host ("{0} {1} deployment profiles are associated" -f (Get-Symbol -Symbol WarningSign),$associatedAssignments.count) -ForegroundColor Yellow
    Write-error "Imported device hash has more than one associated Deployment profile! `
    `nIf a device has more than one deployment profile associated, it can cause inconsistant Autopilot experience.
    `rACTION: Assign device to a single deployment profile and rerun script to continue."
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-error "Unable to determine which Deployment profile is assigned! `
    `nIf a device has no deployment profile associated, Autopilot will not work correctly.
    `rACTION: Assign device to a single deployment profile and rerun script to continue."
}



# If Hybrid, check to make sure only one domain join profile is assigned to device
#------------------------------------------------------------------------------------------

If($HybridProfile){
    Write-Host "`n    |---Checking to make sure hybrid configuration profile is assigned..." -NoNewline:$NoNewLine
    $domainJoinPolicies = (Invoke-MgGraphRequest -Method GET `
                            -Uri "$script:GraphEndpoint/beta/deviceManagement/deviceConfigurations?`$filter=(isof('microsoft.graph.windowsDomainJoinConfiguration'))&`$expand=assignments").Value
                        
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
                    $associatedAssignments = $associatedAssignments | Where groupId -NotIn $assignedDeviceGroups.Id 
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
        Write-error "Device assinged as Hybrid joined devices can only have one Hybrid joine configuration profile assigned! `
        `nIf a device has more than one configuration profile assigned, it can cause a conflict during Autopilot domain join process.
        `rACTION: Assign device to a single configuration profile and rerun script to continue."
    }Else{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-error "Unable to determine if a Hybrid Join configuration profile is assigned! `
        `nIf a device has no Hybrid Join configuration profile assigned, Autopilot will fail during deployment.
        `rACTION: Assign device to a single configuration profile and rerun script to continue."
    }
}




#5. Check if device is assigned an ESP and what are the apps assigned to it
#------------------------------------------------------------------------------------------
Write-Host "`n    |---Checking if device is assigned an ESP configuration..." -NoNewline:$NoNewLine
$ESPProfiles = (Invoke-MgGraphRequest -Method GET `
                    -Uri "$script:GraphEndpoint/beta/deviceManagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'windows10EnrollmentCompletionPageConfiguration'&`$expand=assignments").Value
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
                $associatedAssignments = $associatedAssignments | Where groupId -NotIn $assignedDeviceGroups.Id 
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
    $WinningESP = $ESPProfiles | Where Id -eq $associatedAssignments.profileId
}ElseIf($associatedAssignments.count -ge 1){
    Write-Host ("{0} {1} ESP's are assigned" -f (Get-Symbol -Symbol WarningSign),$associatedAssignments.count) -ForegroundColor Yellow
    #iterate through each group id for name
    Foreach($esp in $associatedAssignments){
        $espDetails = $ESPProfiles | Where Id -eq $esp.profileId
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
    $WinningESP = ($ESPProfiles | Where Priority -eq $LatestPriority)
}Else{
    Write-Host ("{0} No ESP are assigned; using default" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
    $WinningESP = ($ESPProfiles | Where Priority -eq 0)
}

#TEST $WinningESP = $ESPProfiles[1]
$EspAppsIds = $WinningESP.selectedMobileAppIds
Write-Host ("        |---Winning ESP: " ) -ForegroundColor White -NoNewline
Write-Host ("{0}" -f $WinningESP.displayName) -ForegroundColor Cyan
Write-Host ("            |---Found: " ) -ForegroundColor White -NoNewline
Write-Host ("{0}" -f $EspAppsIds.Count) -ForegroundColor Cyan -NoNewline
Write-Host (" apps are required during ESP" ) -ForegroundColor White



#6. Check to see if one of those groups are assigned to the apps as required.
#------------------------------------------------------------------------------------------

If($EspAppsIds.count -gt 0){
    Write-Host "`n    |---Checking if apps associated with winning ESP are assigned as [required]..." -NoNewline:$NoNewLine

    $appAssignmentList = @()

    #TEST $AppId = $EspAppsIds[0]
    Foreach($AppId in $EspAppsIds ){
        $AppDetails = (Invoke-MgGraphRequest -Method GET `
                    -Uri "$script:GraphEndpoint/beta/deviceAppManagement/mobileApps/$($AppId)?`$expand=assignments")

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
                If(-NOT($associatedAssignments | Where Name -eq $appAssignment.Name)){
                    Write-Verbose ("Group id [{0}] is assigned as required for app [{1}]" -f $appAssignment.groupId,$appAssignment.Name) 
                    $associatedAssignments += $appAssignment
                }
            }

            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                If($appAssignment.groupId -in $assignedDeviceGroups.Id){
                    Write-Verbose ("Group id [{0}] does not count for app [{1}]" -f $appAssignment.groupId,$appAssignment.Name)  
                    $associatedAssignments = $associatedAssignments | Where groupId -NotIn $assignedDeviceGroups.Id 
                }
            }

            '#microsoft.graph.allDevicesAssignmentTarget' {
                Write-Verbose ("[All devices] group is assigned as required for app [{0}]" -f $appAssignment.Name)   
                If(-NOT($associatedAssignments | Where Name -eq $appAssignment.Name)){
                    $associatedAssignments += $appAssignment
                }
            }

            '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                Write-Verbose ("[All Users] group is assigned as required for app [{0}]" -f $appAssignment.Name)  
                If(-NOT($associatedAssignments | Where Name -eq $appAssignment.Name)){
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
        Write-Host ("            |---Assigned to user group: " ) -ForegroundColor White -NoNewline
        Write-Host ("All Users") -ForegroundColor Green
    }ElseIf($app.dataType -eq '#microsoft.graph.allDevicesAssignmentTarget'){
        Write-Host ("            |---Assigned to device group: " ) -ForegroundColor White -NoNewline
        Write-Host ("All Devices") -ForegroundColor Green
    }
    Else{
        
        #get group name
        $Group = (Invoke-MgGraphRequest -Method GET `
                    -Uri "$script:GraphEndpoint/beta/groups/$($app.groupId)")
        #get group member types
        $GroupMembers = (Invoke-MgGraphRequest -Method GET `
                    -Uri "$script:GraphEndpoint/beta/groups/$($app.groupId)/members").Value
        If( $GroupMembers[0].'@odata.type' -eq '#microsoft.graph.user'){
            Write-Host ("            |---Assigned to user group: " ) -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $Group.displayName) -ForegroundColor Yellow
            $UserAssignedApps += $app
            $UserAssignedAppsGroups += $Group.displayName
        }Else{
            Write-Host ("            |---Assigned to device group: " ) -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $Group.displayName) -ForegroundColor Green
        }
    }
}

If($PSBoundParameters.ContainsKey('CheckUserLicense')){
    Write-Host ("`n    |---Attempting to retrieve license display names from Microsoft...") -ForegroundColor Gray -NoNewline 
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

        Write-Host ("        |---Parsed: " ) -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $licenseHashTable.count) -ForegroundColor Cyan -NoNewline
        Write-Host (" license skus" ) -ForegroundColor White
    }Catch{
        Write-Host ("{0}. {1}" -f (Get-Symbol -Symbol Information), $_.Exception.Message) -ForegroundColor Yellow
    }

    Write-Host ("`n    |---Retrieving Intune licenses from Azure tenant [{0}]..." -f $MGContext.TenantId) -NoNewline
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

        If(($IntuneLicenses.skuId | Select -Unique).Count -gt 0){    
            Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
            #TEST $IntuneLicense = $IntuneLicenses[0]
            ForEach ($IntuneLicense in $IntuneLicenses){
                # determine license name
                If($licenseHashTable.count -gt 0){
                    $LicenseName = ($licenseHashTable[$IntuneLicense.skuId].GetEnumerator() | Where Name -eq ProductDisplayName).Value
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
        Write-Host ("Unable to determine available Intune licenses `
        `nIf the enrolling user are note assigned the appropiate Intune licenses, Autopilot will fail.") -ForegroundColor Yellow
    }
}Else{
    #null out hashtable
    $licenseHashTable = @{}
}


If($UserPrincipalName)
{

    Write-Host ("`n    |---Retrieving account details for specified user principal name [{0}]..." -f $UserPrincipalName) -NoNewline
    Try{
        #$PrimaryAssignedUser = (Invoke-MgGraphRequest -Method GET -Body (@{securityEnabledOnly=$false} | ConvertTo-Json) `
        #                    -Uri "$script:GraphEndpoint/beta/users?`$filter=userPrincipalName eq '$UserPrincipalName'&`$expand=memberOf").Value
        $PrimaryAssignedUser = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/users?`$filter=userPrincipalName eq '$UserPrincipalName'&`$expand=memberOf").Value
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))                      

    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-error ("Unable to retrieve user principal name from Azure [{0}] `
        `nIf the user doesn't exist, the appropiate Intune licenses cannot be assigned and Autopilot will fail. `
        `rACTION: Change user principal name and rerun script to continue." -f $UserPrincipalName)
    }

}
ElseIf($IntuneDevice.userPrincipalName)
{

    Write-Host ("`n    |---Retrieving account details for current primary user [{0}]..." -f $IntuneDevice.userPrincipalName) -NoNewline
    Try{
        #$PrimaryAssignedUser = (Invoke-MgGraphRequest -Method GET -Body (@{securityEnabledOnly=$false} | ConvertTo-Json) `
        #                        -Uri "$script:GraphEndpoint/beta/users?`$filter=userPrincipalName eq '$($IntuneDevice.userPrincipalName)'&`$expand=memberOf").Value
        $PrimaryAssignedUser = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/users?`$filter=userPrincipalName eq '$($IntuneDevice.userPrincipalName)'&`$expand=memberOf").Value
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))        
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-error ("Unable to retrieve user principal name from Azure [{0}] `
        `nIf the user doesn't exist, the appropiate Intune licenses cannot be assigned and Autopilot will fail. `
        `rACTION: User principal name and rerun script to continue." -f $IntuneDevice.userPrincipalName)
    }                     
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
    Write-Host "No user specified or primary user is found; unable to determine if Intune license is assigned..." -ForegroundColor Yellow
}   


If($PrimaryAssignedUser.memberOf.count -gt 0){
    #display user details
    If($PrimaryAssignedUser.onPremisesSamAccountName){
        Write-Host ("        |---Login Name: ") -NoNewline -ForegroundColor Gray
        Write-Host ("{0}" -f $PrimaryAssignedUser.onPremisesSamAccountName) -ForegroundColor Yellow
    }
    Write-Host ("        |---User Display Name: ") -NoNewline -ForegroundColor Gray
    Write-Host ("{0}" -f $PrimaryAssignedUser.displayName) -ForegroundColor Yellow
    Write-Host ("        |---User Email Account: ") -NoNewline -ForegroundColor Gray
    Write-Host ("{0}" -f $PrimaryAssignedUser.mail) -ForegroundColor Yellow
    Write-Host ("        |---User is assigned to " ) -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $PrimaryAssignedUser.memberOf.count) -ForegroundColor Cyan -NoNewline
    Write-Host (" groups" ) -ForegroundColor White
    
    If($PSBoundParameters.ContainsKey('CheckUserLicense'))
    {
        Write-Host ("        |---User is assigned to " ) -ForegroundColor White -NoNewline
        Write-Host ("{0}" -f $PrimaryAssignedUser.assignedLicenses.count) -ForegroundColor Cyan -NoNewline
        Write-Host (" licenses" ) -ForegroundColor White
    }
    
    
    Write-Host ("`n    |---Checking group assignments for user [{0}]..." -f $PrimaryAssignedUser.userPrincipalName) -NoNewline
    #iterate through each group id for name
    If($UserAssignedApps.count -gt 0){
        Foreach($Group in $PrimaryAssignedUser.memberOf){
        
            #check to see if any of the groups are dynamic groups using orderid
            If($Group.id -in $appAssignmentList.groupId){
                Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) 
                Write-Host ("        |---User is assigned to the app assigned group: ") -NoNewline -ForegroundColor Gray
                Write-Host ("{0}" -f $Group.displayName) -ForegroundColor Yellow
                $AssignedToESPApp = $true
            }
        }
    
        If(!$AssignedToESPApp){
            Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
            Write-Error ("`nThe specified user [{0}] is not assigned to user apps in ESP. `
            `nIf the user is not assigned the ESP apps: [{1}], Autopilot may fail or timeout. `
            `rACTION: Assign user to groups [{2}] and rerun script to continue." -f $PrimaryAssignedUser.userPrincipalName,($UserAssignedApps.Name -join ','),($UserAssignedAppsGroups -join ','))
        }
    }Else{
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) 
        Write-Host ("        |---ESP user group assignments to check: ") -NoNewline -ForegroundColor White
        Write-Host ("{0}" -f '0') -ForegroundColor Yellow
    }
    
}

If(($PrimaryAssignedUser.assignedLicenses.count -gt 0) -and $PSBoundParameters.ContainsKey('CheckUserLicense')){
    Write-Host ("`n    |---Checking Intune licenses for user [{0}]..." -f $PrimaryAssignedUser.userPrincipalName)
    Foreach($AssignedLicense in $PrimaryAssignedUser.assignedLicenses){

        # determine license name
        If($licenseHashTable.count -gt 0){
            $AssignedLicenseName = ($licenseHashTable[$AssignedLicense.skuId].GetEnumerator() | Where Name -eq ProductDisplayName).Value
        }Else{
            $AssignedLicenseName = ($IntuneLicenses | Where skuId -eq $AssignedLicense.skuId).skuPartNumber 
        }
        
        # check if license is one of the Intune licenses
        If($AssignedLicense.skuId -in ($IntuneLicenses.skuId | Select -Unique)){
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
        Write-Error ("`nThe specified user [{0}] is not assigned an Intune license; Autopilot will fail during enrollment" -f $PrimaryAssignedUser.userPrincipalName)
    }
}


# check MDM Policy
If($PrimaryAssignedUser -and $PSBoundParameters.ContainsKey('CheckUserLicense')){
    Write-Host ("`n    |---Checking MDM policy for user group...") -NoNewline
    $MDMPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri "$script:GraphEndpoint/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000?`$expand=includedGroups"

    #$MAMPolicy = Invoke-MgGraphRequest -Method GET `
    #        -Uri "$script:GraphEndpoint/beta/policies/mobileAppManagementPolicies/0000000a-0000-0000-c000-000000000000?`$expand=includedGroups"

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
                        Write-Host ("        |---User is included in group: ") -ForegroundColor Gray -NoNewline 
                        $Group = (Invoke-MgGraphRequest -Method GET -Uri "$script:GraphEndpoint/beta/groups/$($Group.id)")
                        Write-Host ("{0}" -f $Group.displayName ) -ForegroundColor Yellow

                        $MDMPolicyAssigned = $true
                    }
                }
            }

            If(!$MDMPolicyAssigned){
                Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
                Write-error ("The MDM Policy assigne group does not include the user [{0}] `
                `nIf the user isn't assigned the MDM policy, the Autopilot device cannot enroll into Intune and will fail. `
                `rACTION: Add user to MDM policy and rerun script to continue." -f $PrimaryAssignedUser.UserPrincipalName)
            }
        }
        'none' { 
            Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
            Write-error ("MDM Policy is not enabled! `
            `nAutopilot requires the MDM policy to be enabled and assigned `
            `rACTION: Change the MDM policy to [All] or [Some] and rerun script to continue.")
        }
        default{$MDMPolicyAssigned = $false}

    }

    
}

Write-Host ("`nAutopilot readiness completed!") -ForegroundColor Cyan

If($UserAssignedApps.count -gt 0){
    If($PrimaryAssignedUser){
        Write-Host ("`nNOTE: If the user enrolling this device during Autopilot is not the user [{0}]; additional checks must be done for that user" -f $PrimaryAssignedUser.userPrincipalName) -ForegroundColor Yellow
    }Else{
        Write-Host ("`nNOTE: User app(s) detected in ESP: [{0}]`nThe user enrolling the device must be assigned to to these apps as [required] for Autopilot to complete successfully" -f ($UserAssignedApps.Name -join ',')) -ForegroundColor Yellow
    }
    
}