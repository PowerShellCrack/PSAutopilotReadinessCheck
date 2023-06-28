<#
    .SYNOPSIS
        Ensure device is Autopilot Ready

    .DESCRIPTION
        Autopilot readiness is to ensure the device is ready to be reset and Autopilot deployed
    
    .NOTES
        Author		: Dick Tracy <richard.tracy@hotmail.com>
	    Source		: https://github.com/PowerShellCrack/AutopilotTimeZoneSelectorUI
        Version		: 1.0.0
        README      : Review README.md for more details and configurations
        CHANGELOG   : Review CHANGELOG.md for updates and fixes
        IMPORTANT   : By using this script or parts of it, you have read and accepted the DISCLAIMER.md and LICENSE agreement

    .PARAMETER Serial
        Specify the serial number of a device.
    
    .PARAMETER DeviceName
        Specify the deviceName to check against. 

    .EXAMPLE
       .\AutoPilotReadiness.ps1 -Serial 'N4N0CX11Z173170'

    .EXAMPLE
        .\AutoPilotReadiness.ps1 -DeviceName 'N4N0CX11Z173170'
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true,ParameterSetName='device')]
    [string]$DeviceName,
    
    [Parameter(Mandatory = $true,ParameterSetName='serial')]
    [string]$Serial
)

##======================
## VARIABLES
##======================
$ErrorActionPreference = "Stop"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Save current progress preference and hide the progress
$prevProgressPreference = $global:ProgressPreference
$global:ProgressPreference = 'SilentlyContinue'
#Check if verbose is used; if it is don't use the nonewline in output
If($VerbosePreference){$NoNewLine=$False}Else{$NoNewLine=$True}

## ================================
## IMPORT FUNCTIONS
## ================================
Function Get-Symbol{
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
                    'WarningSign',
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
##*=============================================
##* INSTALL MODULES
##*=============================================
# Get WindowsAutopilotIntune module (and dependencies)
Write-Host ("    |---Checking for module dependencies...") -NoNewline:$NoNewLine

$Modules =  @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Users'
    'Microsoft.Graph.Groups'
    'Microsoft.Graph.Applications'
    'Microsoft.Graph.Identity.DirectoryManagement'
    'Microsoft.Graph.Devices.CorporateManagement'
    'Microsoft.Graph.DeviceManagement'
    'Microsoft.Graph.DeviceManagement.Enrolment'
)
Install-Module $Modules -Scope AllUsers -Verbose:$false
Import-Module $Modules -Scope Global -Verbose:$false
#Install-Module WindowsAutopilotIntune -MinimumVersion 5.3

Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
## ================================
## MAIN
## ================================
Write-Host ("    |---Connecting to tenant...") -NoNewline:$NoNewLine
try{
    $Scopes =  @(
        'APIConnectors.Read.All'
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
    $null = Connect-MgGraph -Scopes $Scopes -Verbose:$false
    #activate additional cmdlets using beta version of graph
    Select-MgProfile -Name "beta" -Verbose:$false
    $MGContext = Get-MgContext
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---Connected as: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $MGContext.Account) -ForegroundColor Cyan
}Catch{
    Write-Host ("{0} {1}" -f (Get-Symbol -Symbol RedX), $_.Exception.Message) -ForegroundColor Red
    Write-error "        Unable to connect to tenant. Can't continue!"
}


Write-Host ("`nStarting Autopilot readiness check...") -ForegroundColor Cyan
# 1. Check if device is enrolled as Autopilot Device
#------------------------------------------------------------------------------------------
#check by name
If ($PSCmdlet.ParameterSetName -eq "device")
{
    Write-Host ("`n    |---Retrieving device name from Azure AD [{0}]..." -f $DeviceName) -NoNewline
    Try{
        $AzureADDevice = Get-MgDevice -Filter "DisplayName eq '$DeviceName'"
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Verbose ("Device Object id: {0}" -f $AzureADDevice.Id)
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
        Write-error ("Unable to retrieve device in Azure by device name [{0}] `
        `nIf its an new device and it has been imported as Autopilot device, the device name should be the serial number and in Azure AD. `
        `nUpload hash and rerun script to continue!" -f $DeviceName)
    }

    Write-Host ("`n    |---Retrieving Autopilot ZTDID attribute from device object [{0}]..." -f $AzureADDevice.Id) -NoNewline
    #iterate through each PhysicalIds to get Autopilot one
    Foreach($PhysicalIds in $AzureADDevice.PhysicalIds.split('\n') | where {$_ -match 'ZTDID'}){
        $ZTDID = [System.Text.RegularExpressions.Regex]::Match($PhysicalIds,'\[ZTDID\]:(?<ztdid>.*)').Groups['ztdid'].value
    }

    #if the ztdid is there, it should match ap device id
    Try{
        $AutopilotDevice = Get-MgDeviceManagementWindowAutopilotDeviceIdentity -WindowsAutopilotDeviceIdentityId $ZTDID
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
        Write-Verbose ("ZTDID: {0}" -f $ZTDID)
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-error ("Unable to determine if the device name [{0}] is registered as an Autopilot device `
        `nIf its an new device and it has been imported as Autopilot device, the device name should have a [ZTDID] as a PhysicalId attribute in Azure AD `
        `nEnsure device has this attribute and rerun script to continue." -f $DeviceName)
    }

    Write-Host ("`n    |---Retrieving device name from Intune [{0}]..." -f $DeviceName) -NoNewline
    Try{
        $IntuneManagedDevice = Get-MgDeviceManagementManagedDevice -Filter "DeviceName eq '$DeviceName'"
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
        Write-Verbose "Device does not exist in Intune, could be new device..."
    }
}

#check by serial
If ($PSCmdlet.ParameterSetName -eq "serial")
{
    Write-Host ("`n    |---Retrieving Autopilot device from serial [{0}]..." -f $Serial) -NoNewline
    Try{
        $AutopilotDevice = Get-MgDeviceManagementWindowAutopilotDeviceIdentity -Filter "contains(serialNumber,'$Serial')"
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-error "Unable to retrieve Autopilot device from serial. Make sure the serial is correct and try again"
    }
    
    Write-Host ("`n    |---Retrieving Azure AD device id [{0}]..." -f $AutopilotDevice.AzureAdDeviceId) -NoNewline
    Try{
        $AzureADDevice = Get-MgDevice -Filter "DeviceId eq '$($AutopilotDevice.AzureAdDeviceId)'"
        Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
    }Catch{
        Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
        Write-error ("Unable to retrieve device in Azure by device id [{0}] `
        `nIf its an new device and it has been imported as Autopilot device, the device name should be the serial number and in Azure AD. `
        `nRe-import hash and rerun script to continue." -f $AutopilotDevice.AzureAdDeviceId)
    }
}


# 2. Get all deployment profiels and asssignments
#------------------------------------------------------------------------------------------
Write-Host "`n    |---Retrieving all Autopilot deployment profiles assignments..." -NoNewline
$DeploymentProfiles = Get-MgDeviceManagementWindowAutopilotDeploymentProfile

$depProfileAssignments = @()         
Foreach($DepProfile in $DeploymentProfiles){
    $assignmentsValues = Get-MgDeviceManagementWindowAutopilotDeploymentProfileAssignment -WindowsAutopilotDeploymentProfileId $DepProfile.Id
    
    foreach ($assignmentEntry in $AssignmentsValues)
    {
        $assignmentValue = New-Object pscustomobject
        $assignmentValue | Add-Member -MemberType NoteProperty -Name Name -Value $DepProfile.DisplayName
        $assignmentValue | Add-Member -MemberType NoteProperty -Name profileId -Value $DepProfile.Id
        $assignmentValue | Add-Member -MemberType NoteProperty -Name dataType -Value $assignmentEntry.Target.AdditionalProperties.'@odata.type'
        if ($null -ne $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType)
        {
            $assignmentValue | Add-Member -MemberType NoteProperty -Name TargetFilterType -Value $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType.ToString()
        }
        $assignmentValue | Add-Member -MemberType NoteProperty -Name FilterId -Value $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterId
        $assignmentValue | Add-Member -MemberType NoteProperty -Name groupId -Value $assignmentEntry.Target.AdditionalProperties.groupId
        #add to collection
        $depProfileAssignments += $assignmentValue
    }
}
If($depProfileAssignments.count -ge 1){
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---Deployment Profiles found: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $depProfileAssignments.count) -ForegroundColor Cyan
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-error "No Deployment profiles were found! `
    `nThere must be at least one Deployment profile created and assigned for a device to be Autopilot ready
    `nCreate a Deployment profile, assign it, and rerun script to continue."
}




# 3. Get all Azure AD group the device is a member of
#------------------------------------------------------------------------------------------
Write-Host ("`n    |---Retrieving groups assigned to device object [{0}]..." -f $AzureADDevice.Id) -NoNewline
$assignedGroupIds = @()
<#
#equivalent API call
$assignedGroups = (Invoke-MgGraphRequest -Method 'POST' -Body @{securityEnabledOnly=$false} `
            -Uri "https://graph.microsoft.com/v1.0/devices/$($AzureADDevice.Id)/getMemberGroups").Value
#>
$assignedGroupIds += Get-MgDeviceMemberGroup -BodyParameter @{securityEnabledOnly=$false} -DeviceId $AzureADDevice.Id

If($assignedGroupIds.count -ge 1){
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---Member of groups: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $assignedGroupIds.count) -ForegroundColor Cyan

    #iterate through each group id for name
    Foreach($groupid in $assignedGroupIds){
        $Group = Get-MgGroup -GroupId $groupid
        Write-Host ("            |---Group: ") -NoNewline -ForegroundColor Gray
        #check to see if any of the groups are dynamic groups using orderid
        If($Group.MembershipRule -match '[ZTDID]' -or $Group.MembershipRule -match "[OrderID]:$($AutopilotDevice.groupTag)"){
            Write-Host ("{0}" -f $Group.DisplayName) -ForegroundColor Green
        }Else{
            Write-Host ("{0}" -f $Group.DisplayName) -ForegroundColor White
        }
    }
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
}





#4. Check if the device is assigned a deployment profile and how (group tag, Azure AD group)
#------------------------------------------------------------------------------------------
Write-Host "`n    |---Checking if Autopilot device has group tag..." -NoNewline
IF($null -ne $AutopilotDevice.groupTag){
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark))
    Write-Host ("        |---Group tag: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $AutopilotDevice.groupTag) -ForegroundColor Cyan
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol Information))
    Write-Host ("        |---Group tag: ") -ForegroundColor White -NoNewline
    Write-Host ("none" -f $AutopilotDevice.groupTag) -ForegroundColor Yellow
}

<#
Write-Host "    |---Checking if Autopilot device has been deployed before..." -NoNewline
If($AutopilotDevice.EnrollmentState -eq 'enrolled'){
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol Information)) -ForegroundColor Yellow
}
#>

Write-Host "`n    |---Determining if deployment profile is assigned to device..." -NoNewline:$NoNewLine

$associatedAssignments = @()
Foreach($depProfileAssignment in $depProfileAssignments){
    #determine to add or remove assignment based on target type
    switch($depProfileAssignment.dataType){
        '#microsoft.graph.groupAssignmentTarget' {
            If($depProfileAssignment.groupId -in $assignedGroupIds){
                Write-Verbose ("Adding group id [{0}] to associated assignment list" -f $depProfileAssignment.groupId) 
                $associatedAssignments += $depProfileAssignment
            }
        }

        '#microsoft.graph.exclusionGroupAssignmentTarget' {
            If($depProfileAssignment.groupId -in $assignedGroupIds){
                Write-Verbose ("Excluding group id [{0}] from associated assignment list" -f $depProfileAssignment.groupId) 
                $associatedAssignments = $associatedAssignments | Where groupId -NotIn $assignedGroupIds 
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
    `nAssign device to a single deployment profile and rerun script to continue."
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
    Write-error "Unable to determine which Deployment profile is used! `
    `nIf a device has no deployment profile associated, Autopilot will not work correctly.
    `nAssign device to a single deployment profile and rerun script to continue."
}



#7. If Hybrid, check to make sure only one domain join profile is assigned to device
#------------------------------------------------------------------------------------------

If($HybridProfile){
    Write-Host "`n    |---Checking to make sure hybrid configuration profile is assigned..." -NoNewline:$NoNewLine

    $domainJoinPolicies = Get-MgDeviceManagementDeviceConfiguration | Where-Object `
                        -FilterScript {$_.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.windowsDomainJoinConfiguration"}
                        
    $hybridJoinPolicyAssignmentList = @()
    Foreach($domainJoinPolicy in $domainJoinPolicies){
        $assignmentsValues = Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $domainJoinPolicy.Id

        foreach ($assignmentEntry in $AssignmentsValues)
        {
            $assignmentValue = New-Object pscustomobject
            $assignmentValue | Add-Member -MemberType NoteProperty -Name Name -Value $domainJoinPolicy.DisplayName
            $assignmentValue | Add-Member -MemberType NoteProperty -Name profileId -Value $domainJoinPolicy.Id
            $assignmentValue | Add-Member -MemberType NoteProperty -Name dataType -Value $assignmentEntry.Target.AdditionalProperties.'@odata.type'
            if ($null -ne $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType)
            {
            $assignmentValue | Add-Member -MemberType NoteProperty -Name TargetFilterType -Value $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType.ToString()
            }
            $assignmentValue | Add-Member -MemberType NoteProperty -Name FilterId -Value $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterId
            $assignmentValue | Add-Member -MemberType NoteProperty -Name groupId -Value $assignmentEntry.Target.AdditionalProperties.groupId
            #add to collection
            $hybridJoinPolicyAssignmentList += $assignmentValue
        }
    }

    $associatedAssignments = @()
    Foreach($haadjAssignment in $hybridJoinPolicyAssignmentList){
        #determine to add or remove assignment based on target type
        switch($haadjAssignment.dataType){
            '#microsoft.graph.groupAssignmentTarget' {
                If($haadjAssignment.groupId -in $assignedGroupIds){
                    Write-Verbose ("Group id [{0}] is assigned to profile [{1}]" -f $haadjAssignment.groupId,$haadjAssignment.Name) 
                    $associatedAssignments += $haadjAssignment
                }
            }

            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                If($haadjAssignment.groupId -in $assignedGroupIds){
                    Write-Verbose ("Group id [{0}] is assigned as excluded; not counted for profile [{1}]" -f $haadjAssignment.groupId,$haadjAssignment.Name) 
                    $associatedAssignments = $associatedAssignments | Where groupId -NotIn $assignedGroupIds 
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
        `nAssign device to a single configuration profile and rerun script to continue."
    }Else{
        Write-Host ("{0}" -f (Get-Symbol -Symbol RedX)) -ForegroundColor Red
        Write-error "Unable to determine if a Hybrid Join configuration profile is assigned! `
        `nIf a device has no Hybrid Join configuration profile assigned, Autopilot will fail during deployment.
        `nAssign device to a single configuration profile and rerun script to continue."
    }
}




#5. Check if device is assigned an ESP and what are the apps assigned to it
#------------------------------------------------------------------------------------------
Write-Host "`n    |---Checking if device object is assigned an ESP configuration..." -NoNewline:$NoNewLine
$ESPProfiles = Get-MgDeviceManagementDeviceEnrollmentConfiguration | 
                    Where-Object -FilterScript { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration' }

$enrollmentAssignmentList = @()
Foreach($ESPProfile in $ESPProfiles){
    $assignmentsValues = Get-MgDeviceManagementDeviceEnrollmentConfigurationAssignment -DeviceEnrollmentConfigurationId $ESPProfile.Id

    foreach ($assignmentEntry in $AssignmentsValues)
    {
        $assignmentValue = New-Object pscustomobject
        $assignmentValue | Add-Member -MemberType NoteProperty -Name Name -Value $ESPProfile.DisplayName
        $assignmentValue | Add-Member -MemberType NoteProperty -Name profileId -Value $ESPProfile.Id
        $assignmentValue | Add-Member -MemberType NoteProperty -Name dataType -Value $assignmentEntry.Target.AdditionalProperties.'@odata.type'
        if ($null -ne $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType)
        {
        $assignmentValue | Add-Member -MemberType NoteProperty -Name TargetFilterType -Value $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType.ToString()
        }
        $assignmentValue | Add-Member -MemberType NoteProperty -Name FilterId -Value $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterId
        $assignmentValue | Add-Member -MemberType NoteProperty -Name groupId -Value $assignmentEntry.Target.AdditionalProperties.groupId
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
            If($espAssignment.groupId -in $assignedGroupIds){
                Write-Verbose ("Group id [{0}] is assigned to app [{1}]" -f $espAssignment.groupId,$espAssignment.Name) 
                $associatedAssignments += $espAssignment
            }
        }

        '#microsoft.graph.exclusionGroupAssignmentTarget' {
            If($espAssignment.groupId -in $assignedGroupIds){
                Write-Verbose ("Group id [{0}] is assigned as excluded; not counted for app [{1}]" -f $espAssignment.groupId,$espAssignment.Name)
                $associatedAssignments = $associatedAssignments | Where groupId -NotIn $assignedGroupIds 
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
        Write-Host ("{0}" -f $espDetails.DisplayName) -ForegroundColor Green -NoNewline 
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


$EspAppsIds = ($WinningESP | Select -ExpandProperty AdditionalProperties).selectedMobileAppIds
Write-Host ("        |---Winning ESP: " ) -ForegroundColor White -NoNewline
Write-Host ("{0}" -f $WinningESP.DisplayName) -ForegroundColor Cyan
Write-Host ("            |---Found: " ) -ForegroundColor White -NoNewline
Write-Host ("{0}" -f $EspAppsIds.Count) -ForegroundColor Cyan -NoNewline
Write-Host (" Apps associated with ESP" ) -ForegroundColor White






#6. Check to see if one of those groups are assigned to the apps as required.
#------------------------------------------------------------------------------------------
<#
$WinningESP = $ESPProfiles[1]
#>
$AppIdsAssignedInESP = ($WinningESP | select -ExpandProperty AdditionalProperties).selectedMobileAppIds
If($AppIdsAssignedInESP.count -gt 0){
    Write-Host "`n    |---Checking if apps associated with winning ESP are assigned as required..." -NoNewline:$NoNewLine

    $appAssignmentList = @()
    Foreach($AppId in $AppIdsAssignedInESP ){
        $AppDetails = Get-MgDeviceAppManagementMobileApp -MobileAppId $AppId
        $AssignmentsValues = Get-MgDeviceAppManagementMobileAppAssignment -MobileAppId $AppId

        foreach ($assignmentEntry in $AssignmentsValues)
        {
            $assignmentValue = New-Object pscustomobject
            $assignmentValue | Add-Member -MemberType NoteProperty -Name Name -Value $AppDetails.DisplayName
            $assignmentValue | Add-Member -MemberType NoteProperty -Name AppId -Value $AppId
            $assignmentValue | Add-Member -MemberType NoteProperty -Name Intent -Value $assignmentEntry.Intent
            $assignmentValue | Add-Member -MemberType NoteProperty -Name dataType -Value $assignmentEntry.Target.AdditionalProperties.'@odata.type'
            if ($null -ne $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType)
            {
            $assignmentValue | Add-Member -MemberType NoteProperty -Name TargetFilterType -Value $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType.ToString()
            }
            $assignmentValue | Add-Member -MemberType NoteProperty -Name FilterId -Value $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterId
            $assignmentValue | Add-Member -MemberType NoteProperty -Name groupId -Value $assignmentEntry.Target.AdditionalProperties.groupId
            #add to collection
            $appAssignmentList += $assignmentValue
        }
    }
}

$associatedAssignments = @()
Foreach($appAssignment in $appAssignmentList){

    If($appAssignment.Intent -eq 'required'){
        #determine to add or remove assignment based on target type
        switch($appAssignment.dataType){
            '#microsoft.graph.groupAssignmentTarget' {
                If(($appAssignment.groupId -in $assignedGroupIds) -and -NOT($associatedAssignments | Where Name -eq $appAssignment.Name)){
                    Write-Verbose ("Group id [{0}] is assigned as required for app [{1}]" -f $appAssignment.groupId,$appAssignment.Name) 
                    $associatedAssignments += $appAssignment
                }
            }

            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                If($appAssignment.groupId -in $assignedGroupIds){
                    Write-Verbose ("Group id [{0}] does not count for app [{1}]" -f $appAssignment.groupId,$appAssignment.Name)  
                    $associatedAssignments = $associatedAssignments | Where groupId -NotIn $assignedGroupIds 
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


If($associatedAssignments.count -ne $AppIdsAssignedInESP.count){
    Write-Host ("{0}" -f (Get-Symbol -Symbol WarningSign))
    Write-Host ("        |---Apps assigned as required: ") -ForegroundColor White -NoNewline
    Write-Host ("{0} out of {1}" -f $associatedAssignments.count,$EspAppsIds.count) -ForegroundColor Yellow
}Else{
    Write-Host ("{0}" -f (Get-Symbol -Symbol GreenCheckmark)) -ForegroundColor Green
}
    
#iterate through each group id for name
Foreach($app in $associatedAssignments){
    
    Write-Host ("        |---App: ") -ForegroundColor Gray -NoNewline 
    Write-Host ("{0}" -f $app.Name) -ForegroundColor Green 
    
    
    If($app.dataType -eq '#microsoft.graph.allLicensedUsersAssignmentTarget' ){
        Write-Host ("            |---User Group: " ) -ForegroundColor White -NoNewline
        Write-Host ("All Users") -ForegroundColor Green
    }ElseIf($app.dataType -eq '#microsoft.graph.allDevicesAssignmentTarget'){
        Write-Host ("            |---Device Group: " ) -ForegroundColor White -NoNewline
        Write-Host ("All Devices") -ForegroundColor Green
    }
    Else{
        $Group = Get-MgGroup -GroupId $app.groupId
        If( (Get-MgGroupMember -GroupId $Group.Id -ErrorAction SilentlyContinue).AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user'){
            Write-Host ("            |---User Group: " ) -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $Group.DisplayName) -ForegroundColor Yellow
        }Else{
            Write-Host ("            |---Device Group: " ) -ForegroundColor White -NoNewline
            Write-Host ("{0}" -f $Group.DisplayName) -ForegroundColor Green
        }
    }
}
Write-Host ("    WARNING: The user enrolling the device must be assigned the user-based apps") -BackgroundColor Yellow -ForegroundColor Black

Write-Host ("Autopilot readiness completed!") -ForegroundColor Cyan