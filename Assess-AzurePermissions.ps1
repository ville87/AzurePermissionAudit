#REQUIRES -version 3.0
#REQUIRES -RunAsAdministrator
<#
.SYNOPSIS
   Get all permissions (Azure AD roles, Azure RBAC roles and MS Graph API permissions) of Service Principals and Users for a given subscription.

.DESCRIPTION
   
   Script which gets all permissions of Service Principals and Users in a given subscription.
   If no Subscription is provided with the script, all available ones are listed and the user has to choose which one to assess.
   The script collects information about:
    - MS Graph API permissions
    - Azure RBAC roles
    - Azure AD roles

   It reports potentially dangerous role assignments which could lead to privilege escalation and report the users which might be able to abuse
   those dangerous role assignments. 
   Work is based on research by Compass Security (@compasssecurity) and different blog posts / gists by Andy Robbins (@_wald0) of SpecterOps.

   Note: If the script hangs during the Connect-AzAccount step, this might be due to other accounts still being logged in, which sometimes breaks
   the PowerShell console somehow. In that case, clear all the logins with: Clear-AzContext -Scope CurrentUser -Force
   If this still doesn't help, remove the #REQUIRES -RunAsAdministrator line and rerun the script from a non-elevated PowerShell session. (Make
   sure that all necessary PowerShell modules are already installed!)
   List logged in accounts with: Get-AzContext -ListAvailable

.OUTPUTS

   For the collected data (users, service principals, role assignments etc.) CSV exports are created.
   Those are stored in the current working directory with the naming "<MemberType>_<SubscriptionID or TenantID>_dd_MM_yyyy-HH_mm_ss.csv"
   The findings are stored in a text file with the naming "Assessment_Findings_dd_MM_yyyy-HH_mm_ss.log"

   Logfiles:
       - .\<datetimestring>-azurepermissionsscriptlog.log

    Script ExitCodes:
    # TODO: Add custom ExitCodes for different errors (failed login, permissions etc.)
    0 -  Success
      
.INPUTS

    The subscription ID can be provided. If it is not provided, a list of available subscriptions is being displayed, 
    where the user can choose from.

.EXAMPLE

.LINK

.NOTES

   Author:   Ville Koch (@vegvisir87)
   Version:  V01.10 (beta)
   Date:     01.07.2022
   
   History:
   08.04.2022 V.Koch initial creation
   28.06.2022 Major overhaul
   29.06.2022 First release to test...
   01.07.2022 Beta version for review
   
#>
############################## script params section ########################
Param (
    [Parameter(Mandatory=$false)][string]$subscriptionID
)
############################## VARIABLE section #############################
BEGIN{

    [string]$scriptPath             = Split-Path -Parent $MyInvocation.MyCommand.Definition;
    if($scriptPath -eq ''){ $scriptPath = (Get-Location).Path }
    [string]$DateTimeString         = Get-Date -Format 'dd_MM_yyyy-HH_mm_ss'
    [string]$loggingenabled         = $true # if set to true, write to local logfile
    [bool]$Transcript               = $true # if set to true, Transcript file is created
    [string]$TranscriptLogFile      = "$scriptPath\TranscriptFile_$DateTimeString.log"
    [string]$logfile				= "$DateTimeString"+"-azurepermissionsscriptlog.log"
    [string]$logfilepath			= "$scriptPath\$logfile"
    [string]$MSGraphURL             = "https://graph.microsoft.com"
    [array]$requiredModules         = @("Az.ResourceGraph","Az.Accounts","Az.Resources","AzureAD")
    [string]$findingsReportfile     = "$scriptPath\Assessment_Findings_$DateTimeString.log"
    
    # The following part is used to create the array containing the dangerous MS graph permissions
    # MS documentation of app role IDs: https://docs.microsoft.com/en-us/graph/permissions-reference#all-permissions-and-ids
    [array]$CSVHeader = @("Id","Permission")
    [array]$DangerousGraphPermissionsList = @("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8,RoleManagement.ReadWrite.Directory","06b708a9-e830-4db3-a914-8e69da51d44f,AppRoleAssignment.ReadWrite.All")
    [array]$DangerousGraphPermissions = $DangerousGraphPermissionsList | ConvertFrom-Csv -Header $CSVHeader

    # Collection of different roles is based on the following blog post https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5
    # Define dangerous Azure AD roles
    [array]$MostDangerousAzADRBACRoles = @("Global Administrator","Privileged Role Administrator","Privileged Authentication Administrator")
    [array]$PotentiallyDangerousAzADRBACRoles = @("Application Administrator","Authentication Administrator","Azure AD joined device local administrator","Cloud Application Administrator","Cloud device Administrator","Exchange Administrator","Groups Administrator","Helpdesk Administrator","Hybrid Identity Administrator","Intune Administrator","Password Administrator","User Administrator")
    # Collection of Azure AD roles which allow an identity to potentially abuse high privileged service principals
    [array]$PotentialSPAbuseAzADRoles = @("Application Administrator","Cloud Application Administrator","Hybrid Identity Administrator","Directory Synchronization Account","Partner Tier1 Support","Partner Tier2 Support")

    # Collection of Azure RBAC roles which allow an identity to potentially abuse a high privileged service principal
    [array]$PotentialSPAbuseRBACRoles = @("Owner","Contributor","Automation Contributor","User Access Administrator")

    # Start script transcript if Transcript is set to true
    if($Transcript){
        Start-Transcript -Path $TranscriptLogFile
    }
    
    ############################## FUNCTIONS section #############################

    function printInfo { 
        Param (
        [Parameter(Mandatory = $true)][string]$info, # String to log
        [Parameter(Mandatory = $true)][ValidateSet("INFO","WARNING","ERROR")][string]$level
	    )
        if($level -eq "ERROR"){
            Write-Host -ForegroundColor Red -BackgroundColor Black "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }elseif($level -eq "WARNING"){
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }else{
            Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }
            
        if($loggingenabled){
            "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info" | Out-File -FilePath $logfilepath -Append
        }
    }

    function Get-AzureGraphToken {
        # Taken from https://gist.githubusercontent.com/andyrobbins/7c3dd62e6ed8678c97df9565ff3523fb/raw/2543368cc661820bc1d13e21aecab5f472086db2/AuditAppRoles.ps1
        $APSUser = Get-AzContext *>&1 
        $resource = "$MSGraphURL"
        $Token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($APSUser.Account, $APSUser.Environment, $APSUser.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $resource).AccessToken
        $Headers = @{}
        $Headers.Add("Authorization","Bearer"+ " " + "$($token)")
        $Headers
    }
}#BEGIN
############################## MAIN section ##################################
PROCESS
{
    $FQDN = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
    printInfo -info "+++++++++++++++++++ SCRIPT START +++++++++++++++++++++++++++" -level "INFO"
    printInfo -info "Script startet on system $FQDN" -level "INFO"
    try{
        ################### install necessary modules ###################
        printInfo -info "Checking PowerShell prerequisites..." -level "INFO"
        # Install the required modules from PowerShell Gallery if not already installed
        $psgallery = $false
        
        $installedModules = Get-Module -ListAvailable
        foreach($module in $requiredModules){
            if ($module -notin $installedModules.Name) {
                printInfo -info "Module $module not installed. Installing it..." -level "INFO" 
                if($psgallery -eq $false){
                    printInfo -info "Set PSGallery as trusted installation source..." -level "INFO"
                    # First trust the PSGallery source
                    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
                    $psgallery = $true
                }
                printInfo -info "Installing module $module..." -level "INFO"
                Install-Module -Name $module -AllowClobber -Force
            }
            # Import the module
            printInfo -info "Importing module $module..." -level "INFO"
            Import-Module $module
        }
        printInfo -info "Done!" -level "INFO"
        
        ################### Connect and get token ###################
        printInfo -info "Connecting to Azure with the Az PowerShell module. This will start the authentication process..." -level "INFO"
        Connect-AzAccount
        if($subscriptionID -ne ""){
            printInfo -info "Setting context to the provided subscription..." -level "INFO"
            Get-AzSubscription -SubscriptionId $subscriptionID | Set-AzContext
        }else{
            # Get all available subscriptions and let the user choose which one to assess
            printInfo -info "No subscription was provided, listing available ones:" -level "INFO"
            $availablesubs = Get-AzSubscription
            foreach($availablesub in $availablesubs){
                $subname = $availablesub.Name
                $subid = $availablesub.Id
                printInfo -info "Subscriptionname: $subname`t`t`tSubscriptionID: $subid" -level "INFO"
            }
            $chosensub = Read-Host "Please provide the ID of the subscription you want to assess"
            Get-AzSubscription -SubscriptionId $chosensub | Set-AzContext
            printInfo -info "Set context to subscription $chosensub" -level "INFO"
        }
        $tenantId = (Get-AzContext).Tenant.Id
        printInfo -info "Connecting to Azure AD tenant $tenantId (based on provided subscription) with the AzureAD PowerShell module..." -level "INFO"
        Connect-AzureAD -TenantId $tenantId
        printInfo -info "Done!" -level "INFO"

        ############################################################################
        ############################################################################
        ################### MS Graph API Data Collection         ###################
        ############################################################################
        ############################################################################

        # Inspired by Andy Robbins (@_wald0) talk at Insomnihack 2022 https://www.youtube.com/watch?v=a09_5SCPBZ0
        # and his blog post https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48
        
        $Headers = Get-AzureGraphToken
        # Get all service principals
        $SPsURI = "$MSGraphURL/v1.0/servicePrincipals"
        $TestSPObjects = $null
        $ServicePrincipals = $null
        printInfo -info "Collecting Service Principals in environment..." -level "INFO"
        do{
            $ServicePrincipals = Invoke-RestMethod `
                -Headers $Headers `
                -URI $SPsURI `
                -UseBasicParsing `
                -Method "GET" `
                -ContentType "application/json"
            if($ServicePrincipals.value){
                $TestSPObjects += $ServicePrincipals.value 
            }else{
                $TestSPObjects += $ServicePrincipals
            }
            $SPsURI = $ServicePrincipals.'@odata.nextlink'
        } until (!($SPsURI))
        printInfo -info "Found $($TestSPObjects.count) objects" -level "INFO"

        # Get all users
        $UsersURI = "$MSGraphURL/v1.0/users"
        $TestUsersObjects = $null	
        $Users = $null
        printInfo -info "Collecting Users in environment..." -level "INFO"
        do{
            $Users = Invoke-RestMethod `
                -Headers $Headers `
                -URI $UsersURI `
                -UseBasicParsing `
                -Method "GET" `
                -ContentType "application/json"
            if($Users.value){
                $TestUsersObjects += $Users.value 
            }else{
                $TestUsersObjects += $Users
            }
            $UsersURI = $Users.'@odata.nextlink'
        } until (!($UsersURI))
        printInfo -info "Found $($TestUsersObjects.count) objects" -level "INFO"
        
        ##########################
        # Export to CSV
        $SPexportdata = $TestSPObjects | ForEach-Object { 
            [PSCustomObject]@{ 
                id = $_.id
                accountEnabled = $_.accountEnabled
                appDisplayName = $_.appDisplayName
                displayName = $_.displayName
                appId = $_.appId
                createdDateTime = $_.createdDateTime
                servicePrincipalNames = $($_.servicePrincipalNames -join ',')
                servicePrincipalType = $_.servicePrincipalType
            }
        }
        $Userexportdata = $TestUsersObjects | ForEach-Object { 
            [PSCustomObject]@{ 
                id = $_.id
                givenName = $_.givenName
                surname = $_.surname
                displayName = $_.displayName
                userPrincipalName = $_.userPrincipalName
            }
        }

        $MSGraphSPcsvexport = "$scriptpath\MSGraphServicePrincipals_$chosensub"+"_"+"$DateTimeString.csv"
        printInfo -info "Exporting service principals to the CSV file $MSGraphSPcsvexport" -level "INFO"
        $SPexportdata | Export-CSV -Notypeinformation -path $MSGraphSPcsvexport
        $MSGraphUserscsvexport = "$scriptpath\MSGraphUsers_$chosensub"+"_"+"$DateTimeString.csv"
        printInfo -info "Exporting users to the CSV file $MSGraphUserscsvexport" -level "INFO"
        $Userexportdata | Export-CSV -Notypeinformation -path $MSGraphUserscsvexport
        
        printInfo -info "Done!" -level "INFO"
               
        ################### Dangerous API permissions ####################
        # Get all service principals permissions
        printInfo -info "Collecting information about AppRoleAssignments in MS Graph API. This might take several minutes..." -level "INFO"
        $AffectedServicePrincipalIDs = ($TestSPObjects).id
        $AppRoleAssignments = $null
        ForEach ($id in $AffectedServicePrincipalIDs){
            $req = $null
            $SPAppRoleAssignmentURL = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $id
            $req = Invoke-RestMethod -Headers $Headers `
                -Uri $SPAppRoleAssignmentURL `
                -Method GET
            $AppRoleAssignments += $req.value
        }
        $approleassignmentcount = ($AppRoleAssignments | measure).Count
        printInfo -info "Found $approleassignmentcount AppRoleAssignments of service principals" -level "INFO"

        # Export those into CSV
        $MSGraphAppRolecsvexport = "$scriptpath\MSGraphAppRoles_$chosensub"+"_"+"$DateTimeString.csv"
        printInfo -info "Exporting to the CSV file $MSGraphAppRolecsvexport" -level "INFO"
        $AppRoleAssignments | Export-CSV -NoTypeInformation -Path $MSGraphAppRolecsvexport

        # Find service principals with dangerous app roles
        $DangerousMSGraphAssignments = @()
        printInfo -info "Checking for dangerous AppRoleAssignments in the collected data..." -level "INFO"
        ForEach ($AppRoleAssignment in $AppRoleAssignments){
            $combinedobject = $null
            if($DangerousGraphPermissions.Id -contains $AppRoleAssignment.appRoleId){
                # add the content of the current role assignment plus extra property (the graph permission name) to an object
                $combinedobject += $AppRoleAssignment
                $graphpermissionname = $DangerousGraphPermissions | Where-Object { $_.Id -like $AppRoleAssignment.appRoleId} | select -ExpandProperty Permission
                $combinedobject | Add-Member -Name 'appRoleName' -Type NoteProperty -Value $graphpermissionname
                $DangerousMSGraphAssignments += $combinedobject
            }
        }
        #
        # TODO: Do we also check on dangerous MS Graph API app role assignments of users? Currently we cover only service principals...
        # If yes, the above part can be copied and modified for the users (userdata we have already collected in variable $TestUsersObjects)
        # 
        
        $DangerousMSGraphAssignmentCount = ($DangerousMSGraphAssignments | measure).count
        printInfo -info "Done!" -level "INFO"

        ############################################################################
        ############################################################################
        ################### Azure AD Role collection             ###################
        ############################################################################
        ############################################################################

        printInfo -info "Collecting Azure AD role assignments" -level "INFO"
        # Build our users and roles object
        $UserRoles = Get-AzureADDirectoryRole | ForEach-Object {
                
            $Role = $_
            $RoleDisplayName = $_.DisplayName
                
            $RoleMembers = Get-AzureADDirectoryRoleMember -ObjectID $Role.ObjectID
                
            ForEach ($Member in $RoleMembers) {
            $RoleMembership = [PSCustomObject]@{
                    MemberName      = $Member.DisplayName
                    MemberID        = $Member.ObjectID
                    MemberOnPremID  = $Member.OnPremisesSecurityIdentifier
                    MemberUPN       = $Member.UserPrincipalName
                    MemberType      = $Member.ObjectType
                    RoleID          = $Role.RoleTemplateId
                    RoleDisplayName = $RoleDisplayName
                }
            $RoleMembership    
            }    
        }
        # Export all role assignments to CSV
        $AzADRoleAsscsvexport   = "$scriptpath\AzureADRoleAssignments_$tenantId"+"_"+"$DateTimeString.csv"
        printInfo -info "Exporting all found Azure AD role assignments to the CSV file $AzADRoleAsscsvexport" -level "INFO"
        $UserRoles | Export-Csv -NoTypeInformation -Path $AzADRoleAsscsvexport

        # Now we check only service principals
        $DangerousAzADRoleAssignments = @()
        $PotentiallyDangerousAzADRoleAssignments = @()
        printInfo -info "Checking for dangerous roles in the collected data" -level "INFO"
        $SPUserRoles = $UserRoles | where-object { $_.MemberType -eq "ServicePrincipal" }
        foreach($SPUserRole in $SPUserRoles){
            # Check for most dangerous Azure AD RBAC roles
            if($MostDangerousAzADRBACRoles -contains $SPUserRole.RoleDisplayName){
                # printInfo -info "The service principal $($SPUserRole.MemberName) has assigned the Azure AD role $($SPUserRole.RoleDisplayName) which is a very privileged role!" -level "WARNING"
                $DangerousAzADRoleAssignments += $SPUserRole
            # Check for other potentially dangerous Azure AD RBAC roles
            }elseif($PotentiallyDangerousAzADRBACRoles -contains $SPUserRole.RoleDisplayName){
                #printInfo -info "The service principal $($SPUserRole.MemberName) has assigned the Azure AD role $($SPUserRole.RoleDisplayName) which is a privileged role!" -level "WARNING"
                $PotentiallyDangerousAzADRoleAssignments += $SPUserRole
            }else{
                # do nothing...
            }
        }

        $DangerousAzADRoleAssignmentsCount = ($DangerousAzADRoleAssignments | measure).count
        $PotentiallyDangerousAzADRoleAssignmentsCount = ($PotentiallyDangerousAzADRoleAssignments | measure).count
        # get all users and service principals with roles allowing to abuse other service principals
        $PotentialSPAbuseAzADUsers = $UserRoles | Where-Object { $_.RoleDisplayName -in $PotentialSPAbuseAzADRoles}
        $PotentialSPAbuseAzADUsersCount = ($PotentialSPAbuseAzADUsers | measure).count
        
        printInfo -info "Done!" -level "INFO"

        ############################################################################
        ############################################################################
        ################### Azure RBAC Role collection           ###################
        ############################################################################
        ############################################################################
        
        # Prepare array for the results
        $PotentialSPAbuseRBACUsers = @()
        $currentsub = Get-AzSubscription
        printInfo -info "Collecting RBAC roles of users in the subscription $($currentsub.Name)." -level "INFO"
        # collect all assignments in the given subscription
        $AllAzRBACAssignments = Get-AzRoleAssignment -Scope /subscriptions/$($currentsub.Id)
        
        # get all assignments with RBAC roles which could lead to service principal abuse
        foreach($AzRBACAssignment in $AllAzRBACAssignments){
            if($AzRBACAssignment.RoleDefinitionName -in $PotentialSPAbuseRBACRoles){
                $CustomAzRBACAssignment = [PSCustomObject]@{
                    Scope               = if($null -ne $AzRBACAssignment.Scope){$AzRBACAssignment.Scope}else{"N/A"}
                    DisplayName         = if($null -ne $AzRBACAssignment.DisplayName){$AzRBACAssignment.DisplayName}else{"N/A"}
                    SignInName          = if($null -ne $AzRBACAssignment.SignInName){$AzRBACAssignment.SignInName}else{"N/A"}
                    ObjectId            = if($null -ne $AzRBACAssignment.ObjectId){$AzRBACAssignment.ObjectId}else{"N/A"}
                    ObjectType          = if($null -ne $AzRBACAssignment.ObjectType){$AzRBACAssignment.ObjectType}else{"N/A"}
                    CanDelegate         = if($null -ne $AzRBACAssignment.CanDelegate){$AzRBACAssignment.CanDelegate}else{"N/A"}
                    RoleDefinitionName  = if($null -ne $AzRBACAssignment.RoleDefinitionName){$AzRBACAssignment.RoleDefinitionName}else{"N/A"}
                }
                $PotentialSPAbuseRBACUsers += $CustomAzRBACAssignment
            }
        }

        $PotentialSPAbuseRBACUsersCount = ($PotentialSPAbuseRBACUsers | measure).count
        printInfo -info "Done." -level "INFO"

        ############################################################################
        ############################################################################
        ################### Reporting of identified objects      ###################
        ############################################################################
        ############################################################################
        Write-host "############################################################################"
        printInfo -info "Report of found issues regarding MS Graph API permissions..." -level "INFO"
        "+++++++++++++++++++++ MS Graph API Permissions +++++++++++++++++++++" |Out-File -FilePath $findingsReportfile -Append
        if($DangerousMSGraphAssignmentCount -gt 0){
            printInfo -info "Found $DangerousMSGraphAssignmentCount dangerous MS Graph API app role assignments:" -level "WARNING"
            $DangerousMSGraphAssignments
            # Log findings to report file
            "Found $DangerousMSGraphAssignmentCount dangerous MS Graph API app role assignments:" |Out-File -FilePath $findingsReportfile -Append
            $DangerousMSGraphAssignments |Out-File -FilePath $findingsReportfile -Append
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++`r`n" |Out-File -FilePath $findingsReportfile -Append
        }else{
            printInfo -info "No dangerous MS Graph API app role assignments were found." -level "INFO"
            "No dangerous MS Graph API app role assignments were found." |Out-File -FilePath $findingsReportfile -Append
        }

        Write-host "############################################################################"
        printInfo -info "Report of found issues regarding Azure AD roles..." -level "INFO"
        "+++++++++++++++++++++ Azure AD Role Assignments +++++++++++++++++++++" |Out-File -FilePath $findingsReportfile -Append
        if($DangerousAzADRoleAssignmentsCount -gt 0){
            printInfo -info "Found $DangerousAzADRoleAssignmentsCount dangerous Azure AD role assignments" -level "WARNING"
            $DangerousAzADRoleAssignments
            # Log findings to report file
            "Found $DangerousAzADRoleAssignmentsCount dangerous Azure AD role assignments" |Out-File -FilePath $findingsReportfile -Append
            $DangerousAzADRoleAssignments |Out-File -FilePath $findingsReportfile -Append
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++`r`n" |Out-File -FilePath $findingsReportfile -Append
        }
        if($PotentiallyDangerousAzADRoleAssignmentsCount -gt 0){
            printInfo -info "Found $PotentiallyDangerousAzADRoleAssignmentsCount potentially dangerous Azure AD role assignments:" -level "WARNING"
            $PotentiallyDangerousAzADRoleAssignments
            # Log findings to report file
            "Found $PotentiallyDangerousAzADRoleAssignmentsCount potentially dangerous Azure AD role assignments:" |Out-File -FilePath $findingsReportfile -Append
            $PotentiallyDangerousAzADRoleAssignments |Out-File -FilePath $findingsReportfile -Append
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++`r`n" |Out-File -FilePath $findingsReportfile -Append
        }
        if(($PotentiallyDangerousAzADRoleAssignmentsCount -eq 0) -and ($DangerousAzADRoleAssignmentsCount -eq 0)){
            printInfo -info "No dangerous Azure AD role assignments were found." -level "INFO"
            "No dangerous Azure AD role assignments were found."|Out-File -FilePath $findingsReportfile -Append
        }else{
            $dangerousAzADRoleexists = $true
        }
        if(($PotentialSPAbuseAzADUsersCount -gt 0) -and ($dangerousAzADRoleexists)){
            printInfo -info "The following users / service principals might be able to abuse the previously listed dangerous Azure AD role assignments for privilege escalation, since they have Azure AD roles assigned which allow them to modify the affected applications:" -level "WARNING"
            $PotentialSPAbuseAzADUsers
            # Log findings to report file
            "The following users / service principals might be able to abuse the previously listed dangerous Azure AD role assignments for privilege escalation, since they have Azure AD roles assigned which allow them to modify the affected applications:"  |Out-File -FilePath $findingsReportfile -Append
            $PotentialSPAbuseAzADUsers |Out-File -FilePath $findingsReportfile -Append
            "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++`r`n" |Out-File -FilePath $findingsReportfile -Append
        }

        Write-host "############################################################################"
        printInfo -info "Report of found issues regarding Azure RBAC roles..." -level "INFO"
        "+++++++++++++++++++++ Azure RBAC Roles +++++++++++++++++++++" |Out-File -FilePath $findingsReportfile -Append
        # The goal here is to report users with RBAC roles which could abuse one of the previously reported highly privileged service principals.
        # We have to check first which of the previously listed ones are in the Subscription of the dangerous RBAC role assignments, otherwise they are not relevant for reporting.
        
        # For MS Graph API:
        if(($PotentialSPAbuseRBACUsersCount -gt 0) -and ($DangerousMSGraphAssignmentCount -gt 0)){
            foreach($DangerousMSGraphAssignmententry in $DangerousMSGraphAssignments){
                printInfo -info "Checking the dangerous MS Graph API AppRoleAssignment:" -level "INFO"
                $DangerousMSGraphAssignmententry
                # Log findings to report file
                "Checking the dangerous MS Graph API AppRoleAssignment:"  |Out-File -FilePath $findingsReportfile -Append
                $DangerousMSGraphAssignmententry |Out-File -FilePath $findingsReportfile -Append
                # First we need to get the subscriptionId by using the AppDisplayName. If there is a better way, please improve :)
                $appdisplayname = $DangerousMSGraphAssignmententry.principalDisplayName
                $subscriptionId = Get-AzResource -Name $appdisplayname | select -ExpandProperty SubscriptionId # Note that this does not return anything for enterprise apps not deployed in a subscription, so we set it to Unknown!
                if($null -eq $subscriptionId){ $subscriptionId = "Unknown" }
                printInfo -info "Subscription of the current AppRoleAssignment is: $subscriptionId" -level "INFO"
                "Subscription of the current AppRoleAssignment is: $subscriptionId"  |Out-File -FilePath $findingsReportfile -Append
                $SPAbuseRBACUsers = @()
                foreach($PotentialSPAbuseRBACUser in $PotentialSPAbuseRBACUsers){
                    # Since we cannot reliably get the corresponding subscriptionId, we currently also list entries with subscriptionId of "Unknown" as potential privesc targets. 
                    # TODO: It should be checked, how this can be more reliably verified!
                    if(($PotentialSPAbuseRBACUser.Scope -contains $subscriptionId) -or ($subscriptionId -eq "Unknown")){
                        $SPAbuseRBACUsers += $PotentialSPAbuseRBACUser
                    }
                }
                $SPAbuseRBACUsersCount = ($SPAbuseRBACUsers | measure).Count
                if($SPAbuseRBACUsersCount -gt 0){
                    printInfo -info "The following identities might be able to abuse this AppRoleAssignment for Privilege Escalation:" -level "WARNING"
                    $SPAbuseRBACUsers
                    # Log findings to report file
                    "The following identities might be able to abuse this AppRoleAssignment for Privilege Escalation:" |Out-File -FilePath $findingsReportfile -Append
                    $SPAbuseRBACUsers |Out-File -FilePath $findingsReportfile -Append
                }else{
                    printInfo -info "No identities found which could abuse this AppRoleAssignment." -level "INFO"
                    "No identities found which could abuse this AppRoleAssignment."|Out-File -FilePath $findingsReportfile -Append
                }
            }
            Write-host "############################################################################"
        }

        # For Azure AD roles:
        if(($PotentialSPAbuseRBACUsersCount -gt 0) -and ($dangerousAzADRoleexists)){
            # First, combine the $PotentiallyDangerousAzADRoleAssignments and $DangerousAzADRoleAssignments to $DangerousAzADRoleAssignmentsCombined
            # This was we can go through Service Principals with multiple role assignments only once
            $DangerousAzADRoleAssignmentsCombined = @()
            foreach($DangerousAzADRoleAssignmentitem in $DangerousAzADRoleAssignments) { $DangerousAzADRoleAssignmentsCombined += $DangerousAzADRoleAssignmentitem}
            foreach($PotentiallyDangerousAzADRoleAssignmentitem in $PotentiallyDangerousAzADRoleAssignments) { $DangerousAzADRoleAssignmentsCombined += $PotentiallyDangerousAzADRoleAssignmentitem}
            
            # now check their corresponding apps and what subscription is affected, to check if any of the gathered RBAC user permissions could be abused...
            $uniqueSPIDs = $DangerousAzADRoleAssignmentsCombined.MemberID | select -Unique
            foreach($uniqueSPID in $uniqueSPIDs){
                $CurrentSPAzADRoleAssignments = ($DangerousAzADRoleAssignmentsCombined | Where-Object { $_.MemberID -like $uniqueSPID} | select -ExpandProperty RoleDisplayName)
                printInfo -info "Checking the dangerous Azure AD role assignments (Roles: $($CurrentSPAzADRoleAssignments -join ',')) of the service principal $uniqueSPID" -level "INFO"
                "Checking the dangerous Azure AD role assignments (Roles: $($CurrentSPAzADRoleAssignments -join ',')) of the service principal $uniqueSPID" |Out-File -FilePath $findingsReportfile -Append
                $CurrentSPSubscriptionId = Get-AzResource -Name (Get-AzADServicePrincipal -ObjectId $uniqueSPID).DisplayName | select -ExpandProperty SubscriptionId # Note that this does not return anything for enterprise apps not deployed in a subscription, so we set it to Unknown!
                if($null -eq $CurrentSPSubscriptionId){ $CurrentSPSubscriptionId = "Unknown" }
                printInfo -info "Subscription of the current service principals resource is: $subscriptionId" -level "INFO"
                "Subscription of the current service principals resource is: $subscriptionId" |Out-File -FilePath $findingsReportfile -Append
                $SPAbuseAZADUsers = @()
                foreach($PotentialSPAbuseRBACUser in $PotentialSPAbuseRBACUsers){
                    # Since we cannot reliably get the corresponding subscriptionId, we currently also list entries with subscriptionId of "Unknown" as potential privesc targets. 
                    # TODO: It should be checked, how this can be more reliably verified!
                    if(($PotentialSPAbuseRBACUser.Scope -contains $CurrentSPSubscriptionId) -or ($CurrentSPSubscriptionId -eq "Unknown")){
                        $SPAbuseAZADUsers += $PotentialSPAbuseRBACUser
                    }
                }
                $SPAbuseAZADUsersCount = ($SPAbuseAZADUsers | measure).Count
                if($SPAbuseAZADUsersCount -gt 0){
                    printInfo -info "The following identities might be able to abuse this service principal for Privilege Escalation:" -level "WARNING"
                    $SPAbuseAZADUsers
                    # Log findings to report file
                    "The following identities might be able to abuse this service principal for Privilege Escalation:"|Out-File -FilePath $findingsReportfile -Append
                    $SPAbuseAZADUsers|Out-File -FilePath $findingsReportfile -Append
                }else{
                    printInfo -info "No identities found which could abuse this AppRoleAssignment." -level "INFO"
                    "No identities found which could abuse this AppRoleAssignment."|Out-File -FilePath $findingsReportfile -Append
                }
            }

            Write-host "############################################################################"
        }
        printInfo -info "Done." -level "INFO"

        $ErrorLevel = 0
    }catch{
        printInfo -info "There was an error when running the script. Error:`r`n$_" -level "ERROR"
    }
}#PROCESS
END
{
    if ($ErrorLevel -eq "0") {
        printInfo -info "Script ended succesfully" -level "INFO"
        printInfo -info "The reported findings can be found here: $findingsReportfile" -level "INFO"
    }else{
        printInfo -info "Script ended with ErrorLevel: $ErrorLevel" -level "WARNING"
    }
    printInfo -info "+++++++++++++++++++ SCRIPT END +++++++++++++++++++++++++++" -level "INFO"
    if($Transcript){
        Stop-Transcript
    }
    Exit $ErrorLevel;
}
