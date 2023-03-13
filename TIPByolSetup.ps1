# Modules needed: Az.Accounts, Az.Resources, Az.Storage
# Sample usage:
#.\ByolSetup.ps1 <subscriptionid> <storage account name> <resource group name where storage account is present> <optional: path under the container>
#.\ByolSetup.ps1 8a7d40cd-fb92-4e9a-9c12-0b738ee08ba9 testpsbyol2 testpsrg
#.\ByolSetup.ps1 8a7d40cd-fb92-4e9a-9c12-0b738ee08ba9 testpsbyol2 testpsrg dir1/dir2

<#
.Description
    Prepares external lake for use in Dataverse.

    The script will:
    1.  Register the Dataverse app ids.
    2.  Creates two security groups: one for contributors and one for readers. 
        Set the Dataverse app as the owner of the securitry groups. Dataverse will be managing the groups.
    3.  Modifies Access Control List (ACL) on the container and path (if provided). 
        Contributors group will have rwx permission and readers groups will have r-x permission.
    4.  Same ACL will be set for all files/folders under the container and path provided.
    5.  Assigns Dataverse app id necessary roles to generate SAS tokens. The step will be skipped 
        if -OAuthAccessOnly switch is provided.

    Before running the script:
    1.  Please create a new ADLS Gen2 Storage account with HierarchialNameSpace Enabled or choose an existing one. 
        To create new account, please use:
        https://docs.microsoft.com/en-us/azure/storage/blobs/create-data-lake-storage-account
    2.  User running this script should have "Storage Blob Data Owner" access on the storage account/container level or this script will create one. 
        To add role assignment, please use:
        https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal.
        Role assignment can be removed after the script has completed running successfully.
    3.  Create a customerinsights container under that storage account or this script will create one.
    4.  Optionally create a folder or choose a folder under the container to be used as mount point.
        If folder is not provided container will be used as the mount point.

.PARAMETER SubscriptionId
Subscription Id where the storage account was created.

.PARAMETER StorageAccountName
Storage account name.

.PARAMETER ResourceGroupName
Resource group name under which the storage account was created.

.PARAMETER SecurityGroupNamePrefix
Prefix for security group names. Security groups will be named SecurityGroupNamePrefix-Dataverse-readers and SecurityGroupNamePrefix-Dataverse-contributors

.PARAMETER Path
Optional: Folder under the container that needs to be used as mount point. If not given, container will be used as the mount point.
Note: This is not supported at this point.

.PARAMETER ReaderSecurityGroupId
Optional: Id of the reader security group.

.PARAMETER ContributorSecurityGroupId
Optional: Id of the contributor security group.

.PARAMETER OAuthAccessOnly
Optional: Switch to prevent Dataverse from using SAS tokens to access the lake.

.EXAMPLE
.\ByolSetup.ps1 -SubscriptionId 8a7d40cd-fb92-4e9a-9c12-0b738ee08ba9 -StorageAccountName byodltest -ResourceGroupName testpsrg -SecurityGroupNamePrefix audienceinsights

.EXAMPLE
.\ByolSetup.ps1 -SubscriptionId 8a7d40cd-fb92-4e9a-9c12-0b738ee08ba9 -StorageAccountName byodltest -ResourceGroupName testpsrg -Path mydirectory  -SecurityGroupNamePrefix audienceinsights

.EXAMPLE
.\ByolSetup.ps1 -SubscriptionId 8a7d40cd-fb92-4e9a-9c12-0b738ee08ba9 -StorageAccountName byodltest -ResourceGroupName testpsrg -SecurityGroupNamePrefix audienceinsights -OAuthAccessOnly

.EXAMPLE
.\ByolSetup.ps1 -SubscriptionId 8a7d40cd-fb92-4e9a-9c12-0b738ee08ba9 -StorageAccountName byodltest -ResourceGroupName testpsrg -ReaderSecurityGroupId 943093db-9cbd-4098-8e42-0af878ca4226 -ContributorSecurityGroupId 05e96bdf-5c2b-4f42-ad9d-e46bbc1e136b

#> 

Param(
    [parameter(Mandatory)] [string] $SubscriptionId,
    [parameter(Mandatory)] [string] $StorageAccountName,
    [parameter(Mandatory)] [string] $ResourceGroupName,
    [string] $SecurityGroupNamePrefix,
    [string] $Path,
    [string] $ReaderSecurityGroupId,
    [string] $ContributorSecurityGroupId,
    [switch] $OAuthAccessOnly
)

function Retry([Action]$action)
{
    $attempts = 10
    $sleepInSeconds = 5

    do
    {
        try
        {
            $action.Invoke();
            break;
        }
        catch [Exception]
        {
            # Graph API throws bad request when owner already exists. Bad request will be considered success.
            if ($_.Exception.Message.Contains("Bad Request"))
            {
                break;
            }
        }            
        $attempts--

        if ($attempts -gt 0) 
        { 
            Start-Sleep $sleepInSeconds 
        }
        else
        {
            throw "Unable to complete operation. Retries exhausted."
        }
    } while ($attempts -gt 0) 
}

function CreateServicePrincipalIfNotExists($appId, $displayName)
{
    $obj = Get-AzADServicePrincipal -DisplayName $displayName -ErrorAction Stop

    if (!$obj)
    {
        Write-Host "Creating service principal for" $displayName
        $obj = New-AzADServicePrincipal -ApplicationId $appId -DisplayName $displayName -ErrorAction Stop
    }
    else
    {
         Write-Host "Service principal for" $displayName "already exists."
    }

    return $obj;
}

function AddOwnerIfNotExists($groupId, $ownerId)
{
    $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
    $url = "https://graph.microsoft.com/v1.0/groups/" + $groupId + "/owners/$" + "ref"
    $spId = "https://graph.microsoft.com/v1.0/serviceprincipals/" + $ownerId
    $body = @{
        "@odata.id" = $spId
    }
    $json = $body | ConvertTo-Json;
    $bearerToken = "Bearer " + $token.Token
    $headers = 
    @{
        Authorization = $bearerToken
    }

    Write-Host "Setting Dataverse as owner on the security group"
    Retry({Invoke-RestMethod -Method Post -Uri $url -Body $json -Headers $headers -ContentType 'application/json'})
}

function CreateContainerIfNotExists($ResourceGroupName, $StorageAccountName, $containerName)
{
    $storageAcc=Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName      
    ## Get the storage account context  
    $ctx=$storageAcc.Context
    $isContainerExists=Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction SilentlyContinue
    if(!$isContainerExists)  
    {
        Write-Host -ForegroundColor Magenta $containerName "container does not exist."   
        ## Create a new container 
        New-AzStorageContainer -Name $containerName -Context $ctx -Permission Container -ErrorAction Stop
        Write-Host -ForegroundColor Green $containerName "container created successfully."
    }
    else
    {
        Write-Host -ForegroundColor Green $containerName "container exists."   
    }
}

function GetCurrentUserObjectID 
{
    $ctx = Get-AzContext

    #This is different for users that are internal vs external
    #We can use Mail for users and guests
    $User = Get-AzADUser -Mail $ctx.Account.id
    if (-not $user) {  #Try UPN
        $User = Get-AzADUser -UserPrincipalName $ctx.Account.Id
    }
    if (-not $User) { #User was not found by mail or UPN, try MailNick
        $mail = ($ctx.Account.id -replace "@","_" ) + "#EXT#"
        $User = Get-AzADUser | Where-Object { $_.MailNickname -EQ $Mail}
    }

    return $User.id
}

function AssignRoleIfNotExists($userId, $scope, $roleName)
{
    $role = Get-AzRoleAssignment -ObjectId $userId -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop
    if ($role)
    {
        Write-Host "Role" $roleName "already exists"
    }
    else
    {
        $assign = New-AzRoleAssignment -ObjectId $userId -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop
        Write-Host "Assigned" $roleName
    }
}

function SetACL($storageContext, $containerName, $currPath, $readerSgId, $contribSgId, $setDefault)
{
    $params =
    @{ 
        'Context' = $storageContext
        'FileSystem' = $containerName
    }

    if ($currPath)
    {
        $params['Path'] = $currPath
    }

    if ($setDefault)
    {
        $readerPermissions = "r-x";
        $contribPermissions = "rwx";
    }
    else
    {
        $readerPermissions = "--x";
        $contribPermissions = "--x";
    }

    Write-Host "Fetch existing ACL information"
    $fs = Get-AzDataLakeGen2Item @params -ErrorAction Stop
    $acl = $fs.ACL

    $acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityID $readerSgId -Permission $readerPermissions -InputObject $acl -ErrorAction Stop
    $acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityID $contribSgId -Permission $contribPermissions -InputObject $acl -ErrorAction Stop

    if ($setDefault)
    {
        $acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityID $readerSgId -Permission $readerPermissions -InputObject $acl -DefaultScope -ErrorAction Stop
        $acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityID $contribSgId -Permission $contribPermissions -InputObject $acl -DefaultScope -ErrorAction Stop
    }

    Write-Host "Updating ACL with group information"
    $params['Acl'] = $acl
    $resp = Update-AzDataLakeGen2Item @params

    if (!$resp)
    {
        throw
    }
}

function DoesModuleExist($moduleName, $version)
{
    $module = Get-Module -ListAvailable -Name $moduleName

    if ($module -and ($module[0].Version -ge $version)) 
    {
        Write-Host $moduleName $module[0].Version "( >=" $version ") found." -ForegroundColor Green
        return $true;
    } 
    else {
        Write-Host "Please install" $moduleName $version "before running this script."
        return $false;
    }
}

###############################################################
# Check for modules and versions
###############################################################
$ver = New-Object -TypeName System.Version -ArgumentList 2,5,1
$modules = DoesModuleExist "Az.Accounts" $ver;

$ver = New-Object -TypeName System.Version -ArgumentList 3,2,1
$modules =  (DoesModuleExist "Az.Resources" $ver) -and $modules;

$ver = New-Object -TypeName System.Version -ArgumentList 3,9,0
$modules = (DoesModuleExist "Az.Storage" $ver) -and $modules;

if (!$modules)
{
    return;
}

###############################################################
# Parameter validation.
###############################################################
if (!$ReaderSecurityGroupId -and !$ContributorSecurityGroupId)
{
    if (!$SecurityGroupNamePrefix)
    {
        Write-Host "Please provide SecurityGroupNamePrefix parameter" -ForegroundColor Red
        return;
    }
}
else
{
    if (!$ReaderSecurityGroupId)
    {
        Write-Host "Please provide ReaderSecurityGroupId parameter" -ForegroundColor Red
        return;
    }

    if (!$ContributorSecurityGroupId)
    {
        Write-Host "Please provide ContributorSecurityGroupId parameter" -ForegroundColor Red
        return;
    }
}

$acct = Connect-AzAccount -Subscription $SubscriptionId

Write-Host "Starting..." -ForegroundColor Green
$storageScope = "/subscriptions/" + $SubscriptionId + "/resourceGroups/" + $ResourceGroupName + "/providers/Microsoft.Storage/storageAccounts/" + $StorageAccountName
$containerName = "customerinsights"
$containerScope = $storageScope + "/blobServices/default/containers/" + $containerName

###############################################################
# Check if the customerinsights container exists or create one.
###############################################################
CreateContainerIfNotExists $ResourceGroupName $StorageAccountName $containerName

#############################################################################
# Check if the user has  "Storage Blob Data Owner" permissions or assign it.
#############################################################################
$userId = GetCurrentUserObjectID
if ($userId)
{
    $userRole = Get-AzRoleAssignment -ObjectId $userId -RoleDefinitionName "Storage Blob Data Owner" -Scope $storageScope
    if (!$userRole)
    {
        Write-Host -ForegroundColor Magenta "User doesn't have Storage Blob Data Owner role on the storage account. Adding the role on the storage account"
        New-AzRoleAssignment -ObjectId $userId -RoleDefinitionName "Storage Blob Data Owner" -Scope $storageScope
        Write-Host -ForegroundColor Green "Succesfully added Storage Blob Data Owner role on the storage account."
    }
    else
    {
        Write-Host -ForegroundColor Green "Storage Blob Data owner role exists on the storage account"
    }
}

###############################################################
# Registering Dataverse and MDL service principals.
###############################################################
try
{
    Write-Host "Registering service principals" -ForegroundColor Green
    $mdlApp = CreateServicePrincipalIfNotExists "bfb6af92-393c-4963-b008-56d24eba985f" "Common Data Service - Azure Data Lake Storage - Test"
}
catch
{
    Write-Host "Error registering service principals: $($PSItem.ToString())"
    return;
}

###############################################################
# Creating security groups and making MDL app owner of the groups.
###############################################################
try
{  

    if (!$ReaderSecurityGroupId)
    {
        $sgInfo = & .\CreateSecurityGroups.ps1 -SubscriptionId $SubscriptionId -SecurityGroupNamePrefix $SecurityGroupNamePrefix -FromMainScript
        $ReaderSecurityGroupId = $sgInfo.ReaderSecurityGroupId
        $ContributorSecurityGroupId = $sgInfo.ContributorSecurityGroupId
    }

    $readerSg = 
    [PSCustomObject]@{
        Id = $ReaderSecurityGroupId
    }

    $contribSg = 
    [PSCustomObject]@{
        Id = $ContributorSecurityGroupId
    }
}
catch
{
    Write-Host "If you are unable to create security groups, please ask your tenant admin to create two security groups by running CreateSecurityGroups.ps1. The script is in the same folder as this file."
    Write-Host ".\CreateSecurityGroups.ps1 -SubscriptionId" $SubscriptionId "-SecurityGroupNamePrefix" $SecurityGroupNamePrefix
    Write-Host "After the groups are created the tenant admin should be able to provide you the group object ids."
    Write-Host "Once you have the group object ids, please re-run this script using same paramaters like now but also additionally add -ReaderSecurityGroupId <reader group object id> -ContributorSecurityGroupId <contributor group object id>."
    return;
}

if (!$OAuthAccessOnly)
{
    ###############################################################
    # Assign permissions needed for SAS token generation.
    ###############################################################
    try
    {
        
        Write-Host "Assigning permissions to Dataverse for SAS token generation" -ForegroundColor Green -ErrorAction Stop
        AssignRoleIfNotExists $mdlApp.Id $storageScope "Storage Blob Delegator"
        AssignRoleIfNotExists $mdlApp.Id $containerScope "Storage Blob Data Contributor"
    }
    catch
    {
        Write-Host "Error assigning roles: $($PSItem.ToString())"
        return;
    }
}
else
{
    ###############################################################
    # Add MDL app to contributor group.
    ###############################################################
    try
    {
        Write-Host "Adding Dataverse to Contributors group" -ForegroundColor Green
        Add-AzADGroupMember -MemberObjectId $mdlApp.Id -TargetGroupObjectId $contribSg.Id -ErrorAction Stop
    }
    catch
    {
        $message = $($PSItem.ToString());

        # Graph API throws exception if app is already a member. We will consider this as success.
        if ($message.Contains("already exist"))
        {
            Write-Host "Membership already exists."
        }
        else
        {
            Write-Host "Error adding MDL app to the contributor group: $message"
            return;
        }
    }
}

###############################################################
# Check if role assignment has propogated
###############################################################
Write-Host "Checking if Storage Blob Data Owner role assignment has propogated."
Write-Host "This can take some time. Please leave this window open."
Write-Host -NoNewline "Checking..."

$continue = $True;
while ($continue)
{
    Write-Host -NoNewLine "."
    $role = Get-AzRoleAssignment -ObjectId $userId -RoleDefinitionName "Storage Blob Data Owner" -Scope $storageScope

    if ($role)
    {
        Write-Host "DONE"
        $continue = $False;
    }
    else
    {
        
        Start-Sleep 10
    }
}

###############################################################
# Setting ACLs
###############################################################
try
{
    ###############################################################
    # Setting ACL on the container
    ###############################################################
    $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -Protocol "https" -UseConnectedAccount
    Write-Host "Setting ACL on container" -ForegroundColor Green
    if (!$Path)
    {
        $setDefault = $true
    }
    else
    {
        $setDefault = $false
    }
    SetACL $storageContext $containerName $null $readerSg.Id $contribSg.Id $setDefault

    ###############################################################
    # Setting ACL on the path
    ###############################################################
    if ($Path)
    {
        $folders = $Path.Split("/", [System.StringSplitOptions]::RemoveEmptyEntries)
        $currPath = ""
        
        for ($i = 0; $i -lt $folders.Length; $i++)
        {
            if ($i -eq $folders.Length - 1)
            {
                $setDefault  = $true
            }
            else
            {
                $setDefault = $false
            }

            $currPath = $currPath + $folders[$i] + "/"
            Write-Host "Setting ACL on folder" $currPath -ForegroundColor Green
            SetACL $storageContext $containerName $currPath $readerSg.Id $contribSg.Id $setDefault 
        }
    }
}
catch
{
    if ($PSItem.ToString() -Match "does not support blobstorageevents or softdelete") 
    {
        Write-Host "Error setting ACLs: $($PSItem.ToString()) Please use HNS Enabled Gen2 storage account." -ForegroundColor Red
        return;
    }
    
    Write-Host "Error setting ACLs: $($PSItem.ToString())"
    return;
}

###############################################################
# Setting ACL on the existing files and folders
###############################################################
Write-Host "Setting ACL on the existing files and folders" -ForegroundColor Green

$params =
@{ 
    'Context' = $storageContext
    'FileSystem' = $containerName
}

if ($Path)
{
    $params['Path'] = $Path
}

$acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityID $readerSg.Id -Permission r-x
$acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityID $contribSg.Id -Permission rwx -InputObject $acl
$acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityID $readerSg.Id -Permission r-x -DefaultScope -InputObject $acl
$acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityID $contribSg.Id -Permission rwx -DefaultScope -InputObject $acl 
$params['Acl'] = $acl

$updateAcl = Update-AzDataLakeGen2AclRecursive @params -ContinueOnFailure

if ($updateAcl.FailedEntries)
{
    Write-Host "Unable to set ACL on the following files/folders."
    $updateAcl.FailedEntries
}

###############################################################
# Write output
###############################################################
$output = 'https://' + $StorageAccountName + ".dfs.core.windows.net/" + $containerName
if ($Path)
{
    $output = $output + "/" + $Path
}
$output = $output + "?cg=" + $contribSg.Id + "&rg=" + $readerSg.Id

Write-Host "Please copy and paste the following url in Dataverse" -ForegroundColor Green
Write-Host $output

Write-Host "Setup complete" -ForegroundColor Green
