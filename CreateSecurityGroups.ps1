# Modules needed: Az.Accounts, Az.Resources
# Sample usage:
#.\CreateSecurityGroups.ps1 <subscriptionid> <securitygroupnameprefix>
#.\CreateSecurityGroups.ps1 8a7d40cd-fb92-4e9a-9c12-0b738ee08ba9 customerinsights

<#
.Description
    Creates security groups which will be used for attaching external lake to Dataverse.

    The script will:
    1.  Register the Dataverse app id.
    2.  Creates two security groups: one for contributors and one for readers. 
        Set the Dataverse app as the owner of the securitry groups. Dataverse will be managing the groups.

.PARAMETER SubscriptionId
Subscription Id where the storage account was created.

.PARAMETER SecurityGroupNamePrefix
Prefix for security group names. Security groups will be named SecurityGroupNamePrefix-Dataverse-readers and SecurityGroupNamePrefix-Dataverse-contributors

.PARAMETER FromMainScript
Optional: Do not set this. For internal use only.

.EXAMPLE
.\CreateSecurityGroups.ps1 -SubscriptionId 8a7d40cd-fb92-4e9a-9c12-0b738ee08ba9 -SecurityGroupNamePrefix customerinsights
#> 

Param(
    [parameter(Mandatory)] [string] $SubscriptionId,
    [parameter(Mandatory)] [string] $SecurityGroupNamePrefix,
    [switch] $FromMainScript
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
            sleep $sleepInSeconds 
        }
        else
        {
            throw "Unable to complete operation. Retries exhausted."
        }
    } while ($attempts -gt 0) 
}

function CreateSecurityGroupIfNotExists($groupName, $ownerId)
{
    $grp = Get-AzADGroup -DisplayName $groupName
    
    if (!$grp)
    {
        $grp = New-AzADGroup -DisplayName $groupName -MailNickName $groupName -ErrorAction Stop
    }

    AddOwnerIfNotExists $grp.Id $ownerId

    return $grp;
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

function ModuleExists($moduleName)
{
    if (Get-Module -ListAvailable -Name $moduleName) {
        return $true;
    } 
    else {
        Write-Host "Please install" $moduleName "before running this script."
        return $false;
    }
}

function CreateSPIfNotExists($appId, $displayName)
{
    $obj = Get-AzADServicePrincipal -DisplayName $displayName -ErrorAction Stop

    if (!$obj)
    {
        $obj = New-AzADServicePrincipal -ApplicationId $appId -DisplayName $displayName -ErrorAction Stop
    }

    return $obj;
}

if (!$FromMainScript)
{
    ###############################################################
    # Check for modules.
    ###############################################################
    $modules = ModuleExists "Az.Accounts";
    $modules = $modules -and (ModuleExists "Az.Resources");

    if (!$modules)
    {
        return;
    }

    $acct = Connect-AzAccount -Subscription $SubscriptionId
    Write-Host "Starting..." -ForegroundColor Green
}

###############################################################
# Creating security groups and making MDL app owner of the groups.
###############################################################
try
{
    $mdlApp = CreateSPIfNotExists "546068c3-99b1-4890-8e93-c8aeadcfe56a" "Common Data Service - Azure Data Lake Storage"

    $readerGroupName = $SecurityGroupNamePrefix + "-Dataverse-readers";
    Write-Host "Creating security group $readerGroupName" -ForegroundColor Green
    $readerSg = CreateSecurityGroupIfNotExists $readerGroupName $mdlApp.Id

    $contributorGroupName = $SecurityGroupNamePrefix + "-Dataverse-contributors";
    Write-Host "Creating security group $contributorGroupName" -ForegroundColor Green
    $contribSg = CreateSecurityGroupIfNotExists $contributorGroupName $mdlApp.Id

    if (!$FromMainScript)
    {
        Write-Host "Reader security group id: " $readerSg.Id -ForegroundColor Green
        Write-Host "Contributor security group id: " $contribSg.Id -ForegroundColor Green
    }
    else
    {
        [hashtable]$Return = @{} 
        $Return.ReaderSecurityGroupId = $readerSg.Id
        $Return.ContributorSecurityGroupId = $contribSg.Id
        Return $Return 
    }
}
catch
{
    Write-Host "Error creating security groups: $($PSItem.ToString())" -ForegroundColor Red
    return;
}

Write-Host "Setup complete" -ForegroundColor Green