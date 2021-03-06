﻿  
<#
.SYNOPSIS
There are limits to the number of read/write operations that can be performed against the Azure Resource manager proviers in Azure. 
When this limit is reached there will be an HTTP 429 error returned.  The documentation below outlines the specific REST call but
does not provide a complete example
https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-request-limits
.DESCRIPTION
This script creates the proper bearer token to invoke the REST API on the number of remaining Read Operations allowed against a specific 
subscription.  The function Get-AzureCachedAccessToken provides the logic to pull the access token required to pass into the REST API

Version modified to accomodate AZ PowerShell Module and Azure Stack Hub environments
#>


function Get-AzCachedAccessToken()
{
  $ErrorActionPreference = 'Stop'
  
  if(-not (Get-Module Az.Accounts)) {
    Import-Module Az.Accounts
  }
  $azAccountsModuleVersion = (Get-Module Az.Accounts).Version
  # refactoring performed in AzureRm.Profile v2.0 or later
  if($azAccountsModuleVersion.Major -ge 2) {
    $azAccount = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    if(-not $azAccount.Accounts.Count) {
      Write-Error "Ensure you have logged in before calling this function."    
    }
  }
  
  $currentAzureContext = Get-AzContext
  $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azAccount)

  Write-Debug ("Getting access token for tenant" + $currentAzureContext.Subscription.TenantId)
  $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
  $token.AccessToken

 }


Write-Host "Log in to your Azure subscription..." -ForegroundColor Green
#Login-AzureRmAccount
#Get-AzureRmSubscription -SubscriptionName $SubscriptionName | Select-AzureRmSubscription

$token = Get-AzCachedAccessToken
$currentAzureContext = Get-AzContext
Write-Host ("Getting access ARM Throttle Limits for Subscription: " + $currentAzureContext.Subscription)


$requestHeader = @{
  "Authorization" = "Bearer " + $token
  "Content-Type" = "application/json"
}

$Uri = ('{0}/subscriptions/{1}/resourcegroups?api-version=2016-09-01' -f $currentAzureContext.Environment.ResourceManagerUrl, $currentAzureContext.Subscription.Id)
$r = Invoke-WebRequest -Uri $Uri -Method GET -Headers $requestHeader
write-host("Remaining Read Operations: " + $r.Headers["x-ms-ratelimit-remaining-subscription-reads"])