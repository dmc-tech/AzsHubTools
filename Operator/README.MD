# Azure Stack Hub Operator Tools

## Get-AzsProductDeploymentStatus.ps1

Run this to determine that deployment status of an Azure Stack Hub Resource Provider.  Useful to check the status of secret rotations.

Requires the Azure Stack Operator PowerShell module.

| Parameter | Type | Description |
|:----------|:-----|:------------|
|productid  | String| either microsoft.eventhub or microsoft.iothub|
|wait| Boolean| Specify whether to wait for the status to change to succeeded|
