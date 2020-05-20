There are limits to the number of read/write operations that can be performed against the Azure Resource manager proviers in Azure. 
When this limit is reached there will be an HTTP 429 error returned.  The documentation below outlines the specific REST call but
does not provide a complete example
https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-request-limits

Original Script: https://github.com/Microsoft/csa-misc-utils/tree/master/psh-GetArmLimitsViaAPI

Version modified to accomodate Azure Stack Hub environments
