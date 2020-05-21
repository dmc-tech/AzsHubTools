#Requires -Modules @{'ModuleName'='Azs.Deployment.Admin';'ModuleVersion'='0.1.0'}
[CmdletBinding()]
Param (
    [Parameter()][ValidateSet('microsoft.eventhub','microsoft.iothub')]
    [String]$productid='microsoft.eventhub',
    [Switch]$wait

)


function Get-AzsProductStatus {
    Param(
        [Parameter()][ValidateSet('microsoft.eventhub','microsoft.iothub')]
        [String]$productid
    )

    $status = (Get-AzsProductDeployment -ProductId $productid).properties.status
    if ($status){
        if ($wait){
            while ($status -notlike '*succeeded') {
                $interval = 10
                $status = (Get-AzsProductDeployment -ProductId $productid).properties.status 
                write-output ('Sleeping {0} seconds: {1} current provisioning state: {2}' -f $interval, $productid, $status )
                start-sleep -Seconds $interval
            }
            write-output ('{0} last operation was successful. Current status: {1}' -f $productid, $status )
        }
        else {
            if ($status -notlike '*succeeded') {
                write-output ('{0} current status: {1}' -f $productid, $status )
            }
            else {
                write-output ('{0} last operation was successful. Current status: {1}' -f $productid, $status )

            }

        }
        
    }
    else {
        write-output ('{0} not found. Check you have connected to the admin environment and the RP is installed' -f $productid )

    }
}

Get-AzsProductStatus $productid
