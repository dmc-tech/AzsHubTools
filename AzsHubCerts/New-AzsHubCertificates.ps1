#Requires -RunAsAdministrator
#Requires -Modules @{'ModuleName'='Microsoft.AzureStack.ReadinessChecker';'ModuleVersion'='1.2002.1111.69'}

# Title   : New-AzsHubCertificates.ps1
# Author  : Danny McDermott 
# Version : 0.1
# Date    : 23-04-2020
#
# Description : Create Certificate Requests for an Azure Stack Hub Region within an ADP Region

[CmdletBinding()]
Param(
    [Parameter()][string]$azsregion,
    [Parameter()][string]$azsCertDir = 'c:\azsCerts',
    [Parameter()][String]$azsRegionFQDN,
    [Parameter()]
    [ValidateSet('AAD','ADFS')]
    [String]$IdentitySystem
)

$subject = 'CN=Azure Stack Hub ' # set this if required

#  Create folder structure to host certificates
function new-AzsCertFolder ($AzsCert, $Path ) {
    foreach ($Key in $AzsCert.Keys) {
        if (-not (Test-Path -Path "$Path\$Key")) {
            New-Item -ItemType Directory -Path "$Path\$Key"
        }
    }
}

if (-not (Test-Path -Path $azsCertDir )) {
    mkdir $azsCertDir | out-null
}


$certpath = $azsCertDir  + '\'  + $AzsRegion
$DNSZone = ('{0}' -f $azsRegionFQDN)

if (-not (Test-Path -Path $CertPath)) {
    New-Item -ItemType Directory -Path $CertPath
}

#  Create request files for each endpoint
$outputDirectory = $certpath + '\requests'
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory
}

New-AzsCertificateSigningRequest -certificateType Deployment -RegionName $AzsRegion -FQDN $DNSZone -OutputRequestPath $outputDirectory -IdentitySystem $IdentitySystem
$RequestFileCount = (Get-ChildItem -Path $outputDirectory -Filter *.req| Measure-Object).Count
if ($RequestFileCount -ne $reqCount) {
    write-error ('The required number of request files is not valid. Actual: {0}. Required: {1}.' -f $RequestFileCount, $reqCount )
    break
}

# Need to use the IP address, otherwise Kerberos complains.  Work out IP address for CA in the follwowing 2 lines
$hostEntry =[System.Net.Dns]::GetHostByName($caServer)
$CAIP = $hostEntry.AddressList[0].IPAddressToString
#Setup WinRM
($currentsettings = winrm g winrm/config/client) | out-null
# Check if there are existing entries, we do not want to over write them
foreach ($entry in $currentSettings) {
    if ($entry -like '*TrustedHosts =*') {
        $servers = (($entry.Split('='))[1]).Trim()
    }
}

$serversArray =@()
if ($servers.count -gt 0) { 
    foreach ($server in $servers.Split(',')) {
        # Check to see if the CA server IP already exists in WinRM
        if (($server.Trim() -eq $CAIP)) {
            write-output ('[INFO]: Remote host {0} exists in WinRM' -f $server.Trim())
        }
        else {
            # This isn't the CA IP, we want to preservce this entry
            $serversArray += $server.Trim()
            write-output ('[INFO]: Remote host {0} added to WinRM' -f $server.Trim())
        }
    }
       
}

# Add the CA IP address to the WinRM trusted list
$serversArray += $CAIP
write-output ('[INFO]: Remote host {0} added to WinRM' -f $CAIP)

$list = $serversArray -join ", "

$TrustedHosts=  ('@{{TrustedHosts="{0}"}}' -f $list)
# Update the WinRM config with the new trusted hosts...
(winrm s winrm/config/client $TrustedHosts) | out-null

# Setup the remote session to the CA Server
$caPasswordSecure = $caPassword | ConvertTo-SecureString -AsPlainText -Force
$caCredentials = New-Object System.Management.Automation.PSCredential ($caUser,$caPasswordSecure)
($caSession = New-PSSession -ComputerName $CAIP -Credential $caCredentials) | out-null

$remotefolder = "c:\temp\certs\$azsregion"

$srcFolder = $azsCertDir  + '\'  + $AzsRegion

$requestsFolder = "$srcFolder\requests"
$signedcertsFolder = "$srcFolder\signedcerts"

# Temp - location where the certs exist should exist, so do a check for the corect number of request files.  Quit if it doesn't as it should be present!
if (-not (Test-Path -Path $srcFolder  -PathType Container)) {
    write-error ('[ERROR]: The location for the request files is not present {0}.' -f $requestsFolder )
    (Remove-PSSession -Session $caSession) | out-null
    break
}

$RequestFileCount = (Get-ChildItem -Path $requestsFolder -Filter *.req| Measure-Object).Count

if ($RequestFileCount -ne $reqCount) {
    write-error ('[ERROR]: The required number of request files is not valid. Actual: {0}. Required: {1}.' -f $RequestFileCount, $reqCount )
    (Remove-PSSession -Session $caSession) | out-null
    break
}


Invoke-Command -Session $caSession -ScriptBlock {if (-not (test-path -path $using:remotefolder)){ md $using:remotefolder}} # Create the remote folder if not exist
Copy-Item "$srcFolder\requests\*.req" -Destination "$remotefolder"  -ToSession $caSession -recurse -Force 

$scriptblock= {
param(
    [string]$certReqfolder = ''
)

write-output ('[INFO]: Remote Cert Folder: {0}' -f $certReqfolder)
$CertReqPath = 'C:\Windows\System32\certreq.exe'
$CertUtilPath = 'C:\Windows\System32\certutil.exe'
$result = (Invoke-Expression -Command $CertUtilPath) | Out-String | ConvertFrom-String
$ca = (($result.P5).Replace("'","")).Replace("``","")
$config = (($result.P18).Replace("'","")).Replace("``","")
write-output ('[INFO]: Retrieved CA: {0}' -f $ca)

$CRTPath = $certReqfolder + "\certs"
		
If (-not (Test-Path($CRTPath))){
		
	new-item -Path $CRTPath -ItemType Directory
		
}

#parameters to pass to the CertUtil command
$params = @(
"-ca.cert" 
"$CRTPath\$ca.cer"
)

write-output ('[INFO]: Retrieving Public CA Certificate')
& $CertUtilPath $params
write-output ('[INFO]: Retrieved Public CA Certificate')
foreach ($request in (Get-ChildItem -Path $certReqfolder -filter *.req)){
    write-output ('[INFO]: Processing Request: {0}' -f $request.FullName)
    $command = $CertReqPath + " -config " + $config + " -attrib CertificateTemplate:RASAndIASServer -submit " + $request.FullName
    $result = (Invoke-Expression -Command $command) | Out-String | ConvertFrom-String
   
    # Approve the request
    $id = $result.P2
    $command = $CertUtilPath + " -resubmit " + $id
	Invoke-Expression -Command $command

    # Retrieve the request
    
    write-output ('[INFO]: Retrieving Signed Certificates')
    # .crt and .p7b
    if (($request.BaseName).split('_')[0] -eq 'wildcard') {
        $certname = ($request.BaseName).split('_')[1]
    }
    else {
        $certname = ($request.BaseName).split('_')[0]
    }
	$CRTFilePath = $CRTPath + "\" + $certname + ".crt"
	$P7BFilePath = $CRTPath + "\" + $certname + ".p7b"
	$command = $CertReqPath + " -f -q -config " + $config + " -retrieve " + $id + " " + $CRTFilePath + " " + $P7BFilePath 
    write-output ('[INFO]: Running: {0}' -f $command)
	Invoke-Expression -Command $command
}
}

Invoke-Command -Session $caSession -ScriptBlock $scriptblock -ArgumentList $remotefolder
if ( -not (Test-Path -Path $signedcertsFolder)) {
    new-item -Path $signedcertsFolder -ItemType Directory
}
# Copy Signed Certs locally

write-output ('[INFO]: Copying Signed Certs from CA to Cloud Operator host.')
Copy-Item "$remotefolder\certs\*.crt" -Destination $signedcertsFolder -FromSession $caSession -recurse -Force 

write-output ('[INFO]: Copying Public CA certificate from CA to Cloud Operator host.')
Copy-Item "$remotefolder\certs\*.cer" -Destination $signedcertsFolder -FromSession $caSession -recurse -Force 

# Tidy up folders on the CA
write-output ('[INFO]: Removing Temp files on the CA server.')
invoke-command -Session $caSession -ScriptBlock {remove-item -Path "$using:remotefolder" -Recurse -Force }

# Remove the remote session
(Remove-PSSession -Session $caSession) | out-null

# Remove the request Dir as we're done processing those
Remove-Item -Path $requestsFolder -Recurse -Force
write-output ('[INFO]: Completed processing certificate requests')

#  Determine If ADFS ID system
$ADFS = $false
If ($IdentitySystem -eq 'ADFS') {
    $ADFS = $true
}


# Create folder structure to host certificates
function new-AzsCertFolder ($AzsCert, $Path ) {
    foreach ($Value in $AzsCert.Values) {
        if (-not (Test-Path -Path "$Path\$Value")) {
            New-Item -ItemType Directory -Path "$Path\$Value"
        }
    }
}

if ($adpInstance.length -gt 1) {
    $certpath = $azsCertDir  + '\'  + $AzsRegion + '.' + $adpInstance
    $DNSZone = ('{0}.{1}' -f $adpInstance, $instanceFQDN)
}
else {
    $certpath = $azsCertDir  + '\'  + $AzsRegion
    $DNSZone = ('{0}' -f $instanceFQDN)
}
# Folder to store deployment certificates
$CoreCertPath = "$CertPath\$IdentitySystem"
# //TODO: Set up Certs for other services
$AppSvcCertPath = "$CertPath\AppServices"
$DBAdapterCertPath = "$CertPath\DBAdapter"
$EVHubsCertPath = "$CertPath\EventHubs"
$DBEHubsCertPath = "$CertPath\DataboxEdge"
$IoTHubCertPath = "$CertPath\IoTHub"

$signedcertsFolder = "$srcFolder\signedcerts"


# cert name / Folder name
$AzsCommmonEndpoints = @{
    'portal'="Public Portal";
    'adminportal'="Admin Portal";
    'management'="ARM Public";
    'adminmanagement'="ARM Admin";
    'blob'="ACSBlob";
    'table'="ACSTable";
    'queue'="ACSQueue";
    'vault'="KeyVault";
    'adminvault'="KeyVaultInternal";
    'adminhosting'="Admin Extension Host";
    'hosting'="Public Extension Host"
    }
$AzsADFSEndpoints = @{
    'adfs'="ADFS";
    'graph'="Graph";
    }

if (-not (Test-Path -Path $CertPath  -PathType Container)) {
    write-error ('[ERROR]: The location for the certificate files is not present {0}.' -f $CertPath )
    break
}

#Create the folder structure for core deployment certs
new-AzsCertFolder $AzsCommmonEndpoints -Path $CoreCertPath
if ($ADFS) {
    new-AzsCertFolder $AzsADFSEndpoints -Path $CoreCertPath
}
# Generate a random password using the system.web GeneratePassword functionality
Add-Type -AssemblyName System.Web 
$PasswordLength = 16
$SpecialCharCount = 1
$pfxPassword = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, $SpecialCharCount)
$secPfxPass = ConvertTo-SecureString -AsPlainText $pfxPassword -Force

# Process signed responses from CA
$script:certHash = @{}
$signedcertsFolder = $certpath + '\signedcerts'
if (-not (Test-Path -Path $signedcertsFolder -PathType Container)) {
    write-error ('[ERROR]: The location for the signed certificate files is not present {0}.' -f $signedcertsFolder )
    break
}

# Import the Public CA from the Signing CA
$publicCAFile = Get-ChildItem -Path "$signedcertsFolder\*.cer"

If ($publicCAFile.count -eq 1) {
    write-output ('[INFO]: Public CA Cert found: {0} ' -f $publicCAFile.Name)
    Import-Certificate -FilePath $publicCAFile.FullName -CertStoreLocation Cert:\LocalMachine\Root -Verbose 
    write-output ('[INFO]: Imported Public CA Cert: {0} ' -f $publicCAFile.Name)
} 
else {
    # Decide what to do with no file or multiple .cer files ...
    If ($publicCAFile.count -gt 1) {
        Write-Error ('[ERROR]: Too many .cer files found: {0}.  Expected one Public CA Cert.' -f $publicCAFile.count)
    }
    else {
        Write-Error ('[ERROR]: No .cer file detected.  Expected one.' -f $publicCAFile.count)
    }
}

function processCerts ($hash)
{
    foreach ($signedCert in $hash.keys ) {
        $CTRStore = 'Cert:\LocalMachine\My\'
        $cert = Get-ChildItem -Path "$signedcertsFolder\$signedCert.crt"
        $privCert = Import-Certificate -FilePath $cert -CertStoreLocation $CTRStore -ErrorAction Stop # get the signature and add to a hashtable? 
        write-output ('[INFO]: Imported certificate: {0}' -f $cert)
        write-output ('[INFO]: {0} Thumbprint: {1}' -f $signedCert, $privCert.Thumbprint)
        remove-item -Path $cert.FullName 
        #$certHash.Add($signedCert, @{$privCert.Thumbprint = $privCert.Subject})

        $exportCertpath =('{0}\{1}\{2}.pfx' -f $CoreCertPath, $hash[$signedcert], $signedCert )
       # Export-PfxCertificate -Cert $privCert -Password $secPfxPass -FilePath $exportCertpath -ChainOption BuildChain -NoProperties -Force -CryptoAlgorithmOption TripleDES_SHA1
        Export-AzsCertificate -filePath $exportCertpath -certPath $privCert  -pfxPassword $secPfxPass
        write-output ('[INFO]: Exported certificate: {0}' -f $exportCertpath)

    }
}

processCerts $AzsCommmonEndpoints
processCerts $AzsADFSEndpoints

# Test validity of certificates using Microsoft.AzureStack.ReadinessChecker module - Probably do this in another script
Invoke-AzsCertificateValidation -CertificateType Deployment -CertificatePath $CoreCertPath -pfxPassword $secPfxPass -RegionName $AzsRegion -FQDN $DNSZone -IdentitySystem $IdentitySystem 

Remove-Item -Path $signedcertsFolder -Recurse -Force

Write-Output ('[INFO]: TEMPORARY - PfxPassword: {0}' -f $pfxPassword )
Return $pfxPassword
# //TODO: capability to store password in KeyVault?