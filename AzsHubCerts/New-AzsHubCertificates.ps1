#Requires -RunAsAdministrator
#Requires -Modules @{'ModuleName'='Microsoft.AzureStack.ReadinessChecker';'ModuleVersion'='1.2002.1111.69'}

# Title   : New-AzsHubCertificates.ps1
# Author  : Danny McDermott 
# Version : 0.1
# Date    : 23-04-2020
#

[CmdletBinding()]
    Param(
        [Parameter()][string]$azsregion,
        [Parameter()][string]$azsCertDir = 'c:\azsCerts',
        [Parameter()][String]$azsRegionFQDN,
        [Parameter()][String]$CaServer,
        [Parameter()][ValidateSet('AAD','ADFS')]
            [String]$IdentitySystem,
        [Parameter()][Switch]$AppService,
        [Parameter()][Switch]$DBAdapter,
        [Parameter()][Switch]$EventHubs,
        [Parameter()][Switch]$IoTHub,
        [Parameter()][Switch]$SkipDeployment,
        [Parameter()][System.Management.Automation.PSCredential]$CaCredential,
        [Parameter()][SecureString]$pfxPassword
    )


$ErrorActionPreference = 'stop'

# Description : Create Certificate Requests for an Azure Stack Hub Region.
function new-AzsCertFolder ($AzsCert, $Path ) {
    foreach ($Key in $AzsCert.Keys) {
        if (-not (Test-Path -Path "$Path\$($AzsCert[$key])")) {
            New-Item -ItemType Directory -Path "$Path\$($AzsCert[$key])"
        }
    }
}

 function processCerts{
    Param(
        $hash,
        $CoreCertPath,
        $secPfxPass
    )
        foreach ($signedCert in $hash.keys ) {
            $CTRStore = 'Cert:\LocalMachine\My\'
            $cert = Get-ChildItem -Path "$signedcertsFolder\$signedCert.crt"
            $privCert = Import-Certificate -FilePath $cert -CertStoreLocation $CTRStore -ErrorAction Stop 
            Write-Debug ('[INFO]: Imported certificate: {0}' -f $cert)
            Write-Debug ('[INFO]: {0} Thumbprint: {1}' -f $signedCert, $privCert.Thumbprint)
            remove-item -Path $cert.FullName 
            #$certHash.Add($signedCert, @{$privCert.Thumbprint = $privCert.Subject})

            # Check to see if the service requiring certs needs multiple endpoints. Put in the correct directory.
            $exportCertDir =('{0}\{1}' -f $CoreCertPath, $hash[$signedcert])
            if (Test-Path -Path $exportCertDir -PathType Container) {
                $exportCertpath =('{0}\{1}\{2}.pfx' -f $CoreCertPath, $hash[$signedcert], $signedCert )
            }
            else {
                $exportCertpath =('{0}\{1}.pfx' -f $CoreCertPath, $signedCert )
            }
            try{
                Write-Debug ('[INFO]: Exporting PFX Certificate: {0} to {1}' -f $privcert, $exportCertpath)
                Export-PfxCertificate -Cert $privCert -Password $secPfxPass -FilePath $exportCertpath -ChainOption BuildChain -NoProperties -Force -CryptoAlgorithmOption TripleDES_SHA1
            }
            catch {
                 # =< Windows 2016 does not have the crypt option
                 Write-Debug ('[INFO]: Exporting PFX Certificate: {0} to {1}' -f $privcert, $exportCertpath)
                 Export-PfxCertificate -Cert $privCert -Password $secPfxPass -FilePath $exportCertpath -ChainOption BuildChain -NoProperties -Force 
            }
            Write-Debug ('[INFO]: Exported certificate: {0}' -f $exportCertpath)

        }
    }

function New-AzsHubCertificates {
    [CmdletBinding()]
    Param(
        [Parameter()][string]$azsregion,
        [Parameter()][string]$azsCertDir = 'c:\azsCerts',
        [Parameter()][String]$azsRegionFQDN,
        [Parameter()][String]$CaServer,
        [Parameter()][ValidateSet('AAD','ADFS')]
            [String]$IdentitySystem,
        [Parameter()][Switch]$AppService,
        [Parameter()][Switch]$DBAdapter,
        [Parameter()][Switch]$EventHubs,
        [Parameter()][Switch]$IoTHub,
        [Parameter()][Switch]$SkipDeployment,
        [Parameter()][System.Management.Automation.PSCredential]$CaCredential,
        [Parameter()][SecureString]$pfxPassword
    )

    $subject = 'CN=Azure Stack Hub ' # set this if required

    #  Create folder structure to host certificates


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
    else {
        Write-Debug('[WARN]: Request Directory already exists: {0}' -f $outputDirectory)
    }

    # //TODO: Check if request directory already exists.  Script must have quit somewhere if it does

    # Create 
    if (-not ($SkipDeployment)) {
        New-AzsCertificateSigningRequest -certificateType Deployment -RegionName $AzsRegion -FQDN $DNSZone -OutputRequestPath $outputDirectory -IdentitySystem $IdentitySystem
    }
    if ($AppService){
        New-AzsCertificateSigningRequest -certificateType AppServices -RegionName $AzsRegion -FQDN $DNSZone -OutputRequestPath $OutputDirectory
    }
    if ($DBAdapter){
        New-AzsCertificateSigningRequest -certificateType DBAdapter -RegionName $AzsRegion -FQDN $DNSZone -OutputRequestPath $OutputDirectory
    }
    if ($EventHubs){
        New-AzsCertificateSigningRequest -certificateType EventHubs -RegionName $AzsRegion -FQDN $DNSZone -OutputRequestPath $OutputDirectory
    }
    if ($IoTHub){
        New-AzsCertificateSigningRequest -certificateType IoTHub -RegionName $AzsRegion -FQDN $DNSZone -OutputRequestPath $OutputDirectory
    }


    # Need to use the IP address, otherwise Kerberos complains.  Work out IP address for CA in the following 2 lines
    <# $hostEntry =[System.Net.Dns]::GetHostByName($caServer)
    $CAIP = $hostEntry.AddressList[0].IPAddressToString #>
    $CAIP = $CaServer
    #Setup WinRM
    ($currentsettings = winrm g winrm/config/client) | out-null
    # Check if there are existing entries, we do not want to over write them
    foreach ($entry in $currentSettings) {
        if ($entry -like '*TrustedHosts =*') {
            $servers = (($entry.Split('='))[1]).Trim()
        }
    }

    $serversArray =@()
    $trustHostWildcard = $false
    if ($servers.count -gt 0) { 
        foreach ($server in $servers.Split(',')) {
            # Check to see if the CA server IP already exists in WinRM
            if (($server.Trim() -eq $CAIP)) {
                Write-Debug ('[INFO]: Remote host {0} exists in WinRM' -f $server.Trim())
            }
            elseif (($server.Trim() -eq '*')) {
                Write-Debug ('[INFO]: Remote host {0} is a wildcard' -f $server.Trim())
            }
            else {
                # This isn't the CA IP, we want to preservce this entry
                $serversArray += $server.Trim()
                Write-Debug ('[INFO]: Remote host {0} added to WinRM' -f $server.Trim())
            }
        }
        
    }

    # Add the CA IP address to the WinRM trusted list
    if ($trustHostWildcard) {
        $list = '*'
    }
    else {
     $serversArray += $CAIP
     Write-Debug ('[INFO]: Remote host {0} added to WinRM' -f $CAIP)

     $list = $serversArray -join ", "
    }

    $TrustedHosts=  ('@{{TrustedHosts="{0}"}}' -f $list)
    # Update the WinRM config with the new trusted hosts...
    (winrm s winrm/config/client $TrustedHosts) | out-null

    # Setup the remote session to the CA Server
    ($caSession = New-PSSession -ComputerName $CAIP -Credential $CaCredential) | out-null

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

 <#    if ($RequestFileCount -ne $reqCount) {
        write-error ('[ERROR]: The required number of request files is not valid. Actual: {0}. Required: {1}.' -f $RequestFileCount, $reqCount )
        (Remove-PSSession -Session $caSession) | out-null
        break
    } #>


    Invoke-Command -Session $caSession -ScriptBlock {if (-not (test-path -path $using:remotefolder)){ md $using:remotefolder}} # Create the remote folder if not exist
    Copy-Item "$srcFolder\requests\*.req" -Destination "$remotefolder"  -ToSession $caSession -recurse -Force 

    $scriptblock= {
    param(
        [string]$certReqfolder = ''
    )

    Write-Debug ('[INFO]: Remote Cert Folder: {0}' -f $certReqfolder)
    $CertReqPath = 'C:\Windows\System32\certreq.exe'
    $CertUtilPath = 'C:\Windows\System32\certutil.exe'
    $result = (Invoke-Expression -Command $CertUtilPath) | Out-String | ConvertFrom-String
    $ca = (($result.P5).Replace("'","")).Replace("``","")
    $config = (($result.P18).Replace("'","")).Replace("``","")
    Write-Debug ('[INFO]: Retrieved CA: {0}' -f $ca)

    $CRTPath = $certReqfolder + "\certs"
            
    If (-not (Test-Path($CRTPath))){
            
        $null = new-item -Path $CRTPath -ItemType Directory
            
    }

    #parameters to pass to the CertUtil command
    $params = @(
    "-ca.cert" 
    "$CRTPath\$ca.cer"
    )

    Write-Debug ('[INFO]: Retrieving Public CA Certificate')
    & $CertUtilPath $params
    Write-Debug ('[INFO]: Retrieved Public CA Certificate')
    foreach ($request in (Get-ChildItem -Path $certReqfolder -filter *.req)){
        Write-Debug ('[INFO]: Processing Request: {0}' -f $request.FullName)
        $command = $CertReqPath + " -config " + $config + " -attrib CertificateTemplate:RASAndIASServer -submit " + $request.FullName
        $result = (Invoke-Expression -Command $command) | Out-String | ConvertFrom-String
    
        # Approve the request
        $id = $result.P2
        $command = $CertUtilPath + " -resubmit " + $id
        Invoke-Expression -Command $command

        # Retrieve the request
        
        Write-Debug ('[INFO]: Retrieving Signed Certificates')
        # .crt and .p7b
        if ($request.BaseName -match 'wildcard_sso_appservice') {
            $certname = 'wappsvc'
        }
        elseif (($request.BaseName).split('_')[0] -eq 'wildcard') {
            $certname = ($request.BaseName).split('_')[1]
        }
        else {
            $certname = ($request.BaseName).split('_')[0]
        }
        $CRTFilePath = $CRTPath + "\" + $certname + ".crt"
        $P7BFilePath = $CRTPath + "\" + $certname + ".p7b"
        $command = $CertReqPath + " -f -q -config " + $config + " -retrieve " + $id + " " + $CRTFilePath + " " + $P7BFilePath 
        Write-Debug ('[INFO]: Running: {0}' -f $command)
        Invoke-Expression -Command $command
    }
    }

    Invoke-Command -Session $caSession -ScriptBlock $scriptblock -ArgumentList $remotefolder
    if ( -not (Test-Path -Path $signedcertsFolder)) {
        $null = new-item -Path $signedcertsFolder -ItemType Directory
    }
    # Copy Signed Certs locally

    Write-Debug ('[INFO]: Copying Signed Certs from CA to Cloud Operator host.')
    Copy-Item "$remotefolder\certs\*.crt" -Destination $signedcertsFolder -FromSession $caSession -recurse -Force 

    Write-Debug ('[INFO]: Copying Public CA certificate from CA to Cloud Operator host.')
    Copy-Item "$remotefolder\certs\*.cer" -Destination $signedcertsFolder -FromSession $caSession -recurse -Force 

    # Tidy up folders on the CA
    Write-Debug ('[INFO]: Removing Temp files on the CA server.')
    invoke-command -Session $caSession -ScriptBlock {remove-item -Path "$using:remotefolder" -Recurse -Force }

    # Remove the remote session
    (Remove-PSSession -Session $caSession) | out-null

    # Remove the request Dir as we're done processing those
    Remove-Item -Path $requestsFolder -Recurse -Force
    Write-Debug ('[INFO]: Completed processing certificate requests')

    #  Determine If ADFS ID system
    $ADFS = $false
    If ($IdentitySystem -eq 'ADFS') {
        $ADFS = $true
    }


    # Create folder structure to host certificates

    # Folder to store deployment certificates
    $CoreCertPath = "$CertPath\$IdentitySystem"
    # Set up Certs for other services
    $AppSvcCertPath = "$CertPath\AppServices"
    $DBAdapterCertPath = "$CertPath\DBAdapter"
    $EVHubsCertPath = "$CertPath\EventHubs"
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

    $AppSvcEndpoints = @{
        'api'="API";
        'wappsvc'="DefaultDomain";
        'sso'="Identity";
        'ftp'="Publishing";
    }
    $DBAdapterEndpoints = @{
        'DBAdapter'="DBAdapter"
    }
    $EvHubEndPoints = @{
        'eventhub'="EventHubs"
    }
    $IotHubEndPoints = @{
        'iothub'="IoTHub"
    }

    if (-not (Test-Path -Path $CertPath  -PathType Container)) {
        write-error ('[ERROR]: The location for the certificate files is not present {0}.' -f $CertPath )
        break
    }

    # Create a new secure password for the pfx file if not specified
    if (-not($pfxPassword)) {
        # Generate a random password using the system.web GeneratePassword functionality
        Add-Type -AssemblyName System.Web 
        $PasswordLength = 16
        $SpecialCharCount = 1
        $pfxPassword = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, $SpecialCharCount)
        Write-Debug ('[INFO]: PfxPassword: {0}' -f $pfxPassword)
        $secPfxPass = ConvertTo-SecureString -AsPlainText $pfxPassword -Force
        $pfxPassAutoGen = $true
    }
    else {
        $secPfxPass = $pfxPassword
        $pfxPassAutoGen = $false
                
    }
    # Process signed responses from CA
    $script:certHash = @{}
    $signedcertsFolder = $certpath + '\signedcerts'
    if (-not (Test-Path -Path $signedcertsFolder -PathType Container)) {
        write-error ('[ERROR]: The location for the signed certificate files is not present {0}.' -f $signedcertsFolder )
        break
    }

    # Import the Public CA from the Signing CA.  Will stop errors when checking the cert validity
    $publicCAFile = Get-ChildItem -Path "$signedcertsFolder\*.cer"

    If ($publicCAFile.count -eq 1) {
       Write-Debug ('[INFO]: Public CA Cert found: {0} ' -f $publicCAFile.Name)        
       Import-Certificate -FilePath $publicCAFile.FullName -CertStoreLocation Cert:\LocalMachine\Root -Verbose         
       Write-Debug ('[INFO]: Imported Public CA Cert: {0} ' -f $publicCAFile.Name)
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

    #Create the folder structure for core deployment certs
    new-AzsCertFolder $AzsCommmonEndpoints -Path $CoreCertPath
    # Process the Certificates
    if (-not ($SkipDeployment)) {
        processCerts -hash $AzsCommmonEndpoints -CoreCertPath $CoreCertPath -secPfxPass $secPfxPass
    }
    if ($adfs) {
        new-AzsCertFolder $AzsADFSEndpoints -Path $CoreCertPath
        processCerts -hash $AzsADFSEndpoints -CoreCertPath $CoreCertPath -secPfxPass $secPfxPass
    }
    if ($AppService){
        new-AzsCertFolder $AppSvcEndpoints -Path $AppSvcCertPath
        processCerts -hash $AppSvcEndpoints -CoreCertPath $AppSvcCertPath -secPfxPass $secPfxPass
    }
    if ($DBAdapter){
        if (-not (Test-Path -Path $DBAdapterCertPath -PathType Container)) {
            $null = mkdir -Path $DBAdapterCertPath
        }
        processCerts -hash $DBAdapterEndpoints -CoreCertPath $DBAdapterCertPath -secPfxPass $secPfxPass
    }
    if ($EventHubs){
        if (-not (Test-Path -Path $EVHubsCertPath -PathType Container)) {
            $null = mkdir -Path $EVHubsCertPath
        }
        processCerts -hash $EvHubEndPoints -CoreCertPath $EVHubsCertPath -secPfxPass $secPfxPass
    }
    if ($IoTHub){
        if (-not (Test-Path -Path $IoTHubCertPath -PathType Container)) {
            $null = mkdir -Path $IoTHubCertPath
        }
        processCerts -hash $IotHubEndPoints -CoreCertPath $IoTHubCertPath -secPfxPass $secPfxPass
    }

    # Test validity of certificates using Microsoft.AzureStack.ReadinessChecker module.
    if (-not ($SkipDeployment)) {
        Invoke-AzsCertificateValidation -CertificateType Deployment -CertificatePath $CoreCertPath -pfxPassword $secPfxPass -RegionName $AzsRegion -FQDN $DNSZone -IdentitySystem $IdentitySystem 
    }
    if ($AppService){
        Invoke-AzsCertificateValidation -CertificateType AppServices -CertificatePath $AppSvcCertPath -pfxPassword $secPfxPass -RegionName $AzsRegion -FQDN $DNSZone
    }
    if ($DBAdapter){
        Invoke-AzsCertificateValidation -CertificateType DBAdapter -CertificatePath $DBAdapterCertPath -pfxPassword $secPfxPass -RegionName $AzsRegion -FQDN $DNSZone
    }
    if ($EventHubs){
        Invoke-AzsCertificateValidation -CertificateType EventHubs -CertificatePath $EVHubsCertPath -pfxPassword $secPfxPass -RegionName $AzsRegion -FQDN $DNSZone
    }
    if ($IoTHub){
        Invoke-AzsCertificateValidation -CertificateType IoTHub -CertificatePath $IoTHubCertPath -pfxPassword $secPfxPass -RegionName $AzsRegion -FQDN $DNSZone
    }

    # Tidy up
    Remove-Item -Path $signedcertsFolder -Recurse -Force

    if ($pfxPassAutoGen) {
        Write-Debug ('[INFO]: PfxPassword: {0}' -f $pfxPassword )
        Return $pfxPassword
    }
}



$params =@{
    azsregion = $azsRegion
    azsRegionFQDN = $FQDN
    CaServer = $CertServer
    IdentitySystem = $IdentitySystem
    CaCredential = $caCredential
    AppService = $AppService
    DBAdapter = $DBAdapter
    EventHubs = $EventHubs
    IoTHubs = $IoTHub
    SkipDeployment = $SkipDeployment

}

if ($pfxPassword) {
    $params.Add('pfxPassword', $pfxPassword)
}


New-AzsHubCertificates @params
