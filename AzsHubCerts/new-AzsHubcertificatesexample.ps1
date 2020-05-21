# Generate a random password using the system.web GeneratePassword functionality.  You can also specifiy your own password (un-remark the $pfxPassword variable)
Add-Type -AssemblyName System.Web 
$PasswordLength = 16
$SpecialCharCount = 1
$pfxPasswd = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, $SpecialCharCount)
#$pfxPasswd ='<your passsword>'
$secPfxPass = ConvertTo-SecureString -AsPlainText $pfxPasswd -Force


#Choose how you want to specify your credentials.  Either:

# 1. Specify in the script...
$caPasswordSecure = '<CA Password>' | ConvertTo-SecureString -AsPlainText -Force
$causer='domain\administrator'
$caCredential = New-Object System.Management.Automation.PSCredential ($caUser,$caPasswordSecure)

# 2. or via get-credential
#$caCredential = get-credential -Message 'Enter the Credentials for the CA server.'

# Name of the Azure Stack Hub region
$azsRegion = 'azs1'

# FQDN of the domain that will host the Azure Stack Hub region
$FQDN = '<FQDN>'

# Specify the IP address to avoid kerberos issues!
$CertServer = '<CA IP>'

# Choose the Identity system type to generate certificates for
$IdentitySystem = 'AAD' # ADFS or AAD

$params =@{
    azsregion = $azsRegion
    azsRegionFQDN = $FQDN
    CaServer = $CertServer
    IdentitySystem = $IdentitySystem
    CaCredential = $caCredential
    AppService = $true
    DBAdapter = $true
    EventHubs = $true
    IoTHub = $true
    SkipDeployment = $false
    pfxPassword = $secPfxPass
  
}

cd $PSScriptRoot

.\New-AzsHubCertificates.ps1 @params

Write-Output ('[INFO]: PfxPassword: {0}' -f $pfxPasswd)
