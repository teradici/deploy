Param(
  [string]$rgName,
  [string]$domainUserUPN,
  [string]$domainPassword,
  [string]$machineToJoin,
  [string]$groupToJoin,
  [string]$azureUserName, 
  [string]$azurePassword, 
  [string]$subnetRef,
  [string]$backendIpAddressDefault,
  [string]$backendIpAddressForPathRule1,
  [string]$templateUri
)

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

Install-Module AzureRM -Force

# Finalize the deployment of the system.
# When all the machines are deployed, then this script will do any finalization functions.
# Currently, that finalization is to just add the deployed administrator desktop/application server machine to the correct domain group.

# Make sure we're using the domain account instead of the local admin account
$passwd = ConvertTo-SecureString $domainPassword -AsPlainText -Force

$cred = New-Object -TypeName pscredential –ArgumentList $domainUserUPN, $passwd
$psSession = New-PSSession -Credential $cred

Invoke-Command -Session $psSession -ScriptBlock {
	# Make the AD group for machines
    New-ADGroup -name $using:groupToJoin -GroupScope Global
	Add-ADGroupMember -Identity $using:groupToJoin -Members $machineToJoin
}

# Login to azure
$azurePwd = ConvertTo-SecureString $azurePassword -AsPlainText -Force
$azureloginCred = New-Object -TypeName pscredential –ArgumentList $azureUserName, $azurePwd
Login-AzureRmAccount -Credential $azureloginCred

$rgObj = Get-AzureRmResourceGroup -Name $rgName

# create self signed certificate
$certLoc = 'cert:Localmachine\My'
$domainNameLabel = 'pcoipappgw'
$fqdn = $domainNameLabel + "." + $rgObj.location + ".cloudapp.azure.com"
$startDate = [DateTime]::Now.AddDays(-1)
$cert = New-SelfSignedCertificate -certstorelocation $certLoc -DnsName $fqdn  -KeyLength 3072 -FriendlyName "PCoIP Application Gateway" -NotBefore $startDate -TextExtension @("2.5.29.19={critical}{text}ca=1") -HashAlgorithm SHA384 -KeyUsage DigitalSignature, CertSign,  CRLSign, KeyEncipherment

#generate pfx file from certificate
$certPath = $certLoc + '\' + $cert.Thumbprint

$pfxPath = 'C:\WindowsAzure'
if (!(Test-Path -Path $pfxPath)) {
	New-Item $pfxPath -type directory
}
$certPfx = $pfxPath + '\mySelfSignedCert.pfx'

$certPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
$secureCertPswd = ConvertTo-SecureString -String $certPswd -AsPlainText -Force
Export-PfxCertificate -Cert $certPath -FilePath $certPfx -Password $secureCertPswd

#read from pfx file and convert to base64 string
$fileContentEncoded = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($certPfx))


# deploy application gateway
$parameters = @{}
$parameters.Add(“subnetRef”, $subnetRef)
$parameters.Add(“skuName”, "Standard_Small")
$parameters.Add(“capacity”, 1)
$parameters.Add(“backendIpAddressDefault”, "$backendIpAddressDefault")
$parameters.Add(“backendIpAddressForPathRule1”, "$backendIpAddressForPathRule1")
$parameters.Add(“pathMatch1”, "/pcoip-broker/*")
$parameters.Add(“certData”, "$fileContentEncoded")
$parameters.Add(“certPassword”, "$certPswd")
$parameters.Add("domainNameLabel", $domainNameLabel)

New-AzureRmResourceGroupDeployment -Mode Incremental -Name "DeployAppGateway" -ResourceGroupName $rgName -TemplateUri $templateUri -TemplateParameterObject $parameters