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


# create self signed certificate

$certLoc = 'cert:Localmachine\My'
$cert = New-SelfSignedCertificate -certstorelocation $certLoc -DnsName "pcoip-gateway.cloudapp.net" 

#generate pfx file
$certPath = $certLoc + '\' + $cert.Thumbprint
$certPfx = 'C:\WindowsAzure\mySelfSignedCert.pfx'
$randomPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})

$certPwd = ConvertTo-SecureString -String $randomPswd -AsPlainText -Force
Export-PfxCertificate -Cert $certPath -FilePath $certPfx -Password $certPwd

#read from pfx file and convert to base64 string
$fileContentEncoded = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($certPfx))

# Login to azure
$azurePwd = ConvertTo-SecureString $azurePassword -AsPlainText -Force
$azureloginCred = New-Object -TypeName pscredential –ArgumentList $azureUserName, $azurePwd
Login-AzureRmAccount -Credential $azureloginCred

# deploy application gateway
$parameters = @{}
$parameters.Add(“subnetRef”, $subnetRef)
$parameters.Add(“skuName”, "Standard_Small")
$parameters.Add(“capacity”, 1)
$parameters.Add(“backendIpAddressDefault”, "$backendIpAddressDefault")
$parameters.Add(“backendIpAddressForPathRule1”, "$backendIpAddressForPathRule1")
$parameters.Add(“pathMatch1”, "/pcoip-broker/*")
$parameters.Add(“certData”, "$fileContentEncoded")
$parameters.Add(“certPassword”, "$randomPswd")

New-AzureRmResourceGroupDeployment -Mode Incremental -Name "DeployAppGateway" -ResourceGroupName $rgName -TemplateUri $templateUri -TemplateParameterObject $parameters


#regenerate cert with the fqdn
$fqdn = (Get-AzureRmPublicIpAddress -ResourceGroupName $rgName -Name publicip1).DnsSettings.Fqdn

$certLoc = 'cert:Localmachine\My'
$startDate = [DateTime]::Now.AddDays(-1)

$subject = "cn=" + $fqdn + ",O=Teradici Corporation,OU=SoftPCoIP,L=Burnaby,ST=BC,C=CA"

$cert = New-SelfSignedCertificate -certstorelocation $certLoc -Subject $subject -KeyLength 3072 -FriendlyName "PCoIP Application Gateway" -NotBefore $startDate -TextExtension @("2.5.29.19={critical}{text}ca=1") -HashAlgorithm SHA384 -KeyUsage DigitalSignature, CertSign,  CRLSign, KeyEncipherment

$certPath = $certLoc + '\' + $cert.Thumbprint

$certPfx = 'C:\WindowsAzure\mySelfSignedCert.pfx'

$randomPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})

$certPwd = ConvertTo-SecureString -String $randomPswd -AsPlainText -Force
Export-PfxCertificate -Cert $certPath -FilePath $certPfx -Password $certPwd

$appGwObj = Get-AzureRmApplicationGateway -ResourceGroupName $rgName -Name applicationGateway1

Remove-AzureRmApplicationGatewaySslCertificate -ApplicationGateway $appGwObj -Name appGatewaySslCert

Add-AzureRmApplicationGatewaySslCertificate -ApplicationGateway $appGwObj -Name appGatewaySslCert -CertificateFile $certPfx -Password $randomPswd

Set-AzureRmApplicationGateway -ApplicationGateway $appGwObj




