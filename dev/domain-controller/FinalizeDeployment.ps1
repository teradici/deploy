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
$cert = New-SelfSignedCertificate -certstorelocation $certLoc -Type Custom -Subject "CN=PCoIP-APP-GateWay.teradici.com,O=Teradici Corporation,OU=SoftPCoIP,L=Burnaby,ST=BC,C=CA"  -KeyLength 3072 -FriendlyName "PCoIP Application Gateway" -HashAlgorithm SHA384

#generate pfx file
$certPath = $certLoc + '\' + $cert.Thumbprint
$certPfx = 'C:\WindowsAzure\mySelfSignedCert.pfx'
$randomPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
$certPwd = ConvertTo-SecureString -String $randomPswd -AsPlainText -Force
Export-PfxCertificate -Cert $certPath -FilePath $certPfx -Password $certPwd

#read from pfx file and generate 64base encoded string
$fileContentBytes = get-content $certPfx -Encoding Byte
$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)

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

$deployName = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})

New-AzureRmResourceGroupDeployment -Mode Incremental -Name $deployName -ResourceGroupName $rgName -TemplateUri $templateUri -TemplateParameterObject $parameters