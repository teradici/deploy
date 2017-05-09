Param(
  [string]$deploymentName,
  [string]$rgName,
  [string]$domainUserUPN,
  [string]$domainPassword,
  [string]$machineToJoin,
  [string]$groupToJoin,
  [string]$azureUserName, 
  [string]$azurePassword, 
  #[string]$keyVaultName,
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
$cert = New-SelfSignedCertificate -certstorelocation $certLoc -dnsname local.teradici.com

$certPath = $certLoc + '\' + $cert.Thumbprint
$certPfx = 'C:\WindowsAzure\mySelfSignedCert.pfx'
$randomPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
$certPwd = ConvertTo-SecureString -String $randomPswd -AsPlainText -Force

#generate pfx file
Export-PfxCertificate -Cert $certPath -FilePath $certPfx -Password $certPwd

#read from pfx file and generate 64base encoded string
$fileContentBytes = get-content $certPfx -Encoding Byte
$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
$certData = ConvertTo-SecureString -String $fileContentEncoded -AsPlainText -Force

# Login to azure
$azurePwd = ConvertTo-SecureString $azurePassword -AsPlainText -Force
$cred = New-Object -TypeName pscredential –ArgumentList $azureUserName, $azurePwd
Login-AzureRmAccount -Credential $cred

#set keyvault policy
#$rgObj = Get-AzureRmResourceGroup -ResourceGroupName $rgName
#New-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $rgName -Location $rgObj.Location -EnabledForTemplateDeployment -EnabledForDeployment
#Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -UserPrincipalName $azureUserName -PermissionsToSecrets all

#put into keyvault
#Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'certData' -SecretValue $certData
#Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'certPassword' -SecretValue $certPwd

$parameters = @{}
$parameters.Add(“subnetRef”, $subnetRef)
$parameters.Add(“skuName”, "Standard_Small")
$parameters.Add(“capacity”, 1)
$parameters.Add(“backendIpAddressDefault”, "$backendIpAddressDefault")
$parameters.Add(“backendIpAddressForPathRule1”, "$backendIpAddressForPathRule1")
$parameters.Add(“pathMatch1”, "/pcoip-broker/*")
$parameters.Add(“certData”, "$fileContentEncoded")
$parameters.Add(“certPassword”, "$certPwd")

New-AzureRmResourceGroupDeployment -Mode Incremental -Name $deploymentName -ResourceGroupName $rgName -TemplateUri $templateUri -TemplateParameterObject $parameters