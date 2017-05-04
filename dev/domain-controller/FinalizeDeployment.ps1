Param(
  [string]$domainUserUPN,
  [string]$domainPassword,
  [string]$machineToJoin,
  [string]$groupToJoin,
  [string]$azureUserName, 
  [string]$azurePassword, 
  [string]$keyVaultName
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
$certPwd = ConvertTo-SecureString -String 'passw0rd!' -AsPlainText -Force

#generate pfx file
Export-PfxCertificate -Cert $certPath -FilePath $certPfx -Password $certPwd

#read from pfx file and generate secure string
$fileContentBytes = get-content $certPfx -Encoding Byte
$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
$certData = ConvertTo-SecureString -String $fileContentEncoded -AsPlainText -Force

# Login to azure
$azurePwd = ConvertTo-SecureString $azurePassword -AsPlainText -Force
$cred = New-Object -TypeName pscredential –ArgumentList $azureUserName, $azurePwd
Login-AzureRmAccount -Credential $cred

#put into keyvault
Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'certData' -SecretValue $certData
Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'certPassword' -SecretValue $certPwd
