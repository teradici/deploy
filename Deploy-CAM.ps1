# Deploy-CAM.ps1
#
param
(
	[string]
	$LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPCAMInstall",

	[Parameter(Mandatory)]
	[String]$sourceURI,

	[Parameter(Mandatory)]
	[String]$templateURI,

	[Parameter(Mandatory)]
	[String]$templateAgentURI,

	[Parameter(Mandatory)]
	[System.Management.Automation.PSCredential]$registrationCodeAsCred,

	[string]
	$javaInstaller = "jdk-8u91-windows-x64.exe",

	[string]
	$tomcatInstaller = "apache-tomcat-8.0.39-windows-x64.zip",

	[string]
	$brokerWAR = "pcoip-broker.war",

	[string]
	$adminWAR = "CloudAccessManager.war",

	[string]
	$agentARM = "server2016-standard-agent.json",

	[string]
	$gaAgentARM = "server2016-graphics-agent.json",

	[Parameter(Mandatory)]
	[String]$domainFQDN,

	[Parameter(Mandatory)]
	[String]$adminDesktopVMName,

	[Parameter(Mandatory)]
	[String]$domainGroupAppServersJoin,

	[Parameter(Mandatory)]
	[String]$existingVNETName,

	[Parameter(Mandatory)]
	[String]$existingSubnetName,

	[Parameter(Mandatory)]
	[String]$storageAccountName,

	[Parameter(Mandatory)]
	[System.Management.Automation.PSCredential]$VMAdminCreds,

	[Parameter(Mandatory)]
	[System.Management.Automation.PSCredential]$DomainAdminCreds,

	[Parameter(Mandatory)]
	[System.Management.Automation.PSCredential]$AzureCreds,

	[Parameter(Mandatory=$false)]
	[String]$tenantID,

	[Parameter(Mandatory)]
	[String]$DCVMName, #without the domain suffix

	[Parameter(Mandatory)]
	[String]$RGName, #Azure resource group name

	[Parameter(Mandatory)]
	[String]$gitLocation,

	[Parameter(Mandatory)]
	[String]$sumoCollectorID,

	[Parameter(Mandatory=$false)]
	[String]$brokerPort = "8444",

	#For application gateway
	[Parameter(Mandatory=$true)]
	[string]$AGsubnetRef,

	[Parameter(Mandatory=$true)]
	[string]$AGbackendIpAddressDefault,

	[Parameter(Mandatory=$true)]
	[string]$AGbackendIpAddressForPathRule1,

	[Parameter(Mandatory=$true)] #passed as credential to prevent logging of any embedded access keys
	[System.Management.Automation.PSCredential]$AGtemplateUri,

	[Parameter(Mandatory=$true)]
	[string]$camSaasUri,

	[Parameter(Mandatory=$false)]
	[bool]$verifyCAMSaaSCertificate=$true
)


function Login-AzureRmAccountWithBetterReporting($Credential)
{
	try
	{
		$userName = $Credential.userName
		Login-AzureRmAccount -Credential $Credential @args -ErrorAction stop

		Write-Host "Successfully Logged in $userName"
	}
	catch
	{
		$es = "Error authenticating AzureAdminUsername $userName for Azure subscription access.`n"
		$exceptionMessage = $_.Exception.Message
		$exceptionMessageErrorCode = $exceptionMessage.split(':')[0]

		switch($exceptionMessageErrorCode)
		{
			"AADSTS50076" {$es += "Please ensure your account does not require Multi-Factor Authentication`n"; break}
			"Federated service at https" {$es += "Unable to perform federated login - Unknown username or password?`n"; break}
			"unknown_user_type" {$es += "Please ensure your username is in UPN format. e.g., user@example.com`n"; break}
			"AADSTS50126" {$es += "User not found in directory`n"; break}
			"AADSTS70002" {$es += "Please check your password`n"; break}
		}


		throw "$es$exceptionMessage"

	}
}


function Register-CAM()
{
	Param(
		[bool]
		$verifyCAMSaaSCertificate = $true,
		
		# Retry for CAM Registration
		$retryCount = 3,
		$retryDelay = 10,

		[parameter(Mandatory=$true)] 
		$subscriptionId,
		
		[parameter(Mandatory=$true)]
		$client,
		
		[parameter(Mandatory=$true)]
		$key,
		
		[parameter(Mandatory=$true)]
		$tenant,

		[parameter(Mandatory=$true)]
		$RGName,

		[parameter(Mandatory=$true)]
		$registrationCode,

		[parameter(Mandatory=$true)]
		$camSaasBaseUri
	)

    $camDeploymentInfo = @{} #start with an empty hash map
	$camRegistrationError = ""
	for($idx = 0; $idx -lt $retryCount; $idx++) {
		try {
			$certificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy

			if (!$verifyCAMSaaSCertificate) {
				# Do this so SSL Errors are ignored
				add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
	public bool CheckValidationResult(
		ServicePoint srvPoint, X509Certificate certificate,
		WebRequest request, int certificateProblem) {
		return true;
	}
}
"@

				[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
			}
			##


			$userRequest = @{
				username = $client
				password = $key
				tenantId = $tenant
			}
			$registerUserResult = ""
			try {
				$registerUserResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/auth/users") -Body $userRequest
			} catch {
				if ($_.ErrorDetails.Message) {
					$registerUserResult = ConvertFrom-Json $_.ErrorDetails.Message
				} else {
					throw $_
				}	
			}
			Write-Verbose (ConvertTo-Json $registerUserResult)
			# Check if registration succeeded or if it has been registered previously
			if( !(($registerUserResult.code -eq 201) -or ($registerUserResult.data.reason.ToLower().Contains("already exist"))) ) {
				throw ("Failed to register with CAM. Result was: " + (ConvertTo-Json $registerUserResult))
			}

			Write-Host "Cloud Access Manager Frontend has been registered succesfully"

			# Get a Sign-in token
			$signInResult = ""
			try {
				$signInResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/auth/signin") -Body $userRequest
			} catch {
				if ($_.ErrorDetails.Message) {
					$signInResult = ConvertFrom-Json $_.ErrorDetails.Message
				} else {
					throw $_
				}							
			}
			Write-Verbose ((ConvertTo-Json $signInResult) -replace "\.*token.*", 'Token": "Sanitized"')
			# Check if signIn succeded
			if ($signInResult.code -ne 200) {
				throw ("Signing in failed. Result was: " + (ConvertTo-Json $signInResult))
			}
			$tokenHeader = @{
				authorization=$signInResult.data.token
			}
			Write-Host "Cloud Access Manager sign in succeeded"

			# Register Deployment
			$deploymentRequest = @{
				resourceGroup = $RGName
				subscriptionId = $subscriptionId
				registrationCode = $registrationCode
			}
			$registerDeploymentResult = ""
			try {
				$registerDeploymentResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/deployments") -Body $deploymentRequest -Headers $tokenHeader
			} catch {
				if ($_.ErrorDetails.Message) {
					$registerDeploymentResult = ConvertFrom-Json $_.ErrorDetails.Message
				} else {
					throw $_
				}
			}
			Write-Verbose ((ConvertTo-Json $registerDeploymentResult) -replace "\.*registrationCode.*", 'registrationCode":"Sanitized"')
			# Check if registration succeeded
			if( !( ($registerDeploymentResult.code -eq 201) -or ($registerDeploymentResult.data.reason.ToLower().Contains("already exist")) ) ) {
				throw ("Registering Deployment failed. Result was: " + (ConvertTo-Json $registerDeploymentResult))
			}
			$deploymentId = ""
			# Get the deploymentId
			if( ($registerDeploymentResult.code -eq 409) -and ($registerDeploymentResult.data.reason.ToLower().Contains("already exist")) ) {
				# Deployment is already registered so the deplymentId needs to be retrieved
				$registeredDeployment = ""
				try {
					$registeredDeployment = Invoke-RestMethod -Method Get -Uri ($camSaasBaseUri + "/api/v1/deployments") -Body $deploymentRequest -Headers $tokenHeader
					$deploymentId = $registeredDeployment.data.deploymentId
				} catch {
					if ($_.ErrorDetails.Message) {
						$registeredDeployment = ConvertFrom-Json $_.ErrorDetails.Message
						throw ("Getting Deployment ID failed. Result was: " + (ConvertTo-Json $registeredDeployment))
					} else {
						throw $_
					}								
				}
			} else {
				$deploymentId = $registerDeploymentResult.data.deploymentId
			}

			if ( !$deploymentId ) {
				throw ("Failed to get a Deployment ID")
			}

			$camDeploymentInfo.Add("CAM_USERNAME",$userRequest.username)
			$camDeploymentInfo.Add("CAM_PASSWORD",$userRequest.password)
			$camDeploymentInfo.Add("CAM_TENANTID",$userRequest.tenantId)
			$camDeploymentInfo.Add("CAM_URI",$camSaasBaseUri)
			$camDeploymentInfo.Add("CAM_DEPLOYMENTID",$deploymentId)

			Write-Host "Deployment has been registered succesfully with Cloud Access Manager"

			break;
		} catch {
			$camRegistrationError = $_
			Write-Verbose ( "Attempt {0} of $retryCount failed due to Error: {1}" -f ($idx+1), $camRegistrationError )
			Start-Sleep -s $retryDelay
		} finally {
			# restore CertificatePolicy 
			[System.Net.ServicePointManager]::CertificatePolicy = $certificatePolicy
		}
	}
	if($camRegistrationError) {
		throw $camRegistrationError
	}
	return $camDeploymentInfo
}


function createAndPopulateKeyvault()
{
	Param(
		[parameter(Mandatory=$true)] 
		[String]
		$RGName,
		
		[parameter(Mandatory=$true)] 
		[String]
		$spName,

		[parameter(Mandatory=$true)]
		[System.Management.Automation.PSCredential]
		$registrationCodeAsCred,
		
		[parameter(Mandatory=$true)]
		[System.Management.Automation.PSCredential]
		$DomainJoinCreds
	)

	try{

		#KeyVault names must be globally (or at least regionally) unique, so make a unique string
		$generatedKVID = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$kvName = "CAM-$generatedKVID"

		Write-Host "Creating Azure KeyVault $kvName"

		$rg = Get-AzureRmResourceGroup -ResourceGroupName $RGName
		New-AzureRmKeyVault -VaultName $kvName -ResourceGroupName $RGName -Location $rg.Location -EnabledForTemplateDeployment -EnabledForDeployment

		Write-Host "Populating Azure KeyVault $kvName"
		
		$registrationCode = $registrationCodeAsCred.Password

		$rcSecretName = 'cloudAccessRegistrationCode'
		$djSecretName = 'domainJoinPassword'

		$rcSecret = $null
		$djSecret = $null

		#keyvault populate retry is to catch the case where the DNS has not been updated
		#from the keyvault creation by the time we get here
		$keyVaultPopulateRetry = 60
		while($keyVaultPopulateRetry -ne 0)
		{
			$keyVaultPopulateRetry--

			try
			{
				Set-AzureRmKeyVaultAccessPolicy -VaultName $kvName -ServicePrincipalName $spName -PermissionsToSecrets get, set -ErrorAction stop

				$rcSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $rcSecretName -SecretValue $registrationCode -ErrorAction stop
				$djSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $djSecretName -SecretValue $DomainJoinCreds.Password -ErrorAction stop
				break
			}
			catch
			{
				Write-Host "Waiting for key vault: $keyVaultPopulateRetry"
				if ( $keyVaultPopulateRetry -eq 0)
				{
					#re-throw whatever the original exception was
					throw
				}
				Start-sleep -Seconds 1
			}
		}

		$rcSecretVersionedURL = $rcSecret.Id
		$rcSecretURL = $rcSecretVersionedURL.Substring(0, $rcSecretVersionedURL.lastIndexOf('/'))

		$djSecretVersionedURL = $djSecret.Id
		$djSecretURL = $djSecretVersionedURL.Substring(0, $djSecretVersionedURL.lastIndexOf('/'))


		Write-Host "Creating Local Admin Password for new machines"

		$localAdminPasswordStr =  "5!" + (-join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})) # "5!" is to ensure numbers and symbols

		$localAdminPassword = ConvertTo-SecureString $localAdminPasswordStr -AsPlainText -Force

		$laSecretName = 'localAdminPassword'
		$laSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $laSecretName -SecretValue $localAdminPassword
		$laSecretVersionedURL = $laSecret.Id
		$laSecretURL = $laSecretVersionedURL.Substring(0, $laSecretVersionedURL.lastIndexOf('/'))

		# create self signed certificate for application gateway. Administrators can override the self signed certificate if desired in future.
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        $isAdminSession = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if(!$isAdminSession) { throw "You must be running as adminsitrator to create the self-signed certificate for the application gateway" }


		$certLoc = 'cert:Localmachine\My'
		$startDate = [DateTime]::Now.AddDays(-1)
		$subject = "CN=localhost,O=Teradici Corporation,OU=SoftPCoIP,L=Burnaby,ST=BC,C=CA"
		$cert = New-SelfSignedCertificate -certstorelocation $certLoc -DnsName "*.cloudapp.net" -Subject $subject -KeyLength 3072 `
			-FriendlyName "PCoIP Application Gateway" -NotBefore $startDate -TextExtension @("2.5.29.19={critical}{text}ca=1") `
			-HashAlgorithm SHA384 -KeyUsage DigitalSignature, CertSign, CRLSign, KeyEncipherment

		#generate pfx file from certificate
		$certPath = $certLoc + '\' + $cert.Thumbprint

		$pfxPath = $env:temp
		$pfxFileRoot = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})

		$certPfx = $pfxPath + "\$pfxFileRoot.pfx"

		#generate password for pfx file
		$certPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$secureCertPswd = ConvertTo-SecureString -String $certPswd -AsPlainText -Force

		#export pfx file
		Export-PfxCertificate -Cert $certPath -FilePath $certPfx -Password $secureCertPswd

		#read from pfx file and convert to base64 string
		$fileContentEncoded = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($certPfx))

		$FECertificate = ConvertTo-SecureString $fileContentEncoded -AsPlainText -Force

		$FECertSecretName = 'CAMFECertificate'
		$FECertSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $FECertSecretName -SecretValue $FECertificate
		$FECertSecretVersionedURL = $FECertSecret.Id
		$FECertSecretURL = $FECertSecretVersionedURL.Substring(0, $FECertSecretVersionedURL.lastIndexOf('/'))

		$FECertPasswordSecretName = 'CAMFECertificatePassword'
		$FECertPasswordSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $FECertPasswordSecretName -SecretValue $secureCertPswd
		$FECertPasswordSecretVersionedURL = $FECertPasswordSecret.Id
		$FECertPasswordSecretURL = $FECertPasswordSecretVersionedURL.Substring(0, $FECertPasswordSecretVersionedURL.lastIndexOf('/'))

		$secretHash = @{}
		$secretHash.Add($rcSecretName,$rcSecretURL)
		$secretHash.Add($djSecretName,$djSecretURL)
		$secretHash.Add($laSecretName,$laSecretURL)
		$secretHash.Add($FECertSecretName,$FECertSecretURL)
		$secretHash.Add($FECertPasswordSecretName,$FECertPasswordSecretURL)
	}
	finally {
		#done with files
		if(Test-Path $certPfx) { Remove-Item $certPfx -ErrorAction SilentlyContinue }
		if(Test-Path $certPath) { Remove-Item $certPath -ErrorAction SilentlyContinue }
	}
	return $secretHash
}




<#
	$standardVMSize = "Standard_D2_v3"
	$graphicsVMSize = "Standard_NV6"

	$dcvmfqdn = "$DCVMName.$domainFQDN"
	$pbvmfqdn = "$env:computername.$domainFQDN"
	$family   = "Windows Server 2016"

	#Java locations
	$JavaRootLocation = "$env:systemdrive\Program Files\Java\jdk1.8.0_91"
	$JavaBinLocation = $JavaRootLocation + "\bin"
	$JavaLibLocation = $JavaRootLocation + "\jre\lib"

	#Tomcat locations
	$localtomcatpath = "$env:systemdrive\tomcat"
	$CatalinaHomeLocation = "$localtomcatpath\apache-tomcat-8.0.39"
	$CatalinaBinLocation = $CatalinaHomeLocation + "\bin"

	$brokerServiceName = "CAMBroker"
	$AUIServiceName = "CAMAUI"

	# Retry for CAM Registration
	$retryCount = 3
	$delay = 10

	Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node "localhost"
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

		xRemoteFile Download_Java_Installer
		{
			Uri = "$sourceURI/$javaInstaller"
			DestinationPath = "$LocalDLPath\$javaInstaller"
			MatchSource = $false
		}

		xRemoteFile Download_Tomcat_Installer
		{
			Uri = "$sourceURI/$tomcatInstaller"
			DestinationPath = "$LocalDLPath\$tomcatInstaller"
			MatchSource = $false
		}

		xRemoteFile Download_Keystore
		{
			Uri = "$sourceURI/.keystore"
			DestinationPath = "$LocalDLPath\.keystore"
			MatchSource = $false
		}

		xRemoteFile Download_Broker_WAR
		{
			Uri = "$sourceURI/$brokerWAR"
			DestinationPath = "$LocalDLPath\$brokerWAR"
			MatchSource = $false
		}

		xRemoteFile Download_Admin_WAR
		{
			Uri = "$sourceURI/$adminWAR"
			DestinationPath = "$LocalDLPath\$adminWAR"
			MatchSource = $false
		}

		xRemoteFile Download_Agent_ARM
		{
			Uri = "$templateAgentURI/$agentARM"
			DestinationPath = "$LocalDLPath\$agentARM"
			MatchSource = $false
		}

		xRemoteFile Download_Ga_Agent_ARM
		{
			Uri = "$templateAgentURI/$gaAgentARM"
			DestinationPath = "$LocalDLPath\$gaAgentARM"
			MatchSource = $false
		}
#>

function Create-CAMAppSP()
{
	param(
		$RGName
	)

	#Application name
	$appName = "CAM-$RGName"
	Write-Host "Calling Azure Active Directory to make app $appName and a service principal."

	# 16 letter password
	$generatedPassword = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
	$generatedID = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
	$appURI = "https://www.$generatedID.com"

	Write-Host "Purge any registered app's with the same name."

	# first make sure if there is an app there (or more than one if that's possible?)
	# that they're deleted.
	$appArray = Get-AzureRmADApplication -DisplayName $appName
	foreach($app in $appArray)
	{
		$aoID = $app.ObjectId
		try
		{
			Write-Host "Removing previous SP application $appName ObjectId: $aoID"
			Remove-AzureRmADApplication -ObjectId $aoID -Force -ErrorAction Stop
		}
		catch
		{
			$exceptionContext = Get-AzureRmContext
			$exceptionTenantId = $exceptionContext.Tenant.Id
			Write-Error "Failure to remove application $appName from tenant $exceptionTenantId. Please check your AAD tenant permissions."

			#re-throw whatever the original exception was
			throw
		}
	}

	Write-Host "Purge complete. Creating new app $appName."

	# retry required on app registration (it seems) if there is a race condition with the deleted application.
	$newAppCreateRetry = 60
	while($newAppCreateRetry -ne 0)
	{
		$newAppCreateRetry--

		try
		{
			$app = New-AzureRmADApplication -DisplayName $appName -HomePage $appURI -IdentifierUris $appURI -Password $generatedPassword -ErrorAction Stop
			break
		}
		catch
		{
			Write-Host "Retrying to create app countdown: $newAppCreateRetry appName: $appName"
			Start-sleep -Seconds 1
			if ($newAppCreateRetry -eq 0)
			{
				#re-throw whatever the original exception was
				$exceptionContext = Get-AzureRmContext
				$exceptionTenantId = $exceptionContext.Tenant.Id
				Write-Error "Failure to add application $appName to tenant $exceptionTenantId. Please check your AAD tenant permissions."
				throw
			}
		}
	}


	Write-Host "New app creation complete. Creating SP."

	# retry required since it can take a few seconds for the app registration to percolate through Azure.
	# (Online recommendation was sleep 15 seconds - this is both faster and more conservative)
	$SPCreateRetry = 60
	while($SPCreateRetry -ne 0)
	{
		$SPCreateRetry--

		try
		{
			$sp  = New-AzureRmADServicePrincipal -ApplicationId $app.ApplicationId -ErrorAction Stop
			break
		}
		catch
		{
			$appIDForPrint = $app.ObjectId

			Write-Host "Waiting for app $SPCreateRetry : $appIDForPrint"
			Start-sleep -Seconds 1
			if ($SPCreateRetry -eq 0)
			{
				#re-throw whatever the original exception was
				Write-Error "Failure to create SP for $appName."
				throw
			}
		}
	}
	
	Write-Host "SP creation complete. Adding role assignment."

	# retry required since it can take a few seconds for the app registration to percolate through Azure.
	# (Online recommendation was sleep 15 seconds - this is both faster and more conservative)
	$rollAssignmentRetry = 120
	while($rollAssignmentRetry -ne 0)
	{
		$rollAssignmentRetry--

		try
		{
			New-AzureRmRoleAssignment -RoleDefinitionName Contributor -ResourceGroupName $RGName -ServicePrincipalName $app.ApplicationId -ErrorAction Stop
			break
		}
		catch
		{
			Write-Host "Waiting for service principal. Remaining: $rollAssignmentRetry"
			Start-sleep -Seconds 1
			if ($rollAssignmentRetry -eq 0)
			{
				#re-throw whatever the original exception was
				$exceptionContext = Get-AzureRmContext
				$exceptionSubscriptionId = $exceptionContext.Subscription.Id
				Write-Error "Failure to create Contributor role for $appName in ResourceGroup: $RGName Subscription: $exceptionSubscriptionId. Please check your subscription premissions."
				throw
			}
		}
	}

	# get SP credentials
	$spPass = ConvertTo-SecureString $generatedPassword -AsPlainText -Force
	$spCreds = New-Object -TypeName pscredential -ArgumentList  $sp.ApplicationId, $spPass

	# get tenant ID for this subscription
	$subForTenantID = Get-AzureRmContext
	$tenantID = $subForTenantID.Tenant.Id

	$spInfo = @{}
    $spInfo.Add("spCreds",$spCreds);
    $spInfo.Add("tenantId",$tenantID);

	return $spInfo
}



Login-AzureRmAccount
#get-azurermsubscription
$subscriptionID = "523a0eda-0b3e-41a2-bf22-4a095d972aae"
$registrationCode = "YYZZ9UMBYQBF@CA5E-2E7D-0841-D6A3"
$camSaasBaseUri = "https://cam-staging.teradici.com"

Select-AzureRmSubscription -SubscriptionId $subscriptionID


$azureRGName = "bdallkv2"

New-AzureRmResourceGroup -Name $azureRGName -Location "East US"

$spInfo2 = Create-CAMAppSP -RGName $azureRGName

createAndPopulateKeyvault -RGName $azureRGName -registrationCodeAsCred $spInfo2.spCreds -DomainJoinCreds $spInfo2.spCreds -spName $spInfo2.spCreds.UserName

$client = $spInfo2.spCreds.UserName
$key = $spInfo2.spCreds.GetNetworkCredential().Password
$tenant = $spInfo2.tenantId

$camDeploymenRegInfo = Register-CAM `
	-SubscriptionId $subscriptionID `
	-client $client `
	-key $key `
	-tenant $tenant `
	-RGName $azureRGName `
	-registrationCode $registrationCode `
	-camSaasBaseUri $camSaasBaseUri

$camDeploymenRegInfoJSON = ConvertTo-JSON $camDeploymenRegInfo -Depth 16 -Compress
$camDeploymenRegInfoURL = [System.Web.HttpUtility]::UrlEncode($camDeploymenRegInfoJSON)


Write-Host "Create auth file information for the CAM frontend."

$authFileContent = @"
subscription=$subscriptionID
client=$client
key=$key
tenant=$tenant
managementURI=https\://management.core.windows.net/
baseURL=https\://management.azure.com/
authURL=https\://login.windows.net/
graphURL=https\://graph.windows.net/
"@

$authFileContentURL = [System.Web.HttpUtility]::UrlEncode($authFileContent) 
Write-Host "This is the Encoded URL" $authFileContentURL -ForegroundColor Green

$camDeploymenInfo = @{};
$camDeploymenInfo.Add("registrationInfo",$camDeploymenRegInfo)
$camDeploymenInfo.Add("AzureAuthFile",$authFileContentURL)

$camDeploymenInfoJSON = ConvertTo-JSON $camDeploymenInfo -Depth 16 -Compress
$camDeploymenInfoURL = [System.Web.HttpUtility]::UrlEncode($camDeploymenInfoJSON)

$camDeploymenInfoURL
$camDeploymenInfoJSONDecoded = [System.Web.HttpUtility]::UrlDecode($camDeploymenInfoURL)
$camDeploymenInfoDecoded = ConvertFrom-Json $camDeploymenInfoJSONDecoded

$camDeploymenInfoJSONDecoded

[System.Web.HttpUtility]::UrlDecode($camDeploymenInfoDecoded.AzureAuthFile)

$camDeploymenInfoDecoded.RegistrationInfo

################## Actual script start here ####################

	#save Azure login context for current user
	$generatedFileRoot = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
	$RMContextFileName = "$env:temp\$generatedFileRoot.json"
	Save-AzureRmContext $RMContextFileName #There is some online cookie crumbs that Import-AzureRmContext (to resore the context) may operate from a variable than a file. Worth checking.

	try {
		$spName = $spCreds.UserName
		Write-Host "Logging in SP $spName with tenantID $tenantID"

		# retry required since it can take a few seconds for the app registration to percolate through Azure (and different to different endpoints... sigh).
		$LoginSPRetry = 60
		while($LoginSPRetry -ne 0)
		{
			$LoginSPRetry--

			try
			{
				Login-AzureRmAccount -ServicePrincipal -Credential $spCreds -TenantId $tenantID -ErrorAction Stop
				break
			}
			catch
			{
				Write-Host "Retrying SP login $LoginSPRetry : SPName=$spName TenantID=$tenantID"
				Start-sleep -Seconds 1
				if ($LoginSPRetry -eq 0)
				{
					#re-throw whatever the original exception was
					throw
				}
			}
		}
		
		Write-Host "Create auth file information for the CAM frontend."
		
		$sub = Get-AzureRMContext
		$subID = $sub.Subscription.Id
		$spPassword = $spCreds.GetNetworkCredential().Password

		$authFileContent = @"
subscription=$subID
client=$spName
key=$spPassword
tenant=$tenantID
managementURI=https\://management.core.windows.net/
baseURL=https\://management.azure.com/
authURL=https\://login.windows.net/
graphURL=https\://graph.windows.net/
"@

$authFileContentEncoded = [System.Web.HttpUtility]::UrlEncode($authFileContent) 
Write-Host "This is the Encoded URL" $authFileContentEncoded -ForegroundColor Green


createAndPopulateKeyvault `
	-RGName $RGName `
	-registrationCodeAsCred $registrationCodeAsCred `
	-DomainJoinCreds $DomainAdminCreds

################################

