# Deploy-CAM.ps1
#



#from: https://stackoverflow.com/questions/22002748/hashtables-from-convertfrom-json-have-different-type-from-powershells-built-in-h
function ConvertPSObjectToHashtable
{
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $collection = @(
                foreach ($object in $InputObject) { ConvertPSObjectToHashtable $object }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = ConvertPSObjectToHashtable $property.Value
            }

            $hash
        }
        else
        {
            $InputObject
        }
    }
}


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

			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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

			Write-Host "Cloud Access Manager Frontend has been registered successfully"

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

			Write-Host "Deployment has been registered successfully with Cloud Access Manager"

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



function Register-RemoteAccessWorkstation()
{
	Param(
		[bool]
		$verifyCAMSaaSCertificate = $true,
		
		# Retry for MAchine Registration
		$retryCount = 3,
		$retryDelay = 10,

		[parameter(Mandatory=$true)] 
		$subscription,
		
		[parameter(Mandatory=$true)]
		$client,
		
		[parameter(Mandatory=$true)]
		$key,
		
		[parameter(Mandatory=$true)]
		$tenant,
		
		[parameter(Mandatory=$true)]
		$adminDesktopVMName,

		[parameter(Mandatory=$true)]
		$RGName,

		[parameter(Mandatory=$true)]
		$deploymentId,

		[parameter(Mandatory=$true)]
		$camSaasBaseUri
	)

	# Register Agent Machine


	$userRequest = @{
		username = $client
		password = $key
		tenantId = $tenant
	}


	$machineRequest = @{
		deploymentId = $deploymentId
		resourceGroup = $RGName
		machineName = $adminDesktopVMName
		subscriptionId = $subscription
	}

	$machineRegistrationError = ""
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
			####################

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

			$registerMachineResult = ""
			try {
				$registerMachineResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/machines") -Body $machineRequest -Headers $tokenHeader
			} catch {
				if ($_.ErrorDetails.Message) {
					$registerMachineResult = ConvertFrom-Json $_.ErrorDetails.Message
				} else {
					throw $_
				}
			}
			Write-Verbose (ConvertTo-Json $registerMachineResult)
			# Check if registration succeeded
			if( !(($registerMachineResult.code -eq 201) -or ($registerMachineResult.data.reason.ToLower().Contains("exists")))) {
				throw ("Registering Machine failed. Result was: " + (ConvertTo-Json $registerMachineResult))
			}
			Write-Host ("Machine " + $machineRequest.machineName + " has been registered successfully with Cloud Access Manager.")

			break;
		} catch {
			$machineRegistrationError = $_
			Write-Verbose ( "Attempt {0} of $retryCount failed due to Error: {1}" -f ($idx+1), $machineRegistrationError )
			Start-Sleep -s $retryDelay
		} finally {
			# restore CertificatePolicy 
			[System.Net.ServicePointManager]::CertificatePolicy = $certificatePolicy
		}
	}

	if($machineRegistrationError) {
		throw $machineRegistrationError
	}
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
		[String]
		$registrationCode,
		
		[parameter(Mandatory=$true)]
		[String]
		$DomainJoinPassword
	)

	try{

		#KeyVault names must be globally (or at least regionally) unique, so make a unique string
		$generatedKVID = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$kvName = "CAM-$generatedKVID"

		Write-Host "Creating Azure KeyVault $kvName"

		$rg = Get-AzureRmResourceGroup -ResourceGroupName $RGName
		New-AzureRmKeyVault -VaultName $kvName -ResourceGroupName $RGName -Location $rg.Location -EnabledForTemplateDeployment -EnabledForDeployment

		Write-Host "Populating Azure KeyVault $kvName"
		
		$registrationCodeSecure = ConvertTo-SecureString $registrationCode -AsPlainText -Force
		$domainJoinPasswordSecure = ConvertTo-SecureString $domainJoinPassword -AsPlainText -Force

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

				$rcSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $rcSecretName -SecretValue $registrationCodeSecure -ErrorAction stop
				$djSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $djSecretName -SecretValue $domainJoinPasswordSecure -ErrorAction stop
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

		# create self signed certificate for Application Gateway.
		# System Administrators can override the self signed certificate if desired in future.
		# In order to create the certificate you must be running as Administrator on a Windows 10/Server 2016 machine
		# (Potentially Windows 8/Server 2012R2, but not Windows 7 or Server 2008R2)

		Write-Host "Creating Self-signed certificate for Application Gateway"

		$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        $isAdminSession = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
		if(!$isAdminSession) { throw "You must be running as administrator to create the self-signed certificate for the application gateway" }
		
		if(! (Get-Command New-SelfSignedCertificates -ErrorAction SilentlyContinue) )
		{
			{ throw "New-SelfSignedCertificate cmdlet must be available - please ensure you are running on a supported OS such as Windows 10 or Server 2016." }
		}


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

		Write-Host "Putting certificate in Key Vault."

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

		Write-Host "Successfully put certificate in Key Vault."
		
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


function Deploy-CAM()
{
    param(
	    [bool]
	    $verifyCAMSaaSCertificate = $true,

        $CAMDeploymentTemplateURI,

		$domainAdminUsername,
		$domainAdminPassword,
		$domainName,
		$registrationCode,
		$camSaasUri,
		$CAMDeploymentBlobSource,
		$outputParametersFileName,
		
	    [parameter(Mandatory=$true)] 
	    $subscriptionId,
		
	    [parameter(Mandatory=$true)]
		$RGName,
		
		[parameter(Mandatory=$false)]
		[System.Management.Automation.PSCredential]
		$spCredential,

		[parameter(Mandatory=$false)] #required if $spCredential is provided
		[string]
		$tenantId
	)

	#artifacts location 'folder' is where the template is stored
	$artifactsLocation = $CAMDeploymentTemplateURI.Substring(0, $CAMDeploymentTemplateURI.lastIndexOf('/'))

	$camConfigurationJson = @"
	{
	  "`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
	  "contentVersion": "1.0.0.0",
		"parameters": {
			"domainAdminUsername": {
				"value": "$domainAdminUsername"
			},
			"domainAdminPassword": {
				  "value": "$domainAdminPassword"
			},
			"domainName": {
				  "value": "$domainName"
			},
			"registrationCode": {
				  "value": "$registrationCode"
			},
			"camSaasUri": {
				"value": "$camSaasUri"
			},
			"CAMDeploymentBlobSource": {
				"value": "$CAMDeploymentBlobSource"
			},
			"_artifactsLocation": {
				"value": "$artifactsLocation"
			}
		}
	}
"@
	
    $CAMConfig = ConvertFrom-Json ([string]$camConfigurationJson)

	if($spCredential -eq $null)	{
		$spInfo = Create-CAMAppSP `
			-RGName $RGName
	}
	else {
		if ($tenantId -eq $null) {throw "SP provided but no tenantId"}
		$spInfo = @{}
		$spinfo.spCreds = $spCredential
		$spInfo.tenantId = $tenantId
	}

	$client = $spInfo.spCreds.UserName
	$key = $spInfo.spCreds.GetNetworkCredential().Password
	$tenant = $spInfo.tenantId

	Write-Host "Using SP $client in tenant $tenant and subscription $subscriptionId"

	# Login with SP since some Powershell contexts (with token auth - like Azure Cloud PowerShell or Visual Studio)
	# can't do operations on keyvaults

	#cache the current context
	$azureContext = Get-AzureRMContext

	try {
		Add-AzureRmAccount -Credential $spInfo.spCreds -ServicePrincipal -TenantId $spInfo.tenantId
		
		$kvInfo = createAndPopulateKeyvault `
			-RGName $RGName `
			-registrationCode $registrationCode `
			-DomainJoinPassword $CAMConfig.parameters.domainAdminPassword.value `
			-spName $spInfo.spCreds.UserName
		
			# need to add a retry on the registration for invalid SP as there is a race condition (sigh).
			#Start-Sleep -seconds 30

			Write-Host "Registering CAM Deployment to CAM Service"
		
			$camDeploymenRegInfo = Register-CAM `
				-SubscriptionId $subscriptionID `
				-client $client `
				-key $key `
				-tenant $tenant `
				-RGName $RGName `
				-registrationCode $registrationCode `
				-camSaasBaseUri $camSaasUri `
				-verifyCAMSaaSCertificate $verifyCAMSaaSCertificate
		
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
		
			$camDeploymenInfo = @{};
			$camDeploymenInfo.Add("registrationInfo",$camDeploymenRegInfo)
			$camDeploymenInfo.Add("AzureAuthFile",$authFileContentURL)
		
			$camDeploymenInfoJSON = ConvertTo-JSON $camDeploymenInfo -Depth 16 -Compress
			$camDeploymenInfoURL = [System.Web.HttpUtility]::UrlEncode($camDeploymenInfoJSON)
		
			$camDeploymenInfoURLSecure = ConvertTo-SecureString $camDeploymenInfoURL -AsPlainText -Force
			$camDeploySecretName = 'CAMDeploymentInfo'
			$camDeploySecret = Set-AzureKeyVaultSecret -VaultName $kvInfo.VaultName -Name $camDeploySecretName -SecretValue $camDeploymenInfoURLSecure
		
			$SPKeySecretName = 'SPKey'
			$SPKeySecret = Set-AzureKeyVaultSecret -VaultName $kvInfo.VaultName -Name $SPKeySecretName -SecretValue $spInfo.spCreds.Password
		
			<# Test code for encoding/decoding
			$camDeploymenInfoURL
			$camDeploymenInfoJSONDecoded = [System.Web.HttpUtility]::UrlDecode($camDeploymenInfoURL)
			$camDeploymenInfoDecoded = ConvertFrom-Json $camDeploymenInfoJSONDecoded
		
		
			[System.Web.HttpUtility]::UrlDecode($camDeploymenInfoDecoded.AzureAuthFile)
		
			$regInfo = $camDeploymenInfoDecoded.RegistrationInfo
		
			$regInfo.psobject.properties | Foreach-Object {
				Write-Host "Name: " $_.Name " Value: " $_.Value
		
			#>
		
		
			#keyvault ID of the form: /subscriptions/$subscriptionID/resourceGroups/$azureRGName/providers/Microsoft.KeyVault/vaults/$kvName
		
			Register-RemoteAccessWorkstation `
					-subscription $subscriptionID `
					-client $client `
					-key $key `
					-tenant $tenant `
					-RGName $RGName `
					-deploymentId $camDeploymenRegInfo.CAM_DEPLOYMENTID `
					-camSaasBaseUri $camDeploymenRegInfo.CAM_URI `
					-adminDesktopVMName "vm-desk" `
					-verifyCAMSaaSCertificate $verifyCAMSaaSCertificate

		
		
			$kvId = $kvInfo.ResourceId

			$verifyCAMSaaSCertificateText = "false"
			if($verifyCAMSaaSCertificate)
			{
				$verifyCAMSaaSCertificateText = "true"
			}

		$generatedDeploymentParameters = @"
	{
		"AzureAdminUsername": {
			"value": "$client"
		},
		"AzureAdminPassword": {
			"reference": {
				"keyVault": {
				  "id": "$kvId"
				},
				"secretName": "$SPKeySecretName"
			  }
		},
		"tenantID": {
			"value": "$tenant"
		},
		"certData": {
			"reference": {
				"keyVault": {
				  "id": "$kvId"
				},
				"secretName": "CAMFECertificate"
			  }		
		},
		"certPassword": {
			"reference": {
				"keyVault": {
				  "id": "$kvId"
				},
				"secretName": "CAMFECertificatePassword"
			  }		
		},
		"keyVaultId": {
			"value": "$kvId"
		},
		"CAMDeploymentInfo": {
			"reference": {
				"keyVault": {
				  "id": "$kvId"
				},
				"secretName": "$camDeploySecretName"
			}
		},
        "verifyCAMSaaSCertificate": {
            "value": $verifyCAMSaaSCertificateText
        }
	}
"@
		
		
		
		$CAMConfigTable = ConvertPSObjectToHashtable -InputObject $CAMConfig
	
		$deploymentParametersObj = ConvertFrom-Json $generatedDeploymentParameters
		$deploymentParametersTable = ConvertPSObjectToHashtable -InputObject $deploymentParametersObj
	
		$CAMConfigTable.parameters += $deploymentParametersTable
	
		$outParametersFileContent = ConvertTo-Json -InputObject $CAMConfigTable -Depth 99
		Set-Content $outputParametersFileName  $outParametersFileContent
	
	
	# Test-AzureRmResourceGroupDeployment -ResourceGroupName $azureRGName -TemplateFile "azuredeploy.json" -TemplateParameterFile $outputParametersFileName  -Verbose
		Write-Host "Deploying Cloud Access Manager Connection Service"

		New-AzureRmResourceGroupDeployment `
			-DeploymentName "ad1" `
			-ResourceGroupName $azureRGName `
			-TemplateFile $CAMDeploymentTemplateURI `
			-TemplateParameterFile $outputParametersFileName 

	}
	finally {
		if ($azureContext)
		{
			Set-AzureRMContext -Context $azureContext
		}
	}
}
