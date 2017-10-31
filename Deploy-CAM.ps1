# Deploy-CAM.ps1
#
#


param(
	$subscriptionId,
	$ResourceGroupName,
	$tenantId,
	[System.Management.Automation.PSCredential] $domainAdminCredential,
	[System.Management.Automation.PSCredential] $spCredential,
	$domainName,
	[SecureString]$registrationCode,
	[bool] $verifyCAMSaaSCertificate = $true,
	$camSaasUri = "https://cam-antar.teradici.com",
	$CAMDeploymentTemplateURI ="https://raw.githubusercontent.com/teradici/deploy/bd/azuredeploy.json",
	$CAMDeploymentBlobSource = "https://teradeploy.blob.core.windows.net/bdbinaries",
	$outputParametersFileName = "cam-output.parameters.json"  #fix me - remove credential, make file unique and delete after.
)



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
		[SecureString]$registrationCode,

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

			# Need plaintext registration code
			$userName = "Domain\DummyUser"
			$regCreds = New-Object -TypeName pscredential -ArgumentList  $userName, $registrationCode
			$clearRegCode = $regCreds.GetNetworkCredential().Password


			# Register Deployment
			$deploymentRequest = @{
				resourceGroup = $RGName
				subscriptionId = $subscriptionId
				registrationCode = $clearRegCode
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



function Create-UserStorageAccount
{
	Param(
		$RGName,
		$location
	)

	$saName = 	-join ((97..122) | Get-Random -Count 18 | % {[char]$_})

	Write-Host "Creating user data storage account $saName in resource group $RGName and location $location."

	$acct = New-AzureRmStorageAccount `
		-ResourceGroupName $RGName `
		-AccountName $saName `
		-Location $location `
		-SkuName "Standard_LRS"

	return $acct
}

function Populate-UserBlob
{
	Param(
		$artifactsLocation,
		$userDataStorageAccount,
		$CAMDeploymentBlobSource,
		$linuxAgentARM,
		$gaAgentARM,
		$agentARM,
		$sumoAgentApplicationVM,
		$sumoConf,
		$idleShutdownLinux,
		$RGName,
		$kvName
		)
		
	################################
	Write-Host "Populating user blob"
	################################
	$container_name = "cloudaccessmanager"
	$acct_name = $userDataStorageAccount.StorageAccountName
	$new_agent_vm_files = @(
		"$artifactsLocation/end-user-application-machines/new-agent-vm/Install-PCoIPAgent.ps1", 
		"$artifactsLocation/end-user-application-machines/new-agent-vm/Install-PCoIPAgent.sh",
		"$CAMDeploymentBlobSource\Install-PCoIPAgent.ps1.zip",
		"$artifactsLocation/end-user-application-machines/new-agent-vm/rhel-standard-agent.json", 
		"$artifactsLocation/end-user-application-machines/new-agent-vm/server2016-graphics-agent.json",
		"$artifactsLocation/end-user-application-machines/new-agent-vm/server2016-standard-agent.json", 
		"$artifactsLocation/end-user-application-machines/new-agent-vm/sumo-agent-vm.json",
		"$artifactsLocation/end-user-application-machines/new-agent-vm/sumo.conf",
		"$artifactsLocation/end-user-application-machines/new-agent-vm/Install-Idle-Shutdown.sh"
	)

	# Suppress outputting to pipeline so the return value of the function is the one
	# hash table we want.
	$null = @(
		Write-Host "Will upload these files: $new_agent_vm_files"
		$acctKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $RGName -AccountName $acct_name).Value[0]
		$ctx = New-AzureStorageContext -StorageAccountName $acct_name -StorageAccountKey $acctKey
		try {
			Get-AzureStorageContainer -Name $container_name -Context $ctx -ErrorAction Stop
		} Catch {
			# No container - make one.
			# -Permission needs to be off to allow only owner read and to require access key!
			New-AzureStorageContainer -Name $container_name -Context $ctx -Permission "Off" -ErrorAction Stop
		}
	
		Write-Host "Uploading files to private blob"
		ForEach($fileURI in $new_agent_vm_files) {
			$fileName = $fileURI.Substring($fileURI.lastIndexOf('/') + 1)
			try {
				Get-AzureStorageBlob `
					-Context $ctx `
					-Container $container_name `
					-Blob "remote-workstation/$fileName" `
					-ErrorAction Stop
			# file already exists do nothing
			} Catch {
				Write-Host "Uploading $fileURI to blob.."
				Start-AzureStorageBlobCopy `
					-AbsoluteUri $fileURI `
					-DestContainer $container_name `
					-DestBlob "remote-workstation/$fileName" `
					-DestContext $ctx
			}
		}
	
		#TODO: Check for errors...
		Write-Host "Waiting for blob copy completion"
		ForEach($fileURI in $new_agent_vm_files) {
			$fileName = $fileURI.Substring($fileURI.lastIndexOf('/') + 1)
			Write-Host "Waiting for $fileName"
			Get-AzureStorageBlobCopyState `
				-Blob "remote-workstation/$fileName" `
				-Container $container_name `
				-Context $ctx `
				-WaitForComplete
			Write-Host "$fileName complete"
		}
	
		$blobUri = (((Get-AzureStorageBlob -Context $ctx -Container $container_name)[0].ICloudBlob.uri.AbsoluteUri) -split '/')[0..4] -join '/'
	
		# this is the url to access the blob account
		$blobUriSecretName = "userStorageAccountUri"
		Set-AzureKeyVaultSecret -VaultName $kvName -Name $blobUriSecretName -SecretValue (ConvertTo-SecureString $blobUri -AsPlainText -Force) -ErrorAction stop
	
		$storageAccountSecretName = "userStorageName"
		Set-AzureKeyVaultSecret -VaultName $kvName -Name $storageAccountSecretName -SecretValue (ConvertTo-SecureString $acct_name -AsPlainText -Force) -ErrorAction stop
		$storageAccountKeyName = "userStorageAccountKey"
		Set-AzureKeyVaultSecret -VaultName $kvName -Name $storageAccountKeyName -SecretValue (ConvertTo-SecureString $acctKey -AsPlainText -Force) -ErrorAction stop
	
		$saSasToken = New-AzureStorageAccountSASToken -Service Blob -Resource Object -Context $ctx -ExpiryTime ((Get-Date).AddYears(2)) -Permission "racwdlup" 
		$saSasTokenSecretName = 'userStorageAccountSaasToken'
		Set-AzureKeyVaultSecret -VaultName $kvName -Name $saSasTokenSecretName -SecretValue (ConvertTo-SecureString $saSasToken -AsPlainText -Force) -ErrorAction stop
	
		$userBlobInfo = @{}
	
	
		# using the blob uri + the token from the key vault will allow the web interface to retrieve required information from private blob
		$userBlobInfo.Add("CAM_KEY_VAULT_NAME", $kvName)
		
		# these two are used to retrieve files via http. Their values need to be retrieved from the key vault
		$userBlobInfo.Add("CAM_USER_BLOB_URI", $blobUriSecretName)
		$userBlobInfo.Add("CAM_USER_BLOB_TOKEN", $saSasTokenSecretName)
	
		# these two are used to upload files using cli or sdk. Their values need to be retrieved from the key vault
		$userBlobInfo.Add("CAM_USER_STORAGE_ACCOUNT_NAME", $storageAccountSecretName)
		$userBlobInfo.Add("CAM_USER_STORAGE_ACCOUNT_KEY", $storageAccountKeyName)
	)

	return $userBlobInfo
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
		[SecureString]
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
		New-AzureRmKeyVault `
			-VaultName $kvName `
			-ResourceGroupName $RGName `
			-Location $rg.Location `
			-EnabledForTemplateDeployment `
			-EnabledForDeployment `
			-WarningAction Ignore

		Write-Host "Populating Azure KeyVault $kvName"
		
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
                Write-Host "Set access policy for vault $kvName for user $spName"
				Set-AzureRmKeyVaultAccessPolicy `
                    -VaultName $kvName `
                    -ServicePrincipalName $spName `
                    -PermissionsToSecrets Get, Set `
                    -ErrorAction stop

				$rcSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $rcSecretName -SecretValue $registrationCode -ErrorAction stop
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

		[System.Management.Automation.PSCredential]
		$domainAdminCredential,
		
		$domainName,
		[SecureString]$registrationCode,
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

	$domainAdminUsername = $domainAdminCredential.UserName
	$domainAdminPassword = $domainAdminCredential.GetNetworkCredential().Password

	# Need plaintext registration code
	$userName = "Domain\DummyUser"
	$regCreds = New-Object -TypeName pscredential -ArgumentList  $userName, $registrationCode
	$clearRegCode = $regCreds.GetNetworkCredential().Password

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
				  "value": "$clearRegCode"
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

	$spInfo = $null
	if(-not $spCredential)	{

		# if there's no SP provided then we either need to make one or ask for one

		# if the current context tenantId does not match the desired tenantId then we can't make SP's
		$currentContext = Get-AzureRmContext
		$currentContextTenant = $currentContext.Tenant.Id 
		$tenantIDsMatch = ($currentContextTenant -eq $tenantId)

		if(-not $tenantIDsMatch) {
			Write-Host "The Current Azure context is for a different tenant ($currentContextTenant) that"
			Write-Host "does not match the tenant of the deploment ($tenantId)."
			Write-Host "This can happen in Azure Cloud Powershell when an account has access to multiple tenants."
			Write-Host "Please make a service principal through the Azure Portal or other means and provide here."
		}
		else {
			Write-Host "The CAM deployment script was not passed service principal credentials. It will attempt to create a service principal."
			$requestSPGeneration = Read-Host `
			"Please hit enter to continue or 'no' to manually enter service principal credentials from a pre-made service principal"
		}

		if((-not $tenantIDsMatch) -or ($requestSPGeneration -like "*n*")) {
			# manually get credential
			$spCredential = Get-Credential -Message "Please enter SP credential"

			$spInfo = @{}
			$spinfo.spCreds = $spCredential
			$spInfo.tenantId = $tenantId
			}
		else {
			# generate SP
			$spInfo = Create-CAMAppSP `
				-RGName $RGName
		}
	}
	else {
		# SP credential provided in parameter list
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
	$rg = Get-AzureRmResourceGroup -ResourceGroupName $RGName

	try {
		Add-AzureRmAccount `
			-Credential $spInfo.spCreds `
			-ServicePrincipal `
			-TenantId $spInfo.tenantId `
			-ErrorAction Stop 
		
		$kvInfo = createAndPopulateKeyvault `
			-RGName $RGName `
			-registrationCode $registrationCode `
			-DomainJoinPassword $CAMConfig.parameters.domainAdminPassword.value `
			-spName $spInfo.spCreds.UserName

		$userDataStorageAccount = Create-UserStorageAccount `
			-RGName $RGName `
			-Location $rg.Location
		
		$userBlobInfo = Populate-UserBlob `
			-artifactsLocation $artifactsLocation `
			-userDataStorageAccount	$userDataStorageAccount `
			-CAMDeploymentBlobSource $CAMDeploymentBlobSource `
			-RGName $RGName `
			-kvName $kvInfo.VaultName

		#$userDataStorageAccountName = $userDataStorageAccount.StorageAccountName

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
			$camDeploymenInfo.Add("registrationInfo",($camDeploymenRegInfo + $userBlobInfo))
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
	
	
		Write-Host "Deploying Cloud Access Manager Connection Service. This process can take up to 90 minutes."
		Write-Host "Please feel free to watch here for early errors for a few minutes and then go do something else. Or go for coffee!"
		Write-Host "If this script is running in Azure Cloud Shell then you may let the shell timeout and the deployment will continue."
		Write-Host "Please watch the resource group $RGName in the Azure Portal for current status."

		if($false) {
 			# just do a test if $true
 			Test-AzureRmResourceGroupDeployment `
				-ResourceGroupName $RGName `
				-TemplateFile "azuredeploy.json" `
				-TemplateParameterFile $outputParametersFileName  `
				-Verbose
		}
		else {
			New-AzureRmResourceGroupDeployment `
				-DeploymentName "CAM" `
				-ResourceGroupName $RGName `
				-TemplateFile $CAMDeploymentTemplateURI `
				-TemplateParameterFile $outputParametersFileName 
		}


	}
	finally {
		if ($azureContext)
		{
			Set-AzureRMContext -Context $azureContext
		}
	}
}

##############################################
############# Script starts here #############
##############################################

$rmContext = Get-AzureRmContext
$subscriptions = Get-AzureRmSubscription -WarningAction Ignore
$subscriptionsToDisplay = $subscriptions | Where-Object { $_.State -eq 'Enabled' }

$chosenSubscriptionIndex = $null
if($subscriptionsToDisplay.Length -lt 1) {
    Write-Host ("Account " + $rmContext.Account.Id + " has access to no enabled subscriptions. Exiting.")
    exit
}

    # Match up subscriptions with the current context and let the user choose 
    $subscriptionIndex = 0
    $currentSubscriptionIndex = $null
    ForEach($s in $subscriptionsToDisplay) {
        if(-not (Get-Member -inputobject $s -name "Current")) {
            Add-Member -InputObject $s -Name "Current" -Value "" -MemberType NoteProperty
        }
        if(-not (Get-Member -inputobject $s -name "Number")) {
            Add-Member -InputObject $s -Name "Number" -Value "" -MemberType NoteProperty
        }

        if(($s.SubscriptionId -eq $rmContext.Subscription.Id) -and ($s.TenantId -eq $rmContext.Tenant.Id)) {
            $s.Current = "*"
            $currentSubscriptionIndex = $subscriptionIndex
        }
        else {
            $s.Current = ""
        }

        $s.Number = ($subscriptionIndex++) + 1

    }

    if($subscriptionsToDisplay.Length -eq 1) {
        Write-Host ("Account " + $rmContext.Account.Id + " has access to a single enabled subscription.")
        $chosenSubscriptionNumber = 0
    }
    else {
        # Let user choose since it's sometimes not obvious...
        $subscriptionsToDisplay | Select-Object -Property Current, Number, Name, SubscriptionId, TenantId | Format-Table

        $currentSubscriptionNumber = $currentSubscriptionIndex + 1

        $chosenSubscriptionNumber = 0 #invalid
        while( -not (( $chosenSubscriptionNumber -ge 1) -and ( $chosenSubscriptionNumber -le $subscriptionsToDisplay.Length))) {
            $chosenSubscriptionNumber = 
                if (($chosenSubscriptionNumber = Read-Host "Please enter the Number of the subscription you would like to use or press enter to accept the current one [$currentSubscriptionNumber]") -eq '') `
                {$currentSubscriptionNumber} else {$chosenSubscriptionNumber}
        }
        Write-Host "Chosen Subscription:"
    }

    $chosenSubscriptionIndex = $chosenSubscriptionNumber - 1

    # Let user choose since it's sometimes not obvious...
    Write-Host ($subscriptionsToDisplay[$chosenSubscriptionIndex] | Select-Object -Property Current, Number, Name, SubscriptionId, TenantId | Format-Table | Out-String)
    $rmContext = Set-AzureRmContext -SubscriptionId $subscriptionsToDisplay[$chosenSubscriptionIndex].SubscriptionId -TenantId $subscriptionsToDisplay[$chosenSubscriptionIndex].TenantId

	# The Context doesn't always seem to take the tenant depending on who is logged in - so making a copy from the selected subscription
	$selectedTenantId = $subscriptionsToDisplay[$chosenSubscriptionIndex].TenantId
	$selectedSubcriptionId = $subscriptionsToDisplay[$chosenSubscriptionIndex].SubscriptionId
	
	# Now we have the subscription set. Time to find the CAM root RG.

    $resouceGroups = Get-AzureRmResourceGroup

    $rgIndex = 0
    ForEach($r in $resouceGroups) {
        if(-not (Get-Member -inputobject $r -name "Number")) {
            Add-Member -InputObject $r -Name "Number" -Value "" -MemberType NoteProperty
        }

        $r.Number = ($rgIndex++) + 1
    }

    Write-Host "`nAvailable Resource Groups"
    Write-Host ($resouceGroups | Select-Object -Property Number, ResourceGroupName, Location | Format-Table | Out-String)

    $selectedRGName = $false
    $rgIsInt = $false
    $rgMatch = $null
    while(-not $selectedRGName) {
        Write-Host "Please select the resource group of the CAM deployment root by number or type in a new resource group name for a new CAM deployment."
        $rgIdentifier = Read-Host "Resource group"

        $rgIsInt = [int]::TryParse($rgIdentifier,[ref]$rgIndex) #rgIndex will be 0 on parse failure

        if($rgIsInt) {
            # entered an integer - we are not supporting integer names here for new resource groups
            $rgArrayLength = $resouceGroups.Length
            if( -not (( $rgIndex -ge 1) -and ( $rgIndex -le $rgArrayLength))) {
                #invalid range 
                Write-Host "Please enter a range between 1 and $rgArrayLength or the name of a new resource group."
            }
            else {
                $rgMatch = $resouceGroups[$rgIndex - 1]
                $selectedRGName = $true
            }
            continue
        }
        else {
            # entered a name. Let's see if it matches any resource groups first
            $rgMatch = $resouceGroups | Where-Object {$_.ResourceGroupName -eq $rgIdentifier}
            if ($rgMatch) {
                $rgName = $rgMatch.ResourceGroupName
                Write-Host ("Resource group `"$rgName`" already exists. The current one will be used.")
                $selectedRGName = $true
            }
            else {
                # make a new resource group and on failure go back to RG selection.
                $rgName = $rgIdentifier
                $newRgResult = $null

				Write-Host("Available Azure Locations")
				Write-Host (Get-AzureRMLocation | Select-Object -Property Location, DisplayName | Format-Table | Out-String )

                $newRGLocation = Read-Host "`nPlease enter resource group location"
                $newRgResult = New-AzureRmResourceGroup -Name $rgName -Location $newRGLocation
                if($newRgResult) {
                    # Success!
                    $selectedRGName = $true
                    $rgMatch = Get-AzureRmResourceGroup -Name $rgName
                }
            }
        }
	}
	

	# allow interactive input of a bunch of parameters. spCredential is handled in the SP functions (above) so it can be quickly validated
	while (-not $domainAdminCredential ) {
		$domainAdminCredential = Get-Credential -Message "Please enter admin credential for new domain"
		
		if ($domainAdminCredential.GetNetworkCredential().Password.Length -lt 12) {
			#too short- try again.
			Write-Host "The admin password must be at least 12 characters long"
			$domainAdminCredential = $null
		}
	}

	while(-not $domainName ) {
		$domainName = Read-Host "Please enter new fully qualified domain name including a '.' such as example.com"
		if($domainName -notlike "*.*") {
			#too short- try again.
			Write-Host "The domain name must include two or more components separated by a '.'"
			$domainName = $null
		}
	}

	while(-not $registrationCode ) {
		$registrationCode = Read-Host -AsSecureString "Please enter your Cloud Access registration code"

		# Need plaintext registration code
		$userName = "Domain\DummyUser"
		$regCreds = New-Object -TypeName pscredential -ArgumentList  $userName, $registrationCode
		$clearRegCode = $regCreds.GetNetworkCredential().Password
		if($clearRegCode.Length -lt 21) {
			#too short- try again.
			Write-Host "The registration code is at least 21 characters long"
			$registrationCode = $null
		}
	}

# Not using splat because of bad handling of default values.
Deploy-CAM `
 -domainAdminCredential $domainAdminCredential `
 -domainName $domainName `
 -registrationCode $registrationCode `
 -camSaasUri $camSaasUri.Trim().TrimEnd('/') `
 -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate `
 -CAMDeploymentTemplateURI $CAMDeploymentTemplateURI `
 -CAMDeploymentBlobSource $CAMDeploymentBlobSource.Trim().TrimEnd('/') `
 -outputParametersFileName $outputParametersFileName `
 -subscriptionId $selectedSubcriptionId `
 -RGName $rgMatch.ResourceGroupName `
 -spCredential $spCredential `
 -tenantId $selectedTenantId

