# Copyright (c) 2018 Teradici Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

Param(
    $ResourceGroupName,

    [System.Management.Automation.PSCredential]
    $domainAdminCredential,

    [System.Management.Automation.PSCredential]
    $spCredential,
    [parameter(Mandatory=$false)]
    $AzureSPObjectId=$null,

    $domainName,

    [SecureString]
    $registrationCode,

    [parameter(Mandatory = $false)]
    [bool]
    $verifyCAMSaaSCertificate = $true,

    [parameter(Mandatory = $false)]
    $enableExternalAccess = $null,
    
    [parameter(Mandatory = $false)]
    [bool]
    $testDeployment = $false,

    [parameter(Mandatory = $false)]
    [String]
    $certificateFile = $null,
    
    [parameter(Mandatory = $false)]
    [SecureString]
    $certificateFilePassword = $null,

    [parameter(Mandatory=$false)]
    [ValidateSet("stable","beta","dev")] 
    [String]
    $AgentChannel = "stable",

    [parameter(Mandatory=$false)]
    $deployOverDC,

    [parameter(Mandatory=$false)]
    [String]
    $vnetID,

    [parameter(Mandatory=$false)]
    [String]
    $GatewaySubnetName,

    [parameter(Mandatory=$false)]
    [String]
    $ConnectionServiceSubnetName,

    [parameter(Mandatory=$false)]
    [String]
    $RemoteWorkstationSubnetName,

    [switch]$ignorePrompts,

    [parameter(Mandatory = $false)]
    $enableRadiusMfa=$null,

    [parameter(Mandatory=$false)]
    [String]
    $radiusServerHost,

    [parameter(Mandatory=$false)]
    [int]
    $radiusServerPort,

    [parameter(Mandatory=$false)]
    [SecureString]
    $radiusSharedSecret,

    [parameter(Mandatory=$false)]
    [ValidateSet("Windows Server 2016","Windows Server 2012R2")] 
    [String]
    $domainControllerOsType = "Windows Server 2016",

    [parameter(Mandatory=$false)]
    [ValidateRange(10,10000)]
    [int]
    $defaultIdleShutdownTime = 240,

    [parameter(Mandatory=$false, HelpMessage="the distinguished name aka DN of a domain group which cam users belong to")]
    [String]
    $camUserGroup,

    $camSaasUri = "https://cam.teradici.com",
    $CAMDeploymentTemplateURI = "https://raw.githubusercontent.com/teradici/deploy/master/azuredeploy.json",
    $binaryLocation = "https://teradeploy.blob.core.windows.net/binaries",
    $outputParametersFileName = "cam-output.parameters.json",
    $location,

    [parameter(Mandatory=$false)]
    $camManagementUserGroup = $null,

    [switch]$updateSPCredential,
    [bool]$retrieveAgentState = $false,
    [bool]$showAgentState = $true,

    [parameter(Mandatory = $false)]
    [bool]
    $isBrokerCacheEnabled = $false,

    [parameter(Mandatory = $false)]
    [int]
    $brokerCacheSize = 1000,

    [parameter(Mandatory = $false)]
    [int]
    $brokerCacheTimeoutSeconds = 28800,

    [Hashtable]$tag = @{CloudAccessConnectorType="CACv1"}
)

# Global Variables
# Set the minimum vCPUs needed for a full deployment or an add-on connection
$minCoresFullDeploy = 6
$minCoresAddConn = 3
$isUnix = [Environment]::OSVersion.VersionString.Contains("Unix")

if (-not $env:TEMP) {
    if ($isUnix) {
        $env:TEMP = "/tmp/"
    } else {
        $env:TEMP = "$env:SystemDrive\temp\"
    }
}

function confirmDialog {
    param(
        [parameter(Mandatory=$true)]
        $prompt,

        [parameter(Mandatory=$false)]
        [validateSet("Y","N")] 
        $defaultSelected='N'
    )

    if ($defaultSelected -eq 'Y') {
        $promptMsg =  "`n$prompt [Y/n]" 
    } else {
        $promptMsg =  "`n$prompt [y/N]" 
    }

    do{
        $selected = Read-Host $promptMsg
        $selected = $selected.trim()
        if ($selected -eq '') {
            $selected = $defaultSelected
        }
    }while($selected -notmatch "^y(es)?$|^n(o)?$")

    return $selected.SubString(0,1).ToLower()
}

# Converts a secure string parameter to a plain string
function ConvertTo-Plaintext {
    param(
        [Parameter(ValueFromPipeline)]
        [SecureString]
        $secureString
    )
    return (New-Object PSCredential "user", $secureString).GetNetworkCredential().Password
}
# from: https://stackoverflow.com/questions/22002748/hashtables-from-convertfrom-json-have-different-type-from-powershells-built-in-h
function ConvertPSObjectToHashtable {
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $collection = @(
                foreach ($object in $InputObject) { ConvertPSObjectToHashtable $object }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject]) {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertPSObjectToHashtable $property.Value
            }

            $hash
        }
        else {
            $InputObject
        }
    }
}

function Convert-FromBase64StringWithNoPadding([string]$data) {
    $data = $data.Replace('-', '+').Replace('_', '/')
    switch ($data.Length % 4)
    {
        0 { break }
        2 { $data += '==' }
        3 { $data += '=' }
        default { throw New-Object ArgumentException('data') }
    }
    return [System.Convert]::FromBase64String($data)
}

function Decode-JWT([string]$rawToken) {
    $parts = $rawToken.Split('.');
    $headers = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $parts[0]))
    $claims = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $parts[1]))
    $signature = (Convert-FromBase64StringWithNoPadding $parts[2])

    $customObject = [PSCustomObject]@{
        headers = ($headers | ConvertFrom-Json)
        claims = ($claims | ConvertFrom-Json)
        signature = $signature
    }

    return $customObject
}

function Get-DecodedJWT {
    [CmdletBinding()]  
    Param (
        [Parameter(Mandatory=$true)]
        [string] $Token,
        [switch] $Recurse
    )
    
    if ($Recurse) {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Token))
        $DecodedJwt = Decode-JWT -rawToken $decoded
    }
    else
    {
        $DecodedJwt = Decode-JWT -rawToken $Token
    }
    return $DecodedJwt
}

function Login-AzureRmAccountWithBetterReporting($Credential) {
    try {
        $userName = $Credential.userName
        Login-AzureRmAccount -Credential $Credential @args -ErrorAction stop

        Write-Host "Successfully Logged in $userName"
    }
    catch {
        $es = "Error authenticating AzureAdminUsername $userName for Azure subscription access.`n"
        $exceptionMessage = $_.Exception.Message
        $exceptionMessageErrorCode = $exceptionMessage.split(':')[0]

        switch ($exceptionMessageErrorCode) {
            "AADSTS50076" {$es += "Please ensure your account does not require Multi-Factor Authentication`n"; break}
            "Federated service at https" {$es += "Unable to perform federated login - Unknown username or password?`n"; break}
            "unknown_user_type" {$es += "Please ensure your username is in UPN format, e.g. user@example.com`n"; break}
            "AADSTS50126" {$es += "User not found in directory`n"; break}
            "AADSTS70002" {$es += "Please check your password`n"; break}
        }


        throw "$es$exceptionMessage"

    }
}

# uses session instance profile and TokenCache and returns an access token without having to authentication a second time
function Get-AzureRmCachedAccessToken() {
    $ErrorActionPreference = 'Stop'
    if(-not ((Get-Module AzureRm.Profile) -or (Get-Module AzureRm.Profile.Netcore) -or (Get-Module Az.Profile) -or (Get-Module Az.Accounts))) {
        if($isUnix) {
            try {
                Import-Module AzureRm.Profile.NetCore
            } catch {
                try {
                    Import-Module Az.Profile
                } catch {
                    Import-Module Az.Accounts
                }
            }
        } else {
            Import-Module AzureRm.Profile
        }
    }
    if( -not $isUnix) {
        $azureRmProfileModuleVersion = (Get-Module AzureRm.Profile).Version
    }
    
    # refactoring performed in AzureRm.Profile v3.0 or later
    if( (-not $isUnix -and $azureRmProfileModuleVersion.Major -lt 3) ) {
        # AzureRm.Profile < v3.0
        $azureRmProfile = [Microsoft.WindowsAzure.Commands.Common.AzureRmProfileProvider]::Instance.Profile
        if(-not $azureRmProfile.Context.Account.Count) {
            Write-Error "Ensure you have logged in before calling this function"
        }
    } else {
        $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        if(-not $azureRmProfile.Accounts.Count) {
            Write-Error "Ensure you have logged in before calling this function"
        }
    }
    $currentAzureContext = Get-AzureRmContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
    Write-Debug ("Getting access token for tenant" + $currentAzureContext.Subscription.TenantId)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
    return $token.AccessToken
}

function Get-Claims() {
    try {
        $accessToken = Get-AzureRmCachedAccessToken
        $decodedToken = Get-DecodedJWT `
            -Token $accessToken

        return $decodedToken.claims
    }
    catch {
        $errorMessage = "An error occured while retrieving owner upn"
        throw "$errorMessage"
    }

}
# registers CAM and returns the deployment ID
function Register-CAM() {
    Param(
        [bool]
        $verifyCAMSaaSCertificate = $true,
        
        # Retry for CAM Registration
        $retryCount = 3,
        $retryDelay = 10,

        [parameter(Mandatory = $true)] 
        $subscriptionId,
        
        [parameter(Mandatory = $true)]
        $client,
        
        [parameter(Mandatory = $true)]
        $key,
        
        [parameter(Mandatory = $true)]
        $tenant,
        
        [parameter(Mandatory = $true)]
        $ownerTenant,

        [parameter(Mandatory = $true)]
        $ownerUpn,

        [parameter(Mandatory = $true)]
        $RGName,

        [parameter(Mandatory = $true)]
        [SecureString]$registrationCode,

        [parameter(Mandatory = $true)]
        $camSaasBaseUri
    )

    $deploymentId = $null

    #define variable to keep trace of the error during retry process
    $camRegistrationError = ""
    for ($idx = 0; $idx -lt $retryCount; $idx++) {
        # reset the variable at each iteration, so we can always keep the current loop error message
        $camRegistrationError = ""
        try {
            if ( -not $isUnix ) {
                $certificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                # Can't disable SSL verification for Invoke-RestMethod on Unix with this method
                # Not worth effort fixing since cert should always be valid
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
            }

            # Security Rules on CAM firewall don't like default user-agent for cloudshell, overwrite with a different one (Chrome)
            $baseHeaders = @{
                "User-Agent"="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
            }

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            ##


            $userRequest = @{
                username = $client
                password = $key
                tenantId = $tenant
                ownerTenantId = $ownerTenant
                ownerUpn = $ownerUpn
            }
            $registerUserResult = ""
            try {
                $registerUserResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/auth/users") -Body $userRequest -Headers $baseHeaders
            }
            catch {
                if ($_.ErrorDetails.Message) {
                    $registerUserResult = ConvertFrom-Json $_.ErrorDetails.Message
                }
                else {
                    throw $_
                }
            }
            Write-Verbose (ConvertTo-Json $registerUserResult)
            # Check if registration succeeded or if it has been registered previously
            if ( !(($registerUserResult.code -eq 201) -or (($registerUserResult.data.reason -ne $null) -and $registerUserResult.data.reason.ToLower().Contains("already exist"))) ) {
                throw ("Failed to register with Cloud Access Manager service with result: " + (ConvertTo-Json $registerUserResult))
            }

            Write-Host "Cloud Access Manager user has been registered successfully"

            # Get a Sign-in token
            $signInResult = ""
            try {
                $signInResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/auth/signin") -Body $userRequest -Headers $baseHeaders
            }
            catch {
                if ($_.ErrorDetails.Message) {
                    $signInResult = ConvertFrom-Json $_.ErrorDetails.Message
                }
                else {
                    throw $_
                }
            }
            Write-Verbose ((ConvertTo-Json $signInResult) -replace "\.*token.*", 'Token": "Sanitized"')
            # Check if signIn succeded
            if ($signInResult.code -ne 200) {
                throw ("Signing in failed with result: " + (ConvertTo-Json $signInResult))
            }
            $tokenHeader = $baseHeaders + @{
                authorization = $signInResult.data.token
            }
            Write-Host "Cloud Access Manager sign in succeeded"

            # Need plaintext registration code
            $clearRegCode = ConvertTo-Plaintext $registrationCode


            # Register Deployment
            $deploymentRequest = @{
                registrationCode = $clearRegCode
                deploymentName   = $RGName
            }
            $registerDeploymentResult = ""
            try {
                $registerDeploymentResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/deployments") -Body $deploymentRequest -Headers $tokenHeader
            }
            catch {
                if ($_.ErrorDetails.Message) {
                    $registerDeploymentResult = ConvertFrom-Json $_.ErrorDetails.Message
                }
                else {
                    throw $_
                }
            }
            Write-Verbose ((ConvertTo-Json $registerDeploymentResult) -replace "\.*registrationCode.*", 'registrationCode":"Sanitized"')
            # Check if registration succeeded
            if ( !( ($registerDeploymentResult.code -eq 201) -or (($registerDeploymentResult.data.reason -ne $null) -and $registerDeploymentResult.data.reason.ToLower().Contains("already exist")) ) ) {
                throw ("Registering Deployment failed with result: " + (ConvertTo-Json $registerDeploymentResult))
            }
            $deploymentId = ""
            # Get the deploymentId
            if ( ($registerDeploymentResult.code -eq 409) -and ($registerDeploymentResult.data.reason.ToLower().Contains("already exist")) ) {
                # Deployment is already registered so the deplymentId needs to be retrieved
                $registeredDeployment = ""
                try {
                    $registeredDeployment = Invoke-RestMethod -Method Get -Uri ($camSaasBaseUri + "/api/v1/deployments") -Body $deploymentRequest -Headers $tokenHeader
                    $deploymentId = $registeredDeployment.data.deploymentId
                }
                catch {
                    if ($_.ErrorDetails.Message) {
                        $registeredDeployment = ConvertFrom-Json $_.ErrorDetails.Message
                        throw ("Getting Deployment ID failed with result: " + (ConvertTo-Json $registeredDeployment))
                    }
                    else {
                        throw $_
                    }
                }
            }
            else {
                $deploymentId = $registerDeploymentResult.data.deploymentId
            }

            if ( !$deploymentId ) {
                throw ("Failed to get a Deployment ID")
            }

            Write-Host "Deployment has been registered successfully with Cloud Access Manager service"

            break;
        }
        catch {
            $camRegistrationError = $_
            Write-Verbose ( "Attempt {0} of $retryCount failed due to Error: {1}" -f ($idx + 1), $camRegistrationError )
            Start-Sleep -s $retryDelay
        }
        finally {
            # restore CertificatePolicy 
            if ( -not $isUnix ) {
                [System.Net.ServicePointManager]::CertificatePolicy = $certificatePolicy
            }
        }
    }
    if ($camRegistrationError) {
        throw $camRegistrationError
    }
    return $deploymentId
}

# Get  CAM and returns the deployment ID
function Update-CAMSumoCreds() {
    Param(
        [bool]
        $verifyCAMSaaSCertificate = $true,
        
        # Retry for CAM Registration
        $retryCount = 3,
        $retryDelay = 10,

        [parameter(Mandatory = $true)] 
        $subscriptionId,
        
        [parameter(Mandatory = $true)]
        $client,
        
        [parameter(Mandatory = $true)]
        $key,
        
        [parameter(Mandatory = $true)]
        $tenant,

        [parameter(Mandatory = $true)]
        $camSaasBaseUri,

        [parameter(Mandatory = $true)]
        $RootRGName,

        [parameter(Mandatory = $true)]
        $tempDir
    )

    #define variable to keep trace of the error during retry process
    $camRegistrationError = ""
    for ($idx = 0; $idx -lt $retryCount; $idx++) {
        # reset the variable at each iteration, so we can always keep the current loop error message
        $camRegistrationError = ""
        try {
            if ( -not $isUnix ) {
                $certificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                # Can't disable SSL verification for Invoke-RestMethod on Unix with this method
                # Not worth effort fixing since cert should always be valid
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
            }

            # Security Rules on CAM firewall don't like default user-agent for cloudshell, overwrite with a different one (Chrome)
            $baseHeaders = @{
                "User-Agent"="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
            }

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            ##


            $userRequest = @{
                username = $client
                password = $key
                tenantId = $tenant
                ownerTenantId = $ownerTenant
                ownerUpn = $ownerUpn
            }

            # Get a Sign-in token
            $signInResult = ""
            try {
                $signInResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/auth/signin") -Body $userRequest -Headers $baseHeaders
            }
            catch {
                if ($_.ErrorDetails.Message) {
                    $signInResult = ConvertFrom-Json $_.ErrorDetails.Message
                }
                else {
                    throw $_
                }
            }
            Write-Verbose ((ConvertTo-Json $signInResult) -replace "\.*token.*", 'Token": "Sanitized"')
            # Check if signIn succeded
            if ($signInResult.code -ne 200) {
                throw ("Signing in failed with result: " + (ConvertTo-Json $signInResult))
            }
            $tokenHeader = $baseHeaders + @{
                authorization = $signInResult.data.token
            }
            Write-Host "Cloud Access Manager sign in succeeded"

            Write-Host "Retreiving DeplotmentID"
            # Deployment is already registered so the deplymentId needs to be retrieved
            $registeredDeployment = ""
            $deploymentRequest = @{
                deploymentName   = $RootRGName
            }
            try {
                $registeredDeployment = Invoke-RestMethod -Method Get -Uri ($camSaasBaseUri + "/api/v1/deployments") -Body $deploymentRequest -Headers $tokenHeader
                if ($registeredDeployment.total -eq 0) {
                    $registeredDeployment = Invoke-RestMethod -Method Get -Uri ($camSaasBaseUri + "/api/v1/deployments?deploymentName=$RootRGName-RW") -Headers $tokenHeader
                }
                $deploymentId = $registeredDeployment.data.deploymentId
                if ( -not $deploymentId ) {
                    throw ("Getting Deployment ID failed")
                }
            }
            catch {
                if ($_.ErrorDetails.Message) {
                    $registeredDeployment = ConvertFrom-Json $_.ErrorDetails.Message
                    throw ("Getting Deployment ID failed with result: " + (ConvertTo-Json $registeredDeployment))
                }
                else {
                    throw $_
                }
            }
        
            # Get Sumo Creds
            $getSumoCredsResult = ""
            try {
                $getSumoCredsResult = Invoke-RestMethod -Method Get -Uri ($camSaasBaseUri + "/api/v1/deployments/$deploymentId/settings/logconfig") -Headers $tokenHeader
            }
            catch {
                if ($_.ErrorDetails.Message) {
                    $getSumoCredsResult = ConvertFrom-Json $_.ErrorDetails.Message
                }
                else {
                    throw $_
                }
            }
            # Check if registration succeeded
            if ( !( $getSumoCredsResult.code -eq 200) ) {
                throw ("Fetching SumoLogic Credentials failed with result: " + (ConvertTo-Json $getSumoCredsResult))
            }
            else {
                $sumoCreds = $getSumoCredsResult.data
            }
            Write-Host "SumoLogic Credentials retreived successfully from Cloud Access Manager service"
            break;
        }
        catch {
            $camRegistrationError = $_
            Write-Verbose ( "Attempt {0} of $retryCount failed due to Error: {1}" -f ($idx + 1), $camRegistrationError )
            Start-Sleep -s $retryDelay
        }
        finally {
            # restore CertificatePolicy 
            if ( -not $isUnix ) {
                [System.Net.ServicePointManager]::CertificatePolicy = $certificatePolicy
            }
        }
    }
    if ($camRegistrationError) {
        throw $camRegistrationError
    }
    $sumoCreds = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($sumoCreds)) | ConvertFrom-Json
    
    # Update Sumo Creds
    $userPropertiesContent = @"
collector.name=collectorID
sumo.accessid=$($sumoCreds.sumo_id)
sumo.accesskey=$($sumoCreds.sumo_key)
syncSources=syncsourceFile
"@
    $sumoConfContent = @"
name=collectorID
accessid=$($sumoCreds.sumo_id)
accesskey=$($sumoCreds.sumo_key)
syncSources=C:\\sumo\\sumo-agent-vm.json
"@
    $outputUserProp = Join-Path $tempDir "user.properties"
    $outputSumoConf = Join-Path $tempDir "sumo.conf"
    Set-Content $outputUserProp $userPropertiesContent
    Set-Content $outputSumoConf $sumoConfContent
    
    Write-Host "Logging into Azure Storage Account" 
    $container_name = "cloudaccessmanager"
    $userDataStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $RootRGName | Where {$_.StorageAccountName -match "cam"}
    $acct_name = $userDataStorageAccount.StorageAccountName
    $acctKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $RootRGName -AccountName $acct_name).Value[0]
    $ctx = New-AzureStorageContext -StorageAccountName $acct_name -StorageAccountKey $acctKey
    
    Set-AzureStorageBlobContent `
        -Container $container_name `
        -Context $ctx `
        -Blob "remote-workstation/user.properties" `
        -File $outputUserProp `
        -Force

    Set-AzureStorageBlobContent `
        -Container $container_name `
        -Context $ctx `
        -Blob "remote-workstation/sumo.conf" `
        -File $outputSumoConf `
        -Force
}

# updates service principal password in CAM KeyVault
function Update-CAMUserCredential() {
    Param(
        [bool]
        $verifyCAMSaaSCertificate = $true,
        
        # Retry for CAM Registration
        $retryCount = 3,
        $retryDelay = 10,

        [parameter(Mandatory = $true)]
        $client,
        
        [parameter(Mandatory = $true)]
        $key,
        
        [parameter(Mandatory = $true)]
        $tenant,
        
        [parameter(Mandatory = $true)]
        $ownerTenant,

        [parameter(Mandatory = $true)]
        $ownerUpn,

        [parameter(Mandatory = $true)]
        $camSaasBaseUri
    )

    $spUpdatedSuccessfully = $false

    #define variable to keep trace of the error during retry process
    $camUpdateUserCredentialError = ""
    for ($idx = 0; $idx -lt $retryCount; $idx++) {
        # reset the variable at each iteration, so we can always keep the current loop error message
        $camUpdateUserCredentialError = ""
        try {
            if ( -not $isUnix ) {
                $certificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                # Can't disable SSL verification for Invoke-RestMethod on Unix with this method
                # Not worth effort fixing since cert should always be valid
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
            }

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            ##

            $userRequest = @{
                username = $client
                password = $key
                tenantId = $tenant
                ownerTenantId = $ownerTenant
                ownerUpn = $ownerUpn
            }

            $baseHeaders = @{
                "User-Agent"="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
            }

            # Get a Sign-in token
            $signInResult = ""
            try {
                $signInResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/auth/signin") -Body $userRequest -Headers $baseHeaders
            }
            catch {
                if ($_.ErrorDetails.Message) {
                    $signInResult = ConvertFrom-Json $_.ErrorDetails.Message
                }
                else {
                    throw $_
                }
            }
            Write-Verbose ((ConvertTo-Json $signInResult) -replace "\.*token.*", 'Token": "Sanitized"')
            # Check if signIn succeded
            if ($signInResult.code -ne 200) {
                throw ("Signing in failed with result: " + (ConvertTo-Json $signInResult))
            }
            $tokenHeader = $baseHeaders + @{
                authorization = $signInResult.data.token
            }

            $decodedToken = Get-DecodedJWT `
                -Token $signInResult.data.token

            $userId = $decodedToken.claims.oid

            Write-Host "Cloud Access Manager sign in succeeded"

            # Update service principal credential
            $updateUserCredentialRequest = @{
                password = $key
            }
            $updateUserCredentialRequestJson = $updateUserCredentialRequest | ConvertTo-Json;
            $updateUserCredentialResult = ""
            try {
                $updateUserCredentialResult = Invoke-RestMethod -Method PUT -Uri ($camSaasBaseUri + "/api/v1/auth/users/" + $userId + "/credential") -Body $updateUserCredentialRequestJson -Headers $tokenHeader -ContentType 'application/json'
            }
            catch {
                if ($_.ErrorDetails.Message) {
                    $updateUserCredentialResult = ConvertFrom-Json $_.ErrorDetails.Message
                }
                else {
                    throw $_
                }
            }
            Write-Verbose ((ConvertTo-Json $updateUserCredentialResult) -replace "\.*registrationCode.*", 'registrationCode":"Sanitized"')
            if ( $updateUserCredentialResult.code -eq 200 ) {
                $spUpdatedSuccessfully = $true    
            }

            if ( !$spUpdatedSuccessfully ) {
                throw ("Updating the Service Principal password in the Cloud Access Manager service failed with result: " + (ConvertTo-Json $updateUserCredentialResult))
            }

            Write-Host "Service Principal password has been updated successfully in Cloud Access Manager service"

            break;
        }
        catch {
            $camUpdateUserCredentialError = $_
            Write-Verbose ( "Attempt {0} of $retryCount failed due to Error: {1}" -f ($idx + 1), $camUpdateUserCredentialError )
            Start-Sleep -s $retryDelay
        }
        finally {
            # restore CertificatePolicy 
            if ( -not $isUnix ) {
                [System.Net.ServicePointManager]::CertificatePolicy = $certificatePolicy
            }
        }
    }
    if ($camUpdateUserCredentialError) {
        throw $camUpdateUserCredentialError
    }
    return $spUpdatedSuccessfully
}

function New-UserStorageAccount {
    Param(
        $RGName,
        $location, 
        [HashTable]
        $tag
    )

    $saName = -join ((97..122) | Get-Random -Count 16 | % {[char]$_})
    $saName = 'cam0' + $saName

    Write-Host "Creating user data storage account $saName in resource group $RGName and location $location"

    $acct = New-AzureRmStorageAccount `
        -ResourceGroupName $RGName `
        -AccountName $saName `
        -Location $location `
        -SkuName "Standard_LRS" `
        -EnableHttpsTrafficOnly $false `
        -Tag $tag

    return $acct
}

function New-RemoteWorkstationTemplates {
    param (
        $CAMConfig,
        $binaryLocation,
        $kvId,
        $storageAccountContext,
        $storageAccountContainerName,
        $storageAccountSecretName,
        $storageAccountKeyName,
        $tempDir,
        $tag
    )

    Write-Host "Creating default remote workstation template parameters file data"

    # Setup internal variables from config structure
    $standardVMSize = $CAMConfig.internal.standardVMSize
    $graphicsVMSize = $CAMConfig.internal.graphicsVMSize
    $agentARM = $CAMConfig.internal.agentARM
    $gaAgentARM = $CAMConfig.internal.gaAgentARM
    $linuxAgentARM = $CAMConfig.internal.linuxAgentARM
    $gaLinuxAgentARM = $CAMConfig.internal.gaLinuxAgentARM

    $domainServiceAccountUsername = $CAMConfig.parameters.domainServiceAccountUsername.clearValue
    $domainFQDN = $CAMConfig.parameters.domainName.clearValue

    $agentChannel = $CAMConfig.internal.agentChannel
    $tagString = $tag | ConvertTo-Json -Compress

    $armParamContent = @"
{
    "`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "domainOrganizationUnitToJoin": { "value": "" },
        "imageReferenceId": { "value": "" },
        "location": { "value": "$($CAMConfig.internal.location)" },
        "agentType": { "value": "%agentType%" },
        "vmSize": { "value": "%vmSize%" },
        "autoShutdownIdleTime" : { "value": $defaultIdleShutdownTime },
        "AgentChannel": { "value": "$agentChannel"},
        "binaryLocation": { "value": "$binaryLocation" },
        "subnetID": { "value": "$($CAMConfig.parameters.remoteWorkstationSubnet.clearValue)" },
        "domainUsername": { "value": "$domainServiceAccountUsername" },
        "tag": { "value": $tagString},
        "userStorageAccountName": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "userStorageName"
            }
        },
        "userStorageAccountUri": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "userStorageAccountUri"
            }
        },
        "userStorageAccountSasToken": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "userStorageAccountSasToken"
            }
        },
        "userStorageAccountKey": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "userStorageAccountKey"
            }        
        },
        "domainPassword": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "domainServiceAccountPassword"
            }        
        },
        "registrationCode": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "cloudAccessRegistrationCode"
            }
        },
        "dnsLabelPrefix": { "value": "tbd-vmname" },
        "vmAdminUsername": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "remoteWorkstationLocalAdminUsername"
            }
        },
        "vmAdminPassword": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "remoteWorkstationLocalAdminPassword"
            }
        },
        "domainGroupToJoin": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "remoteWorkstationDomainGroup"
            }
        },
        "domainToJoin": { "value": "$domainFQDN" }
    }
}
"@

    $standardArmParamContent = $armParamContent -replace "%vmSize%", $standardVMSize
    $graphicsArmParamContent = $armParamContent -replace "%vmSize%", $graphicsVMSize
    $linuxArmParamContent = $armParamContent -replace "%vmSize%", $standardVMSize
    $graphicsLinuxArmParamContent = $armParamContent -replace "%vmSize%", $graphicsVMSize

    $standardArmParamContent = $standardArmParamContent -replace "%agentType%", "Standard"
    $graphicsArmParamContent = $graphicsArmParamContent -replace "%agentType%", "Graphics"
    $linuxArmParamContent = $linuxArmParamContent -replace "%agentType%", "Standard"
    $graphicsLinuxArmParamContent = $graphicsLinuxArmParamContent -replace "%agentType%", "Graphics"

    Write-Host "Creating default template parameters files"

    #now make the default parameters filenames - same root name but different suffix as the templates
    $agentARMparam = ($agentARM.split('.')[0]) + ".customparameters.json"
    $gaAgentARMparam = ($gaAgentARM.split('.')[0]) + ".customparameters.json"
    $linuxAgentARMparam = ($linuxAgentARM.split('.')[0]) + ".customparameters.json"
    $gaLinuxAgentARMparam = ($gaLinuxAgentARM.split('.')[0]) + ".customparameters.json"

    #these will be put in the random temp directory to avoid filename conflicts
    $ParamTargetFilePath = Join-Path -Path "$tempDir" -ChildPath "$agentARMparam"
    $GaParamTargetFilePath = Join-Path -Path "$tempDir" -ChildPath "$gaAgentARMparam"
    $LinuxParamTargetFilePath = Join-Path -Path "$tempDir" -ChildPath "$linuxAgentARMparam"
    $GaLinuxParamTargetFilePath = Join-Path -Path "$tempDir" -ChildPath "$gaLinuxAgentARMparam"

    # upload the param files to the blob
    $paramFiles = @(
        @($ParamTargetFilePath, $standardArmParamContent),
        @($GaParamTargetFilePath, $graphicsArmParamContent),
        @($LinuxParamTargetFilePath, $linuxArmParamContent),
        @($GaLinuxParamTargetFilePath, $graphicsLinuxArmParamContent)
    )
    ForEach ($item in $paramFiles) {
        $filepath = $item[0]
        $content = $item[1]
        if (-not (Test-Path $filepath)) {
            New-Item $filepath -type file
        }
        Set-Content $filepath $content -Force

        $file = Split-Path $filepath -leaf
        try {
            Get-AzureStorageBlob `
                -Context $storageAccountContext `
                -Container $storageAccountContainerName `
                -Blob "remote-workstation-template/$file" `
                -ErrorAction Stop
            # file already exists do nothing
        }
        Catch {
            Write-Host "Uploading $filepath to blob"
            Set-AzureStorageBlobContent `
                -File $filepath `
                -Container $storageAccountContainerName `
                -Blob "remote-workstation-template/$file" `
                -Context $storageAccountContext
        }
    }

    Write-Host "Finished Creating default template parameters file data"
}



function Populate-UserBlob {
    Param(
        $CAMConfig,
        $artifactsLocation,
        $userDataStorageAccount,
        $binaryLocation,
        $sumoAgentApplicationVM,
        $sumoConf,
        $idleShutdownLinux,
        $RGName,
        $kvInfo,
        $tempDir,
        $tag
    )

    $kvId = $kvInfo.ResourceId

    ################################
    Write-Host "Populating user blob"
    ################################
    $container_name = "cloudaccessmanager"
    $acct_name = $userDataStorageAccount.StorageAccountName

    #source, targetdir pairs
    $new_agent_vm_files = @(
        @("$artifactsLocation/remote-workstations/new-agent-vm/Install-PCoIPAgent.ps1", "remote-workstation"),
        @("$artifactsLocation/remote-workstations/new-agent-vm/Install-PCoIPAgent.sh", "remote-workstation"),
        @("$binaryLocation/Install-PCoIPAgent.ps1.zip", "remote-workstation"),
        @("$artifactsLocation/remote-workstations/new-agent-vm/sumo-agent-vm.json", "remote-workstation"),
        @("$artifactsLocation/remote-workstations/new-agent-vm/sumo-agent-vm-linux.json", "remote-workstation"),
        @("$artifactsLocation/remote-workstations/new-agent-vm/Install-Idle-Shutdown.sh", "remote-workstation"),
        @("$artifactsLocation/remote-workstations/new-agent-vm/$($CAMConfig.internal.linuxAgentARM)", "remote-workstation-template"),
        @("$artifactsLocation/remote-workstations/new-agent-vm/$($CAMConfig.internal.gaLinuxAgentARM)", "remote-workstation-template"),
        @("$artifactsLocation/remote-workstations/new-agent-vm/$($CAMConfig.internal.gaAgentARM)", "remote-workstation-template"),
        @("$artifactsLocation/remote-workstations/new-agent-vm/$($CAMConfig.internal.agentARM)", "remote-workstation-template")
    )



    # Suppress output to pipeline so the return value of the function is the one
    # hash table we want.
    $null = @(
        $acctKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $RGName -AccountName $acct_name).Value[0]
        $ctx = New-AzureStorageContext -StorageAccountName $acct_name -StorageAccountKey $acctKey
        try {
            Get-AzureStorageContainer -Name $container_name -Context $ctx -ErrorAction Stop
        }
        Catch {
            # No container - make one.
            # -Permission needs to be off to allow only owner read and to require access key!
            New-AzureStorageContainer -Name $container_name -Context $ctx -Permission "Off" -ErrorAction Stop
        }

        Write-Host "Uploading files to private blob"
        ForEach ($fileRecord in $new_agent_vm_files) {
            $fileURI = $fileRecord[0]
            $targetDir = $fileRecord[1]
            $fileName = $fileURI.Substring($fileURI.lastIndexOf('/') + 1)
            try {
                Get-AzureStorageBlob `
                    -Context $ctx `
                    -Container $container_name `
                    -Blob "$targetDir/$fileName" `
                    -ErrorAction Stop
                # file already exists do nothing
            }
            Catch {
                Write-Host "Downloading $fileURI"
                $localRemoteFile=Join-Path -Path $tempDir -ChildPath $fileName
                Invoke-WebRequest `
                    -Uri $fileURI `
                    -OutFile $localRemoteFile
                Write-Host "Uploading $fileName to blob"
                Set-AzureStorageBlobContent `
                    -Container $container_name `
                    -Context $ctx `
                    -Blob "$targetDir/$fileName" `
                    -File $localRemoteFile `
                    -Force
            }
        }
        Write-Host "Blob copy complete"

        $blobUri = $ctx.BlobEndPoint + $container_name + '/'

        # Setup deployment parameters/Keyvault secrets
        # this is the url to access the blob account
        $CAMConfig.parameters.userStorageAccountUri.value = (ConvertTo-SecureString $blobUri -AsPlainText -Force)
        $CAMConfig.parameters.userStorageName.value = (ConvertTo-SecureString $acct_name -AsPlainText -Force)
        $CAMConfig.parameters.userStorageAccountKey.value = (ConvertTo-SecureString $acctKey -AsPlainText -Force)

        $saSasToken = New-AzureStorageAccountSASToken -Service Blob -Resource Object -Context $ctx -ExpiryTime ((Get-Date).AddYears(2)) -Permission "racwdlup" 
        $CAMConfig.parameters.userStorageAccountSasToken.value = (ConvertTo-SecureString $saSasToken -AsPlainText -Force)

        # Generate and upload the parameters files

        # binaryLocation is the original binaries source location hosted by Teradici
        # blobUri is the new per-deployment blob storage location of the binaries (so a sub-directory in the container)
        New-RemoteWorkstationTemplates `
            -CAMConfig $CAMConfig `
            -binaryLocation $binaryLocation `
            -kvId $kvId `
            -storageAccountContext $ctx `
            -storageAccountContainerName $container_name `
            -storageAccountSecretName $storageAccountSecretName `
            -storageAccountKeyName $storageAccountKeyName `
            -tempDir $tempDir `
            -tag $tag
    )
}




# Creates a key vault in the target resource group and gives the current service principal access to the secrets.
function New-CAM-KeyVault() {
    Param(
        [parameter(Mandatory = $true)] 
        [String]
        $RGName,

        [parameter(Mandatory = $true)] 
        [String]
        $spName,

        [parameter(Mandatory = $true)]
        $adminAzureContext,

        [HashTable]
        $tag
    )


    $keyVault = $null
    try {
        #KeyVault names must be globally (or at least regionally) unique, so make a unique string

        $generatedKVID = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
        $kvName = "CAM-$generatedKVID"

        Write-Host "Creating Azure Key Vault $kvName"

        $rg = Get-AzureRmResourceGroup -ResourceGroupName $RGName
        # Some Versions of New-AzureRmKeyVault have no EnableSoftDelete opyion since it's enabled
        # by default (it has DisableSoftDelete instead)
        try {
            $keyVault = New-AzureRmKeyVault `
                -VaultName $kvName `
                -ResourceGroupName $RGName `
                -Location $rg.Location `
                -EnabledForTemplateDeployment `
                -EnabledForDeployment `
                -EnableSoftDelete `
                -WarningAction Ignore `
                -Tag $tag
        } catch {
            $keyVault = New-AzureRmKeyVault `
                -Name $kvName `
                -ResourceGroupName $RGName `
                -Location $rg.Location `
                -EnabledForTemplateDeployment `
                -EnabledForDeployment `
                -WarningAction Ignore `
                -Tag $tag
        }

        Write-Host "Setting Access Policy on Azure Key Vault $kvName"

        #keyvault populate retry is to catch the case where the DNS has not been updated
        #from the keyvault creation by the time we get here
        $keyVaultPopulateRetry = 60
        while ($keyVaultPopulateRetry -ne 0) {
            $keyVaultPopulateRetry--

            try {
                Write-Host "Set access policy for vault $kvName for user $spName"
                Set-AzureRmKeyVaultAccessPolicy `
                    -VaultName $kvName `
                    -ServicePrincipalName $spName `
                    -PermissionsToSecrets Get, Set, List `
                    -ErrorAction stop | Out-Null

                break
            }
            catch {
                Write-Host "Waiting for Key Vault: $keyVaultPopulateRetry"
                if ( $keyVaultPopulateRetry -eq 0) {
                    #TODO: be smarter - we should only retry if the vault doesn't exist yet not on rights issues...
                    #re-throw whatever the original exception was
                    throw
                }
                Start-sleep -Seconds 1 | Out-Null
            }
        }
    }
    catch {
        Write-Error "Error creating Key Vault"
    }

    # Try to set key vault access for the calling administrator (if they have rights...)

    # Get previous service principal context and set back to admin
    $spContext = Get-AzureRMContext
    Set-AzureRMContext -Context $adminAzureContext | Out-Null
    $claims = Get-Claims # Current logged in user info

    try {
        Set-AzureRmKeyVaultAccessPolicy `
            -VaultName $kvName `
            -ObjectId $claims.oid `
            -PermissionsToSecrets Get, Set, List `
            -ErrorAction stop | Out-Null
        Write-Host "Successfully set access policy for vault $kvName for user $($claims.unique_name)"
        }
    catch {
        # Silently swallow exception
    }

    # Set context back to service principal
    Set-AzureRMContext -Context $spContext | Out-Null

    return $keyVault
}

# Populates the vault with generated passwords and the app gateway certificate
function Generate-Certificate-And-Passwords() {
    Param(
        [parameter(Mandatory = $true)]
        [String]
        $kvName,

        [parameter(Mandatory = $true)]
        $CAMConfig,

        [parameter(Mandatory = $false)]
        [String]
        $certificateFile = $null,

        [parameter(Mandatory = $false)]
        [SecureString]
        $certificateFilePassword = $null,

        [parameter(Mandatory = $true)]
        [String]
        $tempDir
    )

    Write-Host "Creating Local Admin Password for new remote workstations"

    $rwLocalAdminPasswordStr = "5!" + ( -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})) # "5!" is to ensure numbers and symbols

    $rwLocalAdminPassword = ConvertTo-SecureString $rwLocalAdminPasswordStr -AsPlainText -Force
    $CAMConfig.parameters.remoteWorkstationLocalAdminPassword.value = $rwLocalAdminPassword

    Write-Host "Creating Local Admin Password for Cloud Access connector servers"

    $csLocalAdminPasswordStr = "5!" + ( -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})) # "5!" is to ensure numbers and symbols

    $csLocalAdminPassword = ConvertTo-SecureString $csLocalAdminPasswordStr -AsPlainText -Force
    $CAMConfig.parameters.connectionServiceLocalAdminPassword.value = $csLocalAdminPassword

    # App gateway certificate info
    $certInfo = Get-CertificateInfoForAppGateway -certificateFile $certificateFile -certificateFilePassword $certificateFilePassword -tempDir $tempDir

    $CAMConfig.parameters.CAMCSCertificate.value = $certInfo.cert
    $CAMConfig.parameters.CAMCSCertificatePassword.value = $certInfo.passwd

    Write-Host "Successfully imported certificate"
}



function Get-CertificateInfoForAppGateway() {
    Param(
        [parameter(Mandatory = $false)]
        [String]
        $certificateFile = $null,

        [parameter(Mandatory = $false)]
        [SecureString]
        $certificateFilePassword = $null,

        [parameter(Mandatory = $false)]
        [String]
        $tempDir
    )

    # default to create self-signed certificate
    $needToCreateSelfCert = $true
    # check if the certificateFile and certificatePassword is null or empty
    # A variable that is null or empty string evaluates to false.
    if ( $certificateFile -and $certificateFilePassword ) {
        Write-Host "using provided certificate $certificateFile for Application Gateway"
        try {
            if (-not $isUnix) {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert.Import($certificateFile, $certificateFilePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"DefaultKeySet")
            } else {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2::Import($certificateFile, $certificateFilePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"DefaultKeySet")
            }
            $needToCreateSelfCert = $false
        }
        catch {
            $errStr = "Could not read certificate from certificate file: " + $certificateFile
            throw $errStr
        }
    } 

    if ($needToCreateSelfCert) {
        # create self signed certificate for Application Gateway.
        # System Administrators can override the self signed certificate if desired in future.
        if (-not $isUnix) {
            # In order to create the certificate you must be running as Administrator on a Windows 10/Server 2016 machine
            # (Potentially Windows 8/Server 2012R2, but not Windows 7 or Server 2008R2)

            Write-Host "Creating Self-signed certificate for Application Gateway"

            #TODO - this is broken??? No maybe fixed with new catch block below. Should re-test.
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
            $isAdminSession = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (!$isAdminSession) {
                $errStr = "You must be running as administrator to create the self-signed certificate for the application gateway"
                Write-error $errStr
                throw $errStr
            }

            if (! (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue) ) {
                $errStr = "New-SelfSignedCertificate cmdlet must be available - please ensure you are running on a supported OS such as Windows 10 or Server 2016"
                Write-error $errStr
                throw $errStr
            }

            $certLoc = 'cert:Localmachine\My'
            $startDate = [DateTime]::Now.AddDays(-1)

            # add some randomization to the subject to get around the Firefox TLS issue referenced here:
            # https://www.thesslstore.com/blog/troubleshoot-firefoxs-tls-handshake-message/
            # (all lower case letters)
            # (However this is causing issues with the software PCoIP Client so we need some more
            # investigation on what is changable in the certificate.
            #$subjectOU = -join ((97..122) | Get-Random -Count 18 | ForEach-Object {[char]$_})

            $subject = "CN=localhost,O=Teradici Corporation,OU=SoftPCoIP,L=Burnaby,ST=BC,C=CA"

            $cert = New-SelfSignedCertificate `
                -certstorelocation $certLoc `
                -DnsName "*.cloudapp.net" `
                -Subject $subject `
                -KeyLength 3072 `
                -FriendlyName "PCoIP Application Gateway" `
                -NotBefore $startDate `
                -TextExtension @("2.5.29.19={critical}{text}ca=1") `
                -HashAlgorithm SHA384 `
                -KeyUsage DigitalSignature, CertSign, CRLSign, KeyEncipherment

            Write-Host "Certificate generated, formatting as .pfx file"

            # Generate pfx file from certificate
            $certPath = $certLoc + '\' + $cert.Thumbprint

            if (-not $tempDir) {
                $tempDir = $env:TEMP
            }

            $certificateFile = Join-Path $tempDir "self-signed-cert.pfx"
            if (Test-Path $certificateFile) {
                Remove-Item $certificateFile
            }

            # Generate password for pfx file
            # https://docs.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl
            # The certificate password must be between 4 to 12 characters made up of letters or numbers.
            # Special characters are not accepted.
            $certPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 10 | % {[char]$_})

            $certificateFilePassword = ConvertTo-SecureString -String $certPswd -AsPlainText -Force

            # Export pfx file
            Export-PfxCertificate -Cert $certPath -FilePath $certificateFile -Password $certificateFilePassword

            # Delete self-signed certificate
            if (Test-Path $certPath) { 
                Remove-Item $certPath -ErrorAction SilentlyContinue
            }
        } else {
            Write-Host "Creating Self-signed certificate for Application Gateway"

            $subject = "/CN=*.cloudapp.net,/CN=localhost,/O=Teradici Corporation,/OU=SoftPCoIP,/L=Burnaby,/ST=BC,/C=CA"
            if (-not $tempDir) {
                $tempDir = $env:TEMP
            }

            # Generate password for pfx file
            # https://docs.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl
            # The certificate password must be between 4 to 12 characters made up of letters or numbers.
            # Special characters are not accepted.
            $certPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 10 | % {[char]$_})
            $certificateFilePassword = ConvertTo-SecureString -String $certPswd -AsPlainText -Force

            openssl req -x509 -newkey rsa:3072 -keyout "$tempDir/key.pem" -out "$tempDir/cert.pem" -days 365 -subj $subject -sha384 -passout pass:$certPswd
            
            Write-Host "Certificate generated, formatting as .pfx file"

            $certificateFile = Join-Path $tempDir "self-signed-cert.pfx"
            if (Test-Path $certificateFile) {
                Remove-Item $certificateFile
            }            

            # Export pfx file
            openssl pkcs12 -inkey "$tempDir/key.pem" -in "$tempDir/cert.pem" -export -out $certificateFile -passin pass:$certPswd -passout pass:$certPswd
            Remove-Item cert.pem -ErrorAction SilentlyContinue
            Remove-Item key.pem -ErrorAction SilentlyContinue
        }
    } 

    # Read from pfx file and convert to base64 string
    $fileContentEncoded = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($certificateFile))

    $CSCertificate = ConvertTo-SecureString $fileContentEncoded -AsPlainText -Force

    $certInfo = @{
        "cert"   = $CSCertificate;
        "passwd" = $certificateFilePassword
    }

    # Delete certificate file if it is generated
    if ($needToCreateSelfCert -and (Test-Path  $certificateFile) ) { 
        Remove-Item $certificateFile -ErrorAction SilentlyContinue 
    }

    return $certInfo
}



# Adds all the parameters in the CAMConfig.parameters sub-tree as keyvault secrets
function Add-SecretsToKeyVault() {
    Param(
        [parameter(Mandatory = $true)]
        [String]
        $kvName,

        [parameter(Mandatory = $true)]
        $CAMConfig
    )
    Write-Host "Populating Key Vault"

    foreach ($key in $CAMConfig.parameters.keys) {
        Set-KVSecret -kvName $kvName -secretName $key -secretValue $CAMConfig.parameters[$key].value
    }

    Write-Host "Completed writing secrets to Key Vault"
}



function New-CAMAppSP() {
    param(
        $RGName
    )

    # Application name
    $appName = "CAM-$RGName"
    Write-Host "Calling Azure Active Directory to make app $appName and a service principal"

    # 16 letter password
    $generatedPassword = ConvertTo-SecureString -String ( -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})) -AsPlainText -Force
    $generatedID = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
    $appURI = "https://www.$generatedID.com"

    Write-Host "Purge any registered apps with the same name"

    # first make sure if there is an app there (or more than one if that's possible?)
    # that they're deleted.
    $appArray = Get-AzureRmADApplication -DisplayName $appName
    foreach ($app in $appArray) {
        $aoID = $app.ObjectId
        try {
            Write-Host "Removing previous service principal application $appName ObjectId: $aoID"
            Remove-AzureRmADApplication -ObjectId $aoID -Force -ErrorAction Stop
        }
        catch {
            $exceptionContext = Get-AzureRmContext
            $exceptionTenantId = $exceptionContext.Tenant.Id
            Write-Error "Failure to remove application $appName from tenant $exceptionTenantId, please check your AAD tenant permissions"

            # Re-throw whatever the original exception was
            throw
        }
    }

    Write-Host "Purge complete, creating new app $appName"

    # Retry required on app registration (it seems) if there is a race condition with the deleted application.
    $newAppCreateRetry = 60
    while ($newAppCreateRetry -ne 0) {
        $newAppCreateRetry--

        try {
            $app = New-AzureRmADApplication `
                -DisplayName $appName `
                -HomePage $appURI `
                -IdentifierUris $appURI `
                -Password $generatedPassword `
                -ErrorAction Stop
            break
        }
        catch {
            Write-Host "Retrying to create app countdown: $newAppCreateRetry appName: $appName"
            Start-sleep -Seconds 1
            if ($newAppCreateRetry -eq 0) {
                #re-throw whatever the original exception was
                $exceptionContext = Get-AzureRmContext
                $exceptionTenantId = $exceptionContext.Tenant.Id
                Write-Error "Failure to add application $appName to tenant $exceptionTenantId, please check your AAD tenant permissions"
                throw
            }
        }
    }


    Write-Host "New app creation complete, creating service principal"

    # Retry required since it can take a few seconds for the app registration to percolate through Azure.
    # (Online recommendation was sleep 15 seconds - this is both faster and more conservative)
    $sp = $null
    $SPCreateRetry = 60
    while ($SPCreateRetry -ne 0) {
        $SPCreateRetry--

        try {
            $sp = New-AzureRmADServicePrincipal -ApplicationId $app.ApplicationId -ErrorAction Stop
            break
        }
        catch {
            $appIDForPrint = $app.ObjectId

            Write-Host "Waiting for app $SPCreateRetry : $appIDForPrint"
            Start-sleep -Seconds 1
            if ($SPCreateRetry -eq 0) {
                #re-throw whatever the original exception was
                Write-Error "Failure to create service principal for $appName"
                throw
            }
        }
    }

    # Get service principal credentials
    $spPass = $generatedPassword
    $spCreds = New-Object -TypeName pscredential -ArgumentList  $sp.ApplicationId, $spPass

    # Get tenant ID for this subscription
    $subForTenantID = Get-AzureRmContext
    $tenantID = $subForTenantID.Tenant.TenantId

    $spInfo = @{}
    $spInfo.Add("spCreds", $spCreds);
    $spInfo.Add("tenantId", $tenantID);
    $spInfo.Add("objectId", $app.ObjectId);

    return $spInfo
}

# Creates cam deployment info structures and pushes to Key Vault
function New-CAMDeploymentInfo() {
    param(
        [parameter(Mandatory = $true)] 
        $kvName # Key Vault name
    )

    Write-Host "Populating CAMDeploymentInfo structure"


    # Mapping CAM deployment info environment variable parameters
    # to Key Vault Secrets 
    $camDeploymenRegInfoParameters = @{
        "CAM_USERNAME"       = "AzureSPClientID"
        "CAM_PASSWORD"       = "AzureSPKey"
        "CAM_TENANTID"       = "AzureSPTenantID"
        "CAM_URI"            = "CAMServiceURI"
        "CAM_DEPLOYMENTID"   = "CAMDeploymentID"
        "CAM_SUBSCRIPTIONID" = "AzureSubscriptionID"
        "CAM_RESOURCEGROUP"  = "AzureResourceGroupName"
        "CAM_KEY_VAULT_NAME" = "AzureKeyVaultName"
    }


    $camDeploymenRegInfo = @{}

    foreach ($key in $camDeploymenRegInfoParameters.keys) {
        $secretName = $camDeploymenRegInfoParameters.$key
        Write-Host "Setting $key to value of secret $secretName"

        $secret = Get-KVSecret -kvName $kvName -secretName $secretName
        if($secret.SecretValueText) {
            $InfoSecret = $secret.SecretValueText
        } else {
            $InfoSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
        }
        $camDeploymenRegInfo.$key = $InfoSecret
    
    }

    $camDeploymenRegInfo.Add("CAM_USER_BLOB_URI", "userStorageAccountUri")
    $camDeploymenRegInfo.Add("CAM_USER_STORAGE_ACCOUNT_NAME", "userStorageName")
    $camDeploymenRegInfo.Add("CAM_USER_STORAGE_ACCOUNT_KEY", "userStorageAccountKey")
    $camDeploymenRegInfo.Add("CAM_USER_BLOB_TOKEN", "userStorageAccountSasToken")


    $authFileContent = @"
subscription=$($camDeploymenRegInfo.CAM_SUBSCRIPTIONID)
client=$($camDeploymenRegInfo.CAM_USERNAME)
key=$($camDeploymenRegInfo.CAM_PASSWORD)
tenant=$($camDeploymenRegInfo.CAM_TENANTID)
managementURI=https\://management.core.windows.net/
baseURL=https\://management.azure.com/
authURL=https\://login.windows.net/
graphURL=https\://graph.windows.net/
"@
    Add-Type -AssemblyName System.Web
    $authFileContentURL = [System.Web.HttpUtility]::UrlEncode($authFileContent) 

    $camDeploymenInfo = @{};
    $camDeploymenInfo.Add("registrationInfo", $camDeploymenRegInfo)
    $camDeploymenInfo.Add("AzureAuthFile", $authFileContentURL)

    $camDeploymenInfoJSON = ConvertTo-JSON $camDeploymenInfo -Depth 99 -Compress
    $camDeploymenInfoURL = [System.Web.HttpUtility]::UrlEncode($camDeploymenInfoJSON)

    $camDeploymenInfoURLSecure = ConvertTo-SecureString $camDeploymenInfoURL -AsPlainText -Force

    # Put URL encoded blob into Key Vault 
    Set-KVSecret -kvName $kvName -secretname "CAMDeploymentInfo" -secretValue $camDeploymenInfoURLSecure

    <# Test code for encoding/decoding
    $camDeploymenInfoURL
    $camDeploymenInfoJSONDecoded = [System.Web.HttpUtility]::UrlDecode($camDeploymenInfoURL)
    $camDeploymenInfoDecoded = ConvertFrom-Json $camDeploymenInfoJSONDecoded


    [System.Web.HttpUtility]::UrlDecode($camDeploymenInfoDecoded.AzureAuthFile)

    $regInfo = $camDeploymenInfoDecoded.RegistrationInfo

    $regInfo.psobject.properties | Foreach-Object {
        Write-Host "Name: " $_.Name " Value: " $_.Value

    #>

}



function Generate-CamDeploymentInfoParameters {
    param(
        $spInfo,
        $camSaasUri,
        $deploymentId,
        $subscriptionID,
        $RGName,
        $kvName
    )
    $CAMConfig.parameters.AzureSPClientID.value = (ConvertTo-SecureString $spInfo.spCreds.UserName -AsPlainText -Force)
    $CAMConfig.parameters.AzureSPKey.value = $spInfo.spCreds.Password
    $CAMConfig.parameters.AzureSPTenantID.value = (ConvertTo-SecureString $spInfo.tenantId -AsPlainText -Force)
    $CAMConfig.parameters.AzureSPObjectId.value = (ConvertTo-SecureString $spInfo.objectId -AsPlainText -Force)
    $CAMConfig.parameters.CAMServiceURI.value = (ConvertTo-SecureString $camSaasUri -AsPlainText -Force)
    $CAMConfig.parameters.CAMDeploymentID.value = (ConvertTo-SecureString $deploymentId -AsPlainText -Force)
    $CAMConfig.parameters.AzureSubscriptionID.value = (ConvertTo-SecureString $subscriptionID -AsPlainText -Force)
    $CAMConfig.parameters.AzureResourceGroupName.value = (ConvertTo-SecureString $RGName -AsPlainText -Force)
    $CAMConfig.parameters.AzureKeyVaultName.value = (ConvertTo-SecureString $kvName -AsPlainText -Force)
}


function Append-AzureRMLog {
    param(
        $err
    )
    $text = $err.exception.Message

    # Ensure the string 'tracking ID' and a GUID show up to try to get AzureRM logs
    if( ([regex]::matches($text, "tracking id"))[0].value ){
        $GUIDpattern = "[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}"
        $trackingID = ([regex]::matches($text, $GUIDpattern))[0].value

        if($trackingID) {
            Write-Host-Warning "Deployment Error Occurred, Azure tracking ID is '$trackingID'"
            $index = 60 # around 5 minutes
            $badAzureRMLogCount = 10 # if the structure isn't fully populated, give another few tries
            while ($index--){
                $azureRMLog = Get-AzureRMLog -CorrelationId $trackingID -WarningAction silentlyContinue
                if($azureRMLog) {
                    if ($azureRMLog.properties -and $azureRMLog.properties[0].Content.statusMessage) {
                        $jsonError = ConvertFrom-Json $azureRMLog.properties[0].Content.statusMessage
                        $fullMessage = $err.exception.Message + ($jsonError.error.details | Format-List | Out-String)
                        Write-Host-Warning $fullMessage
                        return $jsonError.error.details.message
                    }
                    else
                    {
                        if($badAzureRMLogCount--)
                        {
                            Write-Host "Unexpected error format - retries remaining: $badAzureRMLogCount"
                        }
                        else {
                            Write-Host ($azureRMLog | Out-String)
                            return $err
                        }
                    }
    
                }
                Write-Host "Getting error details - retries remaining: $index"
                Start-sleep -Seconds 5
            }
        }
    }
    return $err
}



# Deploy a Cloud Access connector over a current deployment
function New-ConnectionServiceDeployment() {
    param(
        $RGName,
        $subscriptionId,
        $tenantId,
        $spCredential,
        $keyVault,
        $testDeployment,
        $enableExternalAccess,
        $enableRadiusMfa,
        $radiusServerHost,
        $radiusServerPort,
        $radiusSharedSecret,
        $vnetConfig,
        $camSaasUri,
        $verifyCAMSaaSCertificate,
        $ownerTenantId,
        $ownerUpn,
        [switch]$updateSPCredential,
        [bool]$brokerRetrieveAgentState,
        [bool]$clientShowAgentState,
        $brokerCacheTimeoutSeconds,
        $brokerCacheSize,
        [bool]$isBrokerCacheEnabled,
        [HashTable]$tag
    )

    $kvID = $keyVault.ResourceId
    $kvName = $keyVault.Name

    # First, let's find the Service Principal 
    $adminAzureContext = Get-AzureRMContext
    
    $client = $null
    $key = $null

    # put everything in a try block so that if any errors occur we revert to $azureAdminContext
    try {
        if ($spCredential) {
            # function was passed SPcredential
            $client = $spCredential.UserName
            $key = $spCredential.GetNetworkCredential().Password
        }
        else {
            try {
                $secret = Get-AzureKeyVaultSecret `
                    -VaultName $kvName `
                    -Name "AzureSPClientID" `
                    -ErrorAction stop
                if($secret.SecretValueText) {
                    $client = $secret.SecretValueText
                } else {
                    $client = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
                }
            }
            catch {
                $err = $_
                if ($err.Exception.Message -eq "Access denied") {
                    Write-Host "Cannot access Key Vault secret, attempting to set access policy for vault $kvName for user $($adminAzureContext.Account.Id)"
                    try {
                        Set-AzureRmKeyVaultAccessPolicy `
                            -VaultName $kvName `
                            -UserPrincipalName $adminAzureContext.Account.Id `
                            -PermissionsToSecrets Get, Set, List `
                            -ErrorAction stop | Out-Null

                        $secret = Get-AzureKeyVaultSecret `
                            -VaultName $kvName `
                            -Name "AzureSPClientID" `
                            -ErrorAction stop
                        if($secret.SecretValueText) {
                            $client = $secret.SecretValueText
                        } else {
                            $client = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
                        }
                    }
                    catch {
                        Write-Host "`nFailed to set access policy for vault $kvName for user $($adminAzureContext.Account.Id)"
                        Write-Host "Please use the Azure Portal to provide the current logged-in account with get, list, and set access"
                        Write-Host "to the secrets in $kvName"
                        exit # <--- early exit!
                    }
                }
                else {
                    throw $err
                }
            }

            # Get the password (key)
            # Let's update the AzureSPKey in KeyVault if the Service Principal credential has been updated
            if ($updateSPCredential) {
                $spNewCredential = Get-Credential -Message "Please update Service Principal credential" -UserName $client
                $key = $spNewCredential.GetNetworkCredential().Password
                
                $spUpdatedSuccessfully = Update-CAMUserCredential `
                    -client $client `
                    -key $key `
                    -tenant $tenantId `
                    -ownerTenant $ownerTenantId `
                    -ownerUpn $ownerUpn `
                    -camSaasBaseUri $camSaasUri `
                    -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate

                if ( $spUpdatedSuccessfully ) {
                    Set-KVSecret -kvName $kvName -secretName "AzureSPKey" -secretValue $spNewCredential.Password
                }
                
            }
            else {
                $secret = Get-KVSecret -kvName $kvName -secretName "AzureSPKey"
                if($secret.SecretValueText) {
                    $key = $secret.SecretValueText
                } else {
                    $key = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
                }
            }
        }

        $spCreds = New-Object PSCredential $client, (ConvertTo-SecureString $key -AsPlainText -Force)

        try {
            Add-AzureRmAccount `
                -Credential $spCreds `
                -ServicePrincipal `
                -TenantId $tenantId `
                -ErrorAction Stop
        } 
        catch {
            Write-Host "`nPlease first make sure that the Service Principal password has not expired (If so, please add a new key through the Azure Portal)"
            Write-Host "then restart the deployment by passing the updateSPCredential switch"
            exit # <--- early exit!
        }

        Write-Host "Using service principal $client in tenant $tenantId and subscription $subscriptionId"
        
        # Generate ID's from all the name information
        $vnetName = $vnetConfig.vnetID.split("/")[-1]
        $vnetRgName = $vnetConfig.vnetID.split("/")[4]
        $vnetConfig.CSSubnetID = $vnetConfig.vnetID + "/subnets/$($vnetConfig.CSSubnetName)"
        $vnetConfig.GWSubnetID = $vnetConfig.vnetID + "/subnets/$($vnetConfig.GWSubnetName)"

        # Find a connector resource group name that can be used.
        # An incrementing count is used to find a free resource group. This count is the
        # identifier, even if old connectors have been deleted.
        $csRGName = $null
        while(-not $csRGName)
        {
            # Note this doesn't return the same type of context as for a standard account
            # so we'll just keep logging in when needed rather than switching context.
            Add-AzureRmAccount `
                -Credential $spCreds `
                -ServicePrincipal `
                -TenantId $tenantId `
                -ErrorAction Stop | Out-Null
            
            $secret = Get-AzureKeyVaultSecret `
                -VaultName $kvName `
                -Name "connectionServiceNumber" `
                -ErrorAction stop

            if ($secret -eq $null) {
                $connectionServiceNumber = 1
            }
            else {
                # increment connectionServiceNumber
                if($secret.SecretValueText) {
                    $connNumber = $secret.SecretValueText
                } else {
                    $connNumber = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
                }
                $connectionServiceNumber = [int]$connNumber + 1
            }

            $secretValue = (ConvertTo-SecureString $connectionServiceNumber -AsPlainText -Force)
            Set-KVSecret -kvName $kvName -secretName "connectionServiceNumber" -secretValue $secretValue

            Write-Host "Checking available resource group for connector number $connectionServiceNumber"

            $csRGName = $RGName + "-CN" + $connectionServiceNumber
            Set-AzureRMContext -Context $adminAzureContext | Out-Null
            $rg = Get-AzureRmResourceGroup -ResourceGroupName $csRGName -ErrorAction SilentlyContinue

            if($rg)
            {
                # Check if Resource Group is empty
                $Resources = Get-AzureRmResource -ResourceGroupName $csRGName -ErrorAction SilentlyContinue

                if( -not $Resources.Length -eq 0)
                {
                    # found the resource group was not empty - do the loop with an incremented number try to find a free name
                    $csRGName = $null
                }
            }
        }
        
        Set-AzureRMContext -Context $adminAzureContext | Out-Null


        # Create connector Resource Group if it doesn't exist, in the location of the target vnet
        if (-not ((Get-AzureRmResourceGroup) | Where-Object ResourceGroupName -eq $csRGName) ) {
            $vnet = Get-AzureRmVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRgName
            $location = $vnet.Location

            Write-Host "Creating resource group $csRGName in location $location"

            New-AzureRmResourceGroup -Name $csRGName -Location $location -ErrorAction stop -Tag $tag | Out-Null
        }

        $csRG = Get-AzureRmResourceGroup -Name $csRGName

        # Get-AzureRmRoleAssignment responds much more rationally if given a scope with an ID
        # than a resource group name.
        $spRoles = Get-AzureRmRoleAssignment -ServicePrincipalName $client -Scope $csRG.ResourceId

        # filter on an exact resource group ID match as Get-AzureRmRoleAssignment seems to do a more loose pattern match
        $spRoles = $spRoles | Where-Object `
            {($_.Scope -eq $csRG.ResourceId) -or ($_.Scope -eq "/subscriptions/$subscriptionId")}

        $camCustomRoleDefinition = Get-CAMRoleDefinition -subscriptionID $subscriptionID
                    
        # spRoles could be no object, a single object or an array. foreach works with all.
        $hasAccess = $false
        foreach($role in $spRoles) {
            $roleName = $role.RoleDefinitionName
            if (($roleName -eq "Contributor") -or ($roleName -eq "Owner") -or ($roleName -eq $camCustomRoleDefinition.Name)) {
                Write-Host "$client already has $roleName for $csRGName"
                $hasAccess = $true
                break
            }
        }

        if(-not $hasAccess) {
            Write-Host "Giving $client '$($camCustomRoleDefinition.Name)' access to $csRGName"
            Set-AzureRMContext -Context $adminAzureContext | Out-Null
            New-AzureRmRoleAssignment `
                -RoleDefinitionName $camCustomRoleDefinition.Name `
                -ResourceGroupName $csRGName `
                -ServicePrincipalName $client `
                -ErrorAction Stop | Out-Null
        }
    
        # Add Scope to vNet if vNet already exists and scope does not already exist
        Add-SPScopeToVnet `
            -vnetName $vnetName `
            -vnetID $vnetConfig.vnetID `
            -client $client `
            -subscriptionID $subscriptionID `
            -camCustomRoleDefinition $camCustomRoleDefinition

        # SP has proper rights - do deployment with SP
        Write-Host "Using service principal $client in tenant $tenantId and subscription $subscriptionId"
        Add-AzureRmAccount `
            -Credential $spCreds `
            -ServicePrincipal `
            -TenantId $tenantId `
            -ErrorAction Stop | Out-Null

        Set-RadiusSettings `
            -VaultName $kvName `
            -enableExternalAccess $enableExternalAccess `
            -enableRadiusMfa $enableRadiusMfa `
            -radiusServerHost $radiusServerHost `
            -radiusServerPort $radiusServerPort `
            -radiusSharedSecret $radiusSharedSecret

        # make temporary directory for intermediate files
        $folderName = -join ((97..122) | Get-Random -Count 18 | ForEach-Object {[char]$_})
        $tempDir = Join-Path $env:TEMP $folderName
        Write-Host "Using temporary directory $tempDir for intermediate files"
        if (-not (Test-Path $tempDir)) {
            New-Item $tempDir -type directory | Out-Null
        }

        Update-CAMSumoCreds `
            -SubscriptionId $subscriptionID `
            -client $client `
            -key $key `
            -tenant $tenantId `
            -camSaasBaseUri $camSaasUri `
            -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate `
            -RootRGName $RGName `
            -tempDir $tempDir

        # Refresh the CAMDeploymentInfo structure
        New-CAMDeploymentInfo `
            -kvName $CAMRootKeyvault.Name

        # Get the template URI
        $secret = Get-KVSecret -kvName $kvName -secretName "artifactsLocation"
        if($secret.SecretValueText) {
            $artifactsLocation = $secret.SecretValueText
        } else {
            $artifactsLocation = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
        }
        $CSDeploymentTemplateURI = $artifactsLocation + "/connection-service/azuredeploy.json"

        # Get the RegistrationCode
        $secret = Get-KVSecret -kvName $kvName -secretName "cloudAccessRegistrationCode"
        if($secret.SecretValueText) {
            $licenseInstanceIdSecret = $secret.SecretValueText
        } else {
            $licenseInstanceIdSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
        }

        # Get license instance Id from registration code
        $licenseInstanceId = $licenseInstanceIdSecret.Split('@')[0]

        #Convert tags to JSON string
        $tagString = $tag | ConvertTo-Json -Compress

        $generatedDeploymentParameters = @"
        {
            "`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "enableExternalAccess": {
                    "value": "$($enableExternalAccess.ToString())"
                  },
                  "CSUniqueSuffix": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "connectionServiceNumber"
                    }
                },
                "domainServiceAccountUsername": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "domainServiceAccountUsername"
                    }
                },
                "domainServiceAccountPassword": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "domainServiceAccountPassword"
                    }
                },
                "domainName": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "domainName"
                    }
                },
                "LocalAdminUsername": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "connectionServiceLocalAdminUsername"
                    }
                },
                "LocalAdminPassword": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "connectionServiceLocalAdminPassword"
                    }
                },
                "CSsubnetId": {
                    "value": "$($vnetConfig.CSSubnetID)"
                },
                "GWsubnetId": {
                    "value": "$($vnetConfig.GWsubnetId)"
                },
                "binaryLocation": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "binaryLocation"
                    }
                },
                "certData": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "CAMCSCertificate"
                    }
                },
                "certPassword": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "CAMCSCertificatePassword"
                    }
                },
                "remoteWorkstationDomainGroup": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "remoteWorkstationDomainGroup"
                    }
                },
                "CAMDeploymentInfo": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "CAMDeploymentInfo"
                    }
                },
                "enableRadiusMfa": {
                    "reference": {
                        "keyVault": {
                        "id": "$kvId"
                        },
                        "secretName": "enableRadiusMfa"
                    }
                },
                "licenseInstanceId": {
                    "value": "$licenseInstanceId"
                },
                "brokerRetrieveAgentState": {
                    "value": $($brokerRetrieveAgentState | ConvertTo-Json)
                },
                "clientShowAgentState": {
                    "value": $($clientShowAgentState | ConvertTo-Json)
                },                
                "_baseArtifactsLocation": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvID"
                        },
                        "secretName": "artifactsLocation"
                    }
                },
                "brokerCacheTimeoutSeconds": {
                    "value": $brokerCacheTimeoutSeconds
                },
                "brokerCacheSize": {
                    "value": $brokerCacheSize
                },
                "isBrokerCacheEnabled": {
                    "value": $($isBrokerCacheEnabled | ConvertTo-Json)
                },
                "tag": {
                    "value": $tagString
                },
                "userStorageAccountUri": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvId"
                        },
                        "secretName": "userStorageAccountUri"
                    }
                },
                "userStorageAccountSasToken": {
                    "reference": {
                        "keyVault": {
                            "id": "$kvId"
                        },
                        "secretName": "userStorageAccountSasToken"
                    }
                }
            }
        }
"@

        $outputParametersFileName = "csdeploymentparameters.json"
        $outputParametersFilePath = Join-Path $tempDir $outputParametersFileName
        Set-Content $outputParametersFilePath  $generatedDeploymentParameters

        Write-Host "`nDeploying Cloud Access connector, this process can take up to 60 minutes"
        Write-Host "Please feel free to watch here for early errors for a few minutes and then go do something else, or go for coffee!"
        Write-Host "If this script is running in Azure Cloud Shell then you may let the shell timeout and the deployment will continue"
        Write-Host "Please watch the resource group $csRGName in the Azure Portal for current status, the Connection Service deployment is"
        Write-Host "complete when all deployments are showing as 'Succeeded'"
        Write-Host "Error information is also available through the deployments area of the resource group pane"

        if ($testDeployment) {
            # just do a test if $true
            Test-AzureRmResourceGroupDeployment `
                -ResourceGroupName $csRGName `
                -TemplateFile $CSDeploymentTemplateURI `
                -TemplateParameterFile $outputParametersFilePath `
                -Verbose
        }
        else {
            $maxRetries = 30
            for($idx = 0;$idx -lt $maxRetries;$idx++)
            {
                try {
                    $deploymentName = "CS$connectionServiceNumber-$idx"
                    New-AzureRmResourceGroupDeployment `
                        -DeploymentName $deploymentName `
                        -ResourceGroupName $csRGName `
                        -TemplateUri $CSDeploymentTemplateURI `
                        -TemplateParameterFile $outputParametersFilePath `
                        -ErrorAction stop `
                        -WarningAction Ignore
                    # success!
                    break
                }
                catch {
                    # Seems there can be a race condition on the role assignment of the service principal with
                    # the resource group before getting here - setting a retry loop
                    if ($idx -eq ($maxRetries - 1))
                    {
                        # last try - just throw
                        throw
                    }
                    if ($_.Exception.Message -like "*does not have authorization*")
                    {
                        $remaining = $maxRetries - $idx - 1
                        Write-Host "Authorization error, usually this means we are waiting for the authorization to percolate through Azure"
                        Write-Host "This error can take a long time to clear especially if there is another deployment"
                        Write-Host "happening concurrently using the same service principal account"
                        Write-Host "Reason: $($_.Exception.Message)"

                        # Try to stop the deployment in case that helps, but don't warn or fail.
                        Stop-AzureRmResourceGroupDeployment `
                            -Name $deploymentName `
                            -ResourceGroupName $csRGName `
                            -ErrorAction SilentlyContinue | Out-Null

                        Write-Host-Warning "Retrying deployment - retries remaining: $remaining"
                        Start-sleep -Seconds 10
                    }
                    else {
                        throw
                    }
                }
            }
        }
    }
    catch {
        # Check if there's an Azure log message we can show, otherwise just re-throw
        $err = $_
        $errorToThrow = Append-AzureRMLog -err $err

        throw $errorToThrow
    }
    finally {
        if ($adminAzureContext) {
            Set-AzureRMContext -Context $adminAzureContext | Out-Null
        }
    }
}

# Creates a CAM Deployment Root including keyvault, user data storage account
# and populates parameters.
# Returns key vault info.
function New-CAMDeploymentRoot()
{
    param(
        $RGName,
        $rwRGName,
        $spInfo,
        $azureContext,
        $CAMConfig,
        $tempDir,
        $certificateFile,
        $certificateFilePassword,
        $camSaasUri,
        $verifyCAMSaaSCertificate,
        $subscriptionID,
        $ownerTenantId,
        $ownerUpn,
        [HashTable]
        $tag
    )

    $rg = Get-AzureRmResourceGroup -ResourceGroupName $RGName
    $client = $spInfo.spCreds.UserName
    $key = $spInfo.spCreds.GetNetworkCredential().Password
    $tenant = $spInfo.tenantId
    $ownerTenant = $ownerTenantId
    $registrationCode = $CAMConfig.parameters.cloudAccessRegistrationCode.value
    $artifactsLocation = $CAMConfig.parameters.artifactsLocation.clearValue
    $binaryLocation = $CAMConfig.parameters.binaryLocation.clearValue
    
    $kvInfo = New-CAM-KeyVault `
        -RGName $RGName `
        -spName $spInfo.spCreds.UserName `
        -adminAzureContext $azureContext `
        -Tag $tag

    Generate-Certificate-And-Passwords `
        -kvName $kvInfo.VaultName `
        -CAMConfig $CAMConfig `
        -tempDir $tempDir `
        -certificateFile $certificateFile `
        -certificateFilePassword $certificateFilePassword | Out-Null
   
    $userDataStorageAccount = New-UserStorageAccount `
        -RGName $RGName `
        -Location $rg.Location `
        -Tag $tag

    Populate-UserBlob `
        -CAMConfig $CAMConfig `
        -artifactsLocation $artifactsLocation `
        -userDataStorageAccount $userDataStorageAccount `
        -binaryLocation $binaryLocation `
        -RGName $RGName `
        -kvInfo $kvInfo `
        -tempDir $tempDir `
        -tag $tag | Out-Null

    Write-Host "Registering Cloud Access Manager Deployment to Cloud Access Manager Service"
    $deploymentId = Register-CAM `
        -SubscriptionId $subscriptionID `
        -client $client `
        -key $key `
        -tenant $tenant `
        -ownerTenant $ownerTenant `
        -ownerUpn $ownerUpn `
        -RGName $rwRGName `
        -registrationCode $registrationCode `
        -camSaasBaseUri $camSaasUri `
        -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate
    
    Update-CAMSumoCreds `
        -SubscriptionId $subscriptionID `
        -client $client `
        -key $key `
        -tenant $tenant `
        -camSaasBaseUri $camSaasUri `
        -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate `
        -RootRGName $RGName `
        -tempDir $tempDir 


    Generate-CamDeploymentInfoParameters `
        -spInfo $spInfo `
        -camSaasUri $camSaasUri `
        -deploymentId $deploymentId `
        -subscriptionID $subscriptionID `
        -RGName $rwRGName `
        -kvName $kvInfo.VaultName | Out-Null

    Add-SecretsToKeyVault `
        -kvName $kvInfo.VaultName `
        -CAMConfig $CAMConfig | Out-Null

    return $kvInfo
}

# Provide the SP $client with camCustomRoleDefinition rights to the vnet, if needed
function Add-SPScopeToVnet()
{
    param(
        [parameter(Mandatory = $true)] 
        $vnetName,
        [parameter(Mandatory = $true)] 
        $vnetID,
        [parameter(Mandatory = $true)] 
        $client,
        [parameter(Mandatory = $true)] 
        $subscriptionId,
        [parameter(Mandatory = $true)] 
        $camCustomRoleDefinition
    )

    $vnetRGName = $vnetID.Split("/")[4]


    if( Get-AzureRmResource `
        -Name $vnetName `
        -ResourceType "Microsoft.Network/virtualNetworks" `
        -ResourceGroupName $vnetRGName `
        -ErrorAction SilentlyContinue
        )
    {
        # Get-AzureRmRoleAssignment responds much more rationally if given a scope with an ID
        # than a resource group name.
        $spRoles = Get-AzureRmRoleAssignment -ServicePrincipalName $client -Scope $vnetID
    
        $vmRG = Get-AzureRmResourceGroup -Name $vnetRGName

        # filter on an exact resource group ID match as Get-AzureRmRoleAssignment seems to do a more loose pattern match
        $spRoles = $spRoles | Where-Object `
            {   ($_.Scope -eq $vmRG.ResourceId) `
            -or ($_.Scope -eq $vnetID) `
            -or ($_.Scope -eq "/subscriptions/$subscriptionId")}
        
        # spRoles could be no object, a single object or an array. foreach works with all.
        $hasAccess = $false
        foreach($role in $spRoles) {
            $roleName = $role.RoleDefinitionName
            if (($roleName -eq "Contributor") -or ($roleName -eq "Owner") -or ($roleName -eq $camCustomRoleDefinition.Name)) {
                Write-Host "$client already has $roleName for $vnetName"
                $hasAccess = $true
                break
            }
        }
    
        if(-not $hasAccess) {
            Write-Host "Giving $client '$($camCustomRoleDefinition.Name)' access to $vnetName"
            New-AzureRmRoleAssignment `
                -RoleDefinitionName $camCustomRoleDefinition.Name `
                -Scope $vnetID `
                -ServicePrincipalName $client `
                -ErrorAction Stop | Out-Null
        }
    }
}


# Deploy a full CAM deployment with root networking and DC, a connection service
# and a convenience 'first' Windows standard agent machine 
function Deploy-CAM() {
    param(
        [parameter(Mandatory = $false)] 
        [bool]
        $verifyCAMSaaSCertificate = $true,

        [parameter(Mandatory = $true)]
        [bool]
        $enableExternalAccess,

        [parameter(Mandatory = $true)] 
        $CAMDeploymentTemplateURI,

        [parameter(Mandatory = $true)] 
        [System.Management.Automation.PSCredential]
        $domainAdminCredential,

        [parameter(Mandatory = $true)] 
        $domainName,

        [parameter(Mandatory = $true)] 
        [SecureString]
        $registrationCode,

        [parameter(Mandatory = $true)] 
        $camSaasUri,

        [parameter(Mandatory = $true)] 
        $binaryLocation,

        [parameter(Mandatory = $true)] 
        $outputParametersFileName,

        [parameter(Mandatory = $true)] 
        $subscriptionId,

        [parameter(Mandatory = $true)]
        $RGName,

        [parameter(Mandatory = $true)]
        $csRGName,

        [parameter(Mandatory = $true)]
        $rwRGName,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $spCredential,

        [parameter(Mandatory = $false)] # required if $spCredential is provided
        [string]
        $tenantId,

        [parameter(Mandatory = $false)]
        [String]
        $certificateFile = $null,
    
        [parameter(Mandatory = $false)]
        [SecureString]
        $certificateFilePassword = $null,

        [parameter(Mandatory=$false)]
        [ValidateSet("stable","beta","dev")] 
        [String]
        $AgentChannel = "stable",

        [parameter(Mandatory = $false)]
        [bool]
        $testDeployment = $false,

        [parameter(Mandatory = $false)]
        $deployOverDC,

        [parameter(Mandatory = $true)]
        $vnetConfig,

        [parameter(Mandatory=$true)]
        $radiusConfig,
        
        [parameter(Mandatory = $true)]
        $ownerTenantId,

        [parameter(Mandatory = $true)]
        $ownerUpn,
        
        [parameter(Mandatory=$false)]
        [ValidateSet("Windows Server 2016","Windows Server 2012R2")] 
        [String]
        $domainControllerOsType = "Windows Server 2016",

        [parameter(Mandatory=$false)]
        [ValidateRange(10,10000)]
        [int]
        $defaultIdleShutdownTime = 240,

        [parameter(Mandatory=$false)]
        [String]
        $camUserGroup,
        
        [parameter(Mandatory=$false)]
        $camManagementUserGroup = $null,

        [parameter(Mandatory=$false)]
        $AzureSPObjectId=$null,
        [bool]$brokerRetrieveAgentState,
        [bool]$clientShowAgentState,

        [parameter(Mandatory = $false)]
        [bool]
        $isBrokerCacheEnabled = $false,
    
        [parameter(Mandatory = $false)]
        [int]
        $brokerCacheSize,
    
        [parameter(Mandatory = $false)]
        [int]
        $brokerCacheTimeoutSeconds,

        [Hashtable]$tag
    )

    # Artifacts location 'folder' is where the template is stored
    $artifactsLocation = $CAMDeploymentTemplateURI.Substring(0, $CAMDeploymentTemplateURI.lastIndexOf('/'))

    $domainServiceAccountUsername = $domainAdminCredential.UserName

    # Setup CAMConfig as a hash table of ARM parameters for Azure (KeyVault)
    # Most parameters are secrets so the KeyVault can be a single configuration source
    # the parameter name is the KeyVault secret name
    # and internal parameters for this script which are not pushed to the key vault
    $CAMConfig = @{} 
    $CAMConfig.parameters = @{}
    if ($camUserGroup -and $camUserGroup.Trim()) {
        $camUserGroup = $camUserGroup.Trim()
        $CAMConfig.parameters.CAMUserGroupName = @{
            value      = (ConvertTo-SecureString $camUserGroup -AsPlainText -Force)
            clearValue = $camUserGroup
        }
    }
    $CAMConfig.parameters.domainServiceAccountUsername = @{
        value      = (ConvertTo-SecureString $domainServiceAccountUsername -AsPlainText -Force)
        clearValue = $domainServiceAccountUsername
    }
    $CAMConfig.parameters.domainName = @{
        value      = (ConvertTo-SecureString $domainName -AsPlainText -Force)
        clearValue = $domainName
    }
    $CAMConfig.parameters.camManagementUserGroup = @{
        value = (ConvertTo-SecureString $camManagementUserGroup -AsPlainText -Force)
    }
    $CAMConfig.parameters.binaryLocation = @{
        value      = (ConvertTo-SecureString $binaryLocation -AsPlainText -Force)
        clearValue = $binaryLocation
    }
    $CAMConfig.parameters.artifactsLocation = @{
        value      = (ConvertTo-SecureString $artifactsLocation -AsPlainText -Force)
        clearValue = $artifactsLocation
    }

    $CAMConfig.parameters.enableAddUser = @{
        value      = if($deployOverDC) {
            ConvertTo-SecureString "FALSE" -AsPlainText -Force
        } else {
            ConvertTo-SecureString "TRUE" -AsPlainText -Force
        }
    }

    $CAMConfig.parameters.cloudAccessRegistrationCode = @{value = $registrationCode}

    $CAMConfig.parameters.domainServiceAccountPassword = @{value = $domainAdminCredential.Password}

    # Set in Generate-Certificate-And-Passwords
    $CAMConfig.parameters.CAMCSCertificate = @{}
    $CAMConfig.parameters.CAMCSCertificatePassword = @{}
    $CAMConfig.parameters.remoteWorkstationLocalAdminPassword = @{}
    $CAMConfig.parameters.remoteWorkstationLocalAdminUsername = @{
        value      = (ConvertTo-SecureString "localadmin" -AsPlainText -Force)
        clearValue = "localadmin"
    }
    $CAMConfig.parameters.connectionServiceLocalAdminPassword = @{}
    $CAMConfig.parameters.connectionServiceLocalAdminUsername = @{
        value      = (ConvertTo-SecureString "localadmin" -AsPlainText -Force)
        clearValue = "localadmin"
    }

    $CAMConfig.parameters.remoteWorkstationDomainGroup = @{
        value      = (ConvertTo-SecureString "Remote Workstations" -AsPlainText -Force)
        clearValue = "Remote Workstations"
    }

    # Set in Populate-UserBlob
    $CAMConfig.parameters.userStorageAccountSasToken = @{}
    $CAMConfig.parameters.userStorageAccountUri = @{}
    $CAMConfig.parameters.userStorageName = @{}
    $CAMConfig.parameters.userStorageAccountKey = @{}

    # Populated in Generate-CamDeploymentInfoParameters
    $CAMConfig.parameters.AzureSPClientID = @{}
    $CAMConfig.parameters.AzureSPKey = @{}
    $CAMConfig.parameters.AzureSPTenantID = @{}
    $CAMConfig.parameters.AzureSPObjectId = @{}
    $CAMConfig.parameters.CAMServiceURI = @{}
    $CAMConfig.parameters.CAMDeploymentID = @{}
    $CAMConfig.parameters.AzureSubscriptionID = @{}
    $CAMConfig.parameters.AzureResourceGroupName = @{}
    $CAMConfig.parameters.AzureKeyVaultName = @{}

    $CAMConfig.internal = @{}
    $CAMConfig.internal.location = (Get-AzureRmResourceGroup -ResourceGroupName $rwRGName -ErrorAction stop).location
    $CAMConfig.internal.vnetID = $vnetConfig.vnetID
    $CAMConfig.internal.vnetName = $CAMConfig.internal.vnetID.split("/")[-1]
    $CAMConfig.internal.rootSubnetName = "CAMRoot"
    $CAMConfig.internal.RWSubnetName = $vnetConfig.RWSubnetName
    $CAMConfig.internal.CSSubnetName = $vnetConfig.CSSubnetName
    $CAMConfig.internal.GWSubnetName = $vnetConfig.GWSubnetName

    $CAMConfig.internal.RWSubnetID = $CAMConfig.internal.vnetID + "/subnets/$($CAMConfig.internal.RWSubnetName)"
    $CAMConfig.internal.CSSubnetID = $CAMConfig.internal.vnetID + "/subnets/$($CAMConfig.internal.CSSubnetName)"
    $CAMConfig.internal.GWSubnetID = $CAMConfig.internal.vnetID + "/subnets/$($CAMConfig.internal.GWSubnetName)"

    $CAMConfig.parameters.remoteWorkstationSubnet = @{
        value      = (ConvertTo-SecureString $CAMConfig.internal.RWSubnetID -AsPlainText -Force)
        clearValue = $CAMConfig.internal.RWSubnetID
    }

    $CAMConfig.parameters.connectionServiceSubnet = @{
        value      = (ConvertTo-SecureString $CAMConfig.internal.CSSubnetID -AsPlainText -Force)
        clearValue = $CAMConfig.internal.CSSubnetID
    }

    $CAMConfig.parameters.gatewaySubnet = @{
        value      = (ConvertTo-SecureString $CAMConfig.internal.GWSubnetID -AsPlainText -Force)
        clearValue = $CAMConfig.internal.GWSubnetID
    }

    $CAMConfig.internal.agentChannel = $AgentChannel

    $CAMConfig.internal.standardVMSize = "Standard_D2_v3"
    $CAMConfig.internal.graphicsVMSize = "Standard_NV6"
    $CAMConfig.internal.agentARM = "server2016-standard-agent.json"
    $CAMConfig.internal.gaAgentARM = "server2016-graphics-agent.json"
    $CAMConfig.internal.linuxAgentARM = "rhel-standard-agent.json"
    $CAMConfig.internal.gaLinuxAgentARM = "rhel-graphics-agent.json"

    # RADIUS MFA Configuration Parameters
    $CAMConfig.parameters.enableRadiusMfa = @{
        value=(ConvertTo-SecureString $radiusConfig.enableRadiusMfa -AsPlainText -Force)
    }
    $CAMConfig.parameters.radiusServerHost = @{
        value=(ConvertTo-SecureString $radiusConfig.radiusServerHost -AsPlainText -Force)
    }
    $CAMConfig.parameters.radiusServerPort = @{
       value=(ConvertTo-SecureString $radiusConfig.radiusServerPort -AsPlainText -Force)
     
    }
    $CAMConfig.parameters.radiusSharedSecret = @{
        value=$radiusConfig.radiusSharedSecret
    }

    # make temporary directory for intermediate files
    $folderName = -join ((97..122) | Get-Random -Count 18 | ForEach-Object {[char]$_})
    $tempDir = Join-Path $env:TEMP $folderName
    Write-Host "Using temporary directory $tempDir for intermediate files"
    if (-not (Test-Path $tempDir)) {
        New-Item $tempDir -type directory | Out-Null
    }

    # if the current context tenantId does not match the desired tenantId then we can't make service principal's
    $currentContext = Get-AzureRmContext
    $currentContextTenant = $currentContext.Tenant.Id 
    $tenantIDsMatch = ($currentContextTenant -eq $tenantId)

    if (-not $tenantIDsMatch) {
        Write-Host "The Current Azure context is for a different tenant ($currentContextTenant) that"
        Write-Host "does not match the tenant of the deployment ($tenantId)"
        Write-Host "This can happen in Azure Cloud Powershell when an account has access to multiple tenants"
        if (-not $spCredential) {
            Write-Host "Please make a service principal through the Azure Portal or other means and provide here"
        }
        else {
            Write-Host "Thank you for providing service principal credentials"
        }
        Write-Host "Note - the service principal must already have Contributor rights to the subscription or target"
        Write-Host "resource groups because role assignment is not possible in this case"
    }

    $spInfo = $null
    if (-not $spCredential) {
        # if there's no service principal provided through the command line or elsewhere then we need to make one if we can or ask for one if
        # we're in the wrong tenant (which shouldn't happen...)

        if (-not $tenantIDsMatch) {
            # manually get credential
            $spCredential = Get-Credential -Message "Enter service principal credential"

            $spInfo = @{}
            $spinfo.spCreds = $spCredential
            $spInfo.tenantId = $tenantId
            $spInfo.objectId = (Get-AzureRmADApplication -ApplicationId $spCredential.UserName).ObjectId
        }
        else {
            # generate service principal
            $spInfo = New-CAMAppSP `
                -RGName $RGName
        }
    }
    else {
        # service principal credential provided in parameter list
        if ($tenantId -eq $null) {throw "Service principal provided but no tenantId"}
        if ($AzureSPObjectId -eq $null) {throw "Service principal providede but no ObjectId. Please run '(Get-AzureRmADApplication -ApplicationId " + $spCredential.UserName + ").ObjectId' and provide the output with the '-AzureSPObjectId' switch."}
        $spInfo = @{}
        $spinfo.spCreds = $spCredential
        $spInfo.tenantId = $tenantId
        $spInfo.objectId = $AzureSPObjectId
    }

    $client = $spInfo.spCreds.UserName
    $tenant = $spInfo.tenantId

    Write-Host "Using service principal $client in tenant $tenant and subscription $subscriptionId"

    if($tenantIDsMatch) {
        # Service principal info exists but needs to get rights to the required resource groups
        Write-Host "Adding role assignments for the service principal account"

        $camCustomRoleDefinition = Get-CAMRoleDefinition -subscriptionID $subscriptionID
        
        # Retry required since it can take a few seconds for app registration to percolate through Azure.
        # (Online recommendation was sleep 15 seconds - this is both faster and more conservative)
        $rollAssignmentRetry = 120
        while ($rollAssignmentRetry -ne 0) {
            $rollAssignmentRetry--

            try {
                # Only assign camCustomRoleDefinition access if needed
                $rgNames = @($RGName, $csRGName, $rwRGName)
                ForEach ($rgn in $rgNames) {
                    $rg = Get-AzureRmResourceGroup -Name $rgn

                    # Get-AzureRmRoleAssignment responds much more rationally if given a scope with an ID
                    # than a resource group name.
                    $spRoles = Get-AzureRmRoleAssignment -ServicePrincipalName $client -Scope $rg.ResourceId

                    # filter on an exact resource group ID match as Get-AzureRmRoleAssignment seems to do a more loose pattern match
                    $spRoles = $spRoles | Where-Object `
                        {($_.Scope -eq $rg.ResourceId) -or ($_.Scope -eq "/subscriptions/$subscriptionID")}
                    
                    # spRoles could be no object, a single object or an array. foreach works with all.
                    $hasAccess = $false
                    foreach($role in $spRoles) {
                        $roleName = $role.RoleDefinitionName
                        if (($roleName -eq "Contributor") -or ($roleName -eq "Owner") -or ($roleName -eq $camCustomRoleDefinition.Name)) {
                            Write-Host "$client already has $roleName for $rgn"
                            $hasAccess = $true
                            break
                        }
                    }

                    if(-not $hasAccess) {
                        Write-Host "Giving $client '$($camCustomRoleDefinition.Name)' access to $rgn"
                        New-AzureRmRoleAssignment `
                            -RoleDefinitionName $camCustomRoleDefinition.Name `
                            -ResourceGroupName $rgn `
                            -ServicePrincipalName $client `
                            -ErrorAction Stop | Out-Null
                    }
                }
            
                # Add Scope to vNet if vNet already exists and scope does not already exist
                Add-SPScopeToVnet `
                    -vnetName $CAMConfig.internal.vnetName `
                    -vnetID $CAMConfig.internal.vnetID `
                    -client $client `
                    -subscriptionId $subscriptionId `
                    -camCustomRoleDefinition $camCustomRoleDefinition

                break # while loop
            } catch {
                #TODO: we should only be catching the 'Service principal or app not found' error
                Write-Host "Waiting for service principal - retries remaining: $rollAssignmentRetry"
                Start-sleep -Seconds 1
                if ($rollAssignmentRetry -eq 0) {
                    #re-throw whatever the original exception was
                    $exceptionContext = Get-AzureRmContext
                    $exceptionSubscriptionId = $exceptionContext.Subscription.Id
                    Write-Error "Failure to create Contributor role for $client in subscription: $exceptionSubscriptionId, please check your subscription permissions"
                    throw
                }
            }
        }
    }

    # Login with service principal since some Powershell contexts (with token auth - like Azure Cloud PowerShell or Visual Studio)
    # can't do operations on keyvaults
    
    # cache the current context and sign in as service principal
    $azureContext = Get-AzureRMContext
    $retryCount = 60
    for ($idx = ($retryCount - 1); $idx -ge 0; $idx--) {
        try {
            Add-AzureRmAccount `
                -Credential $spInfo.spCreds `
                -ServicePrincipal `
                -TenantId $spInfo.tenantId `
                -ErrorAction Stop | Out-Null
            break
        }
        catch {
            $caughtError = $_
            if ($azureContext) {
                Write-Host "Reverting to initial Azure context for $($azureContext.Account.Id)"
                Set-AzureRMContext -Context $azureContext | Out-Null
            }
            # if it's the unknown user (so potentially a timing issue where the account hasn't percolated
            # through the system yet) retry. Otherwise abort and re-throw
            if (     ($caughtError.Exception -is [Microsoft.IdentityModel.Clients.ActiveDirectory.AdalException]) `
                -and ($caughtError.Exception.ServiceErrorCodes[0] -eq 70001) `
                -and ($idx -gt 0))
            {
                Write-Host "Could not find application ID for tenant - retries remaining: $idx"
                continue
            }
            else {
                Write-Host "`nPlease make sure that the Service Principal password has not been expired (If so, please add a new key through the Azure Portal)"
                throw $caughtError
            }
        }
    }

    try {    
        $kvInfo = New-CAMDeploymentRoot `
            -RGName $RGName `
            -rwRGName $rwRGName `
            -spInfo $spInfo `
            -azureContext $azureContext `
            -CAMConfig $CAMConfig `
            -tempDir $tempDir `
            -certificateFile $certificateFile `
            -certificateFilePassword $certificateFilePassword `
            -camSaasUri $camSaasUri `
            -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate `
            -subscriptionID $subscriptionID `
            -ownerTenantId $ownerTenantId `
            -ownerUpn $ownerUpn `
            -Tag $tag

        # Populate/re-populate CAMDeploymentInfo before deploying the connector
        New-CAMDeploymentInfo `
            -kvName $kvInfo.VaultName

        if( $deployOverDC)
        {
            # Need to change to admin context for this to work
            Write-Host "Reverting to initial Azure context for $($azureContext.Account.Id)"
            Set-AzureRMContext -Context $azureContext | Out-Null

            # Should only be one KeyVault at this step (verified in an earlier step in main script)
            $CAMRootKeyvault = Get-AzureRmResource `
                -ResourceGroupName $rgName `
                -ResourceType "Microsoft.KeyVault/vaults" `
                | Where-object {$_.Name -like "CAM-*"}

            New-ConnectionServiceDeployment `
                -spCredential $spInfo.spCreds `
                -RGName $rgName `
                -subscriptionId $subscriptionID `
                -keyVault $CAMRootKeyvault `
                -tenantId $tenantId `
                -testDeployment $testDeployment `
                -tempDir $tempDir `
                -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate `
                -camSaasUri $camSaasUri `
                -enableExternalAccess $enableExternalAccess `
                -enableRadiusMfa $radiusConfig.enableRadiusMfa `
                -radiusServerHost $radiusConfig.radiusServerHost `
                -radiusServerPort $radiusConfig.radiusServerPort `
                -radiusSharedSecret $radiusConfig.radiusSharedSecret `
                -vnetConfig $vnetConfig `
                -brokerRetrieveAgentState $brokerRetrieveAgentState `
                -clientShowAgentState $clientShowAgentState `
                -brokerCacheTimeoutSeconds $brokerCacheTimeoutSeconds `
                -brokerCacheSize $brokerCacheSize `
                -isBrokerCacheEnabled $isBrokerCacheEnabled `
                -Tag $tag
        }
        else
        {
            # keyvault ID of the form: /subscriptions/$subscriptionID/resourceGroups/$azureRGName/providers/Microsoft.KeyVault/vaults/$kvName
            $kvId = $kvInfo.ResourceId

            $tagString = $tag | ConvertTo-Json -Compress

            $generatedDeploymentParameters = @"
{
    "`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "dcOsType": {
            "value": "$domainControllerOsType"
        },
        "domainAdminUsername": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "domainServiceAccountUsername"
            }
        },
        "domainName": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "domainName"
            }
        },
        "remoteWorkstationDomainGroup": {
            "reference": {
                "keyVault": {
                    "id": "$kvID"
                },
                "secretName": "remoteWorkstationDomainGroup"
            }
        },
        "connectionServiceResourceGroup": {
            "value": "$csRGName"
        },
        "remoteWorkstationResourceGroup": {
            "value": "$rwRGName"
        },
        "vnetName": {
            "value": "$($CAMConfig.internal.vnetName)"
        },
        "rootSubnetName": {
            "value": "$($CAMConfig.internal.rootSubnetName)"
        },
        "remoteWorkstationSubnetName": {
            "value": "$($CAMConfig.internal.RWSubnetName)"
        },
        "connectionServiceSubnetName": {
            "value": "$($CAMConfig.internal.CSSubnetName)"
        },
        "gatewaySubnetName": {
            "value": "$($CAMConfig.internal.GWSubnetName)"
        },
        "binaryLocation": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "binaryLocation"
            }
        },
        "_artifactsLocation": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "artifactsLocation"
            }
        },
        "userStorageAccountName": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "userStorageName"
            }
        },
        "userStorageAccountUri": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "userStorageAccountUri"
            }
        },
        "userStorageAccountSasToken": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "userStorageAccountSasToken"
            }
        },
        "userStorageAccountKey": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "userStorageAccountKey"
            }
        },
        "LocalAdminUsername": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "connectionServiceLocalAdminUsername"
            }
        },
        "LocalAdminPassword": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "connectionServiceLocalAdminPassword"
            }
        },
        "rwsLocalAdminUsername": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "remoteWorkstationLocalAdminUsername"
            }
        },
        "rwsLocalAdminPassword": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "remoteWorkstationLocalAdminPassword"
            }
        },
        "DomainAdminPassword": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "domainServiceAccountPassword"
            }
        },
        "certData": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "CAMCSCertificate"
            }        
        },
        "certPassword": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "CAMCSCertificatePassword"
            }
        },
        "CAMDeploymentInfo": {
            "reference": {
                "keyVault": {
                    "id": "$kvId"
                },
                "secretName": "CAMDeploymentInfo"
            }
        },
        "registrationCode": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "cloudAccessRegistrationCode"
            }
        },
        "enableRadiusMfa": {
            "reference": {
                "keyVault": {
                "id": "$kvId"
                },
                "secretName": "enableRadiusMfa"
            }
        },
        "enableExternalAccess" : {
            "value": "$($enableExternalAccess.ToString())"
        },
        "autoShutdownIdleTime" : {
            "value": $defaultIdleShutdownTime
        },
        "brokerRetrieveAgentState" : {
            "value": $($brokerRetrieveAgentState | ConvertTo-Json)
        },
        "clientShowAgentState" : {
            "value": $($clientShowAgentState | ConvertTo-Json)
        },
        "brokerCacheTimeoutSeconds": {
            "value": $brokerCacheTimeoutSeconds
        },
        "brokerCacheSize": {
            "value": $brokerCacheSize
        },
        "isBrokerCacheEnabled": {
            "value": $($isBrokerCacheEnabled | ConvertTo-Json)
        },
        "tag" : {
            "value": $tagString
        }
    }
}
"@

            $outputParametersFilePath = Join-Path $tempDir $outputParametersFileName
            Set-Content $outputParametersFilePath  $generatedDeploymentParameters

            Write-Host "`nDeploying Cloud Access Manager, this process can take up to 120 minutes"
            Write-Host "Please feel free to watch here for early errors for a few minutes and then go do something else, or go for coffee!"
            Write-Host "If this script is running in Azure Cloud Shell then you may let the shell timeout and the deployment will continue"
            Write-Host "Please watch the resource group $RGName in the Azure Portal for current status, the Cloud Access Manager deployment is"
            Write-Host "complete when all deployments are showing as 'Succeeded'"
            Write-Host "Error information is also available through the deployments area of the resource group pane"

            if ($testDeployment) {
                # just do a test if $true
                Test-AzureRmResourceGroupDeployment `
                    -ResourceGroupName $RGName `
                    -TemplateFile $CAMDeploymentTemplateURI `
                    -TemplateParameterFile $outputParametersFilePath `
                    -Verbose
            }
            else {
                New-AzureRmResourceGroupDeployment `
                    -DeploymentName "CAM" `
                    -ResourceGroupName $RGName `
                    -TemplateUri $CAMDeploymentTemplateURI `
                    -TemplateParameterFile $outputParametersFilePath `
                    -ErrorAction stop `
                    -WarningAction Ignore
            }
        }
    }
    catch {
        # Check if there's an Azure log message we can show, otherwise just re-throw
        $err = $_
        $errorToThrow = Append-AzureRMLog -err $err

        throw $errorToThrow
    }
    finally {
        if ($azureContext) {
            Write-Host "Reverting to initial Azure context for $($azureContext.Account.Id)"
            Set-AzureRMContext -Context $azureContext | Out-Null
        }
    }
}

function Confirm-ModuleVersion()
{
    # Check Azure RM version
    if ($isUnix) {
        $MinAzureRMVersion="0.12.0"
        $AzureRMModule = Get-Module -ListAvailable -Name "AzureRM.Netcore"
        if( -not $AzureRMModule ) {
            $MinAzureRMVersion="0.1.0"
            $AzureRMModule = Get-Module -ListAvailable -Name "Az.*"
        }
    } else {
        $MinAzureRMVersion="6.0.0"
        $AzureRMModule = Get-Module -ListAvailable -Name "AzureRM"
    }
    if ( $AzureRMModule ) {
        # have an AzureRM version - check that.
        if (-not ( $AzureRMModule.Version -ge [version]$MinAzureRMVersion)) {
            Write-Host ("AzureRM module version must be equal or greater than " + $MinAzureRMVersion)
            return $false
        }
    }
    else {
        # the Azure SDK doesn't install 'AzureRM' as a base module any more, just Azure
        $MinAzureVersion="5.1.1"
        $AzureModule = Get-Module -ListAvailable -Name "Azure"

        if ( -not $AzureModule ) {
            # neither module found
            Write-Host ("Please install the Azure Command Line tools for Powershell from Microsoft, Azure and AzureRM modules must be present")
            return $false
        }
        if (-not ( $AzureModule.Version -ge [version]$MinAzureVersion)) {
            Write-Host ("Azure module version must be equal or greater than " + $MinAzureVersion)
            return $false
        }
    }
    return $true
}

function Get-CAMRoleDefinitionName() {
    param(
        [String]$subscriptionId=""
    )
    if ( -not $subscriptionId ) {
        return "Cloud Access Manager"
    }
    return "Cloud Access Manager", $subscriptionId -Join "-"
}

# Create a custom role for CAM with necessary permissions
# Use 'Get-AzureRmProviderOperation *' to get a list of Azure Operations and their details
# See https://docs.microsoft.com/en-us/azure/active-directory/role-based-access-built-in-roles for details on Azure Built in Roles
function Get-CAMRoleDefinition() {
    param(
        [String]$subscriptionId=""
    )

    # Check for old "Cloud Access Manager" Role Deifinition
    $roleName = Get-CAMRoleDefinitionName
    $camCustomRoleDefinition = Get-AzureRmRoleDefinition $roleName
    # Check for new "Cloud Access Manager-$subsctionId" Role Definition if old is invalid
    if ( -not $camCustomRoleDefinition -or ($camCustomRoleDefinition -and -not ( `
            $camCustomRoleDefinition.AssignableScopes.Contains("/subscriptions/$subscriptionId") `
            -or $camCustomRoleDefinition.AssignableScopes.Contains("/subscriptions/*")))) {
        $roleName = Get-CAMRoleDefinitionName -subscriptionId $subscriptionId
        $camCustomRoleDefinition = Get-AzureRmRoleDefinition $roleName
    }
    
    # Create Role Defintion Based off of Contributor if it doesn't already exist
    if ( -not $camCustomRoleDefinition ) {
        Write-Host "Creating '$roleName' Role Definition"
        $camCustomRoleDefinition = Get-AzureRmRoleDefinition "Contributor"
        $camCustomRoleDefinition.Id = $null
        $camCustomRoleDefinition.IsCustom = $true
        $camCustomRoleDefinition.Name = $roleName
        $camCustomRoleDefinition.Description = "Required Permissions for $roleName"

        # Limit Assignable scopes to specified subscription
        if ($subscriptionId) {
            $camCustomRoleDefinition.AssignableScopes.Clear()
            $camCustomRoleDefinition.AssignableScopes.Add("/subscriptions/$subscriptionId")
        }

        # Clear out existing NotActions
        $camCustomRoleDefinition.NotActions.clear()

        # Actions to remove
        $requiredNotActions = @(
            # Default NotActions to disable to prevent elevation of privlege
            'Microsoft.Authorization/*/Delete'
            'Microsoft.Authorization/*/Write'
            'Microsoft.Authorization/elevateAccess/Action'
            
            # Remove ability to access snapshots
            'Microsoft.Compute/snapshots/*'
            # Remove ability to access restore points
            'Microsoft.Compute/restorePointCollections/*'
            # Remove ability to get SAS URI of VM Disk for Blob access
            'Microsoft.Compute/disks/beginGetAccess/action'
            # Remove ability to revoke SAS URI of VM Disk for Blob access
            'Microsoft.Compute/disks/endGetAccess/action'

            # Remove ability to access application gateway WAF rulesets
            'Microsoft.Network/applicationGatewayAvailableWafRuleSets/*'
            # Remove ability to access vpn connection info
            'Microsoft.Network/connections/*'
            # Remove ability to access dns zones and operation satuses
            'Microsoft.Network/dnszones/*'
            'Microsoft.Network/dnsoperationstatuses/*'
            # Remove ability to access express routes
            'Microsoft.Network/expressRouteCrossConnections/*'
            'Microsoft.Network/expressRouteCircuits/*'
            'Microsoft.Network/expressRouteServiceProviders/*'
            # Remove ability to access load balancers
            'Microsoft.Network/loadBalancers/*'
            # Remove ability to access network watchers
            'Microsoft.Network/networkWatchers/*'
            # Remove ability to access route filters and tables
            'Microsoft.Network/routeFilters/*'
            'Microsoft.Network/routeTables/*'
            # Remove ability to access service endpoint policies
            'Microsoft.Network/serviceEndpointPolicies/*'
            # Remove ability to access traffic management
            'Microsoft.Network/trafficManagerProfiles/*'
            'Microsoft.Network/trafficManagerUserMetricsKeys/*'
            'Microsoft.Network/trafficManagerGeographicHierarchies/*'
            # Remove ability to delete Vnets
            'Microsoft.Network/virtualNetworks/delete'
            # Remove ability to peer Vnet to other Vnets
            'Microsoft.Network/virtualNetworks/peer/action'
            # Remove ability to access Vnet peering info
            'Microsoft.Network/virtualNetworks/virtualNetworkPeerings/*'
            # Remove ability to access virtual network gateways and taps
            'Microsoft.Network/virtualNetworkGateways/*'
            'Microsoft.Network/virtualNetworkTaps/*'
            # Remove ability to access virtual wans and hubs
            'Microsoft.Network/virtualwans/*'
            'Microsoft.Network/virtualHubs/*'
            # Remove ability to access vpn gateways and sites
            'Microsoft.Network/vpnGateways/*'
            'Microsoft.Network/vpnsites/*'

            # Remove ability to access queue service in storage account
            'Microsoft.Storage/StorageAccounts/queueServices/*'
        )

        # Add Not Actions required to be disabled
        foreach ( $notAction in $requiredNotActions) {
            if ( (Get-AzureRmProviderOperation $notAction) -and -not $camCustomRoleDefinition.NotActions.Contains($notAction)) {
                $camCustomRoleDefinition.NotActions.Add($notAction)
            }
        }

        # Clear out existing Actions
        $camCustomRoleDefinition.Actions.Clear()

        # Actions to add
        $requiredActions = @(
            "Microsoft.Resources/*"
            "Microsoft.KeyVault/*"
            "Microsoft.Storage/*"
            "Microsoft.Network/*"
            "Microsoft.Compute/*"
        )

        # Add Actions required to be enabled
        foreach ( $Action in $requiredActions) {
            if ( (Get-AzureRmProviderOperation $Action) -and -not $camCustomRoleDefinition.Actions.Contains($Action)) {
                $camCustomRoleDefinition.Actions.Add($Action)
            }
        }

        try{
            New-AzureRmRoleDefinition -Role $camCustomRoleDefinition -ErrorAction Stop | Out-Null
        }
        catch {
            $err = $_
            Write-Host-Warning "Cannot create '$roleName' Role Definition"
            throw $err
        }
        $camCustomRoleDefinition = Get-AzureRmRoleDefinition $roleName
    } else {
        Write-Host "Found existing '$roleName' Role Definition"
    }

    return $camCustomRoleDefinition
}

# Make message more visible
function Write-Host-Warning() {
    param(
        $message
    )
    Write-Host ("`n$message") -ForegroundColor Red
}

# Check if a resource is currently registered to the Subscription
function checkResource(){
    param(
        [parameter(Mandatory=$true)]
        $resourceProviderList,
        [parameter(Mandatory=$true)]
        $resourceName,
        [parameter(Mandatory=$true)]
        $ignorePrompts,
        [parameter(Mandatory=$true)]
        $rmContext
    )

    $resource = $resourceProviderList | Where-Object {$_.ProviderNamespace -eq $resourceName}
    Write-host "Checking $($resourceName)"
    if(-not ($resource.RegistrationState -eq "Registered")) {
        Write-Host "$($resourceName) is not registered as a resource provider for this subscription,"
        Write-Host "Cloud Access Manager requires access to features within $($resourceName) to deploy"
        if(-not $ignorePrompts) {
            $cancelDeployment = (confirmDialog "Do you want to register $($resourceName) with subscription $($rmContext.Subscription.Id) or 'no' to cancel deployment?" -defaultSelected 'Y') -eq "n"
            if ($cancelDeployment) { exit }
        }
        Register-AzureRmResourceProvider -ProviderNamespace $resourceName -ErrorAction stop | Out-Null
    }


}


# Check resource group location for cores, if less than $neededCores exit the launch
function Check-Location-Cores() {
    param(
        [parameter(Mandatory=$true)]
        $rgLocation,
        [parameter(Mandatory=$true)]
        $neededCores
    )
    # "cores" is the Name.Value for "Total Regional vCPUs"
    $totalRegionUsage = Get-AzureRmVMUsage -Location $rgLocation | Where-Object {$_.Name.Value -eq "cores"}
    $availableCores = $totalRegionUsage.Limit - $totalRegionUsage.CurrentValue
    if($availableCores -lt $neededCores){

        Write-Host-Warning "Not enough vCPUs available in $rgLocation, $neededCores vCPUs required, $availableCores available"
        exit
    }
}

# Sets any unpopulated sections of the passed in vnetConfig structure, by prompting the user
function Set-VnetConfig() {
    Param(
        [parameter(Mandatory=$true)]
        $vnetConfig,
        [parameter(Mandatory=$false)]
        $setRWSubnet = $true,
        [parameter(Mandatory=$false)]
        $reqCores,
        [parameter(Mandatory=$false)]
        $domainController = $false
    )

    # prompt for vnet name, gateway subnet name, remote workstation subnet name, connector subnet name
    do {
        if ( -not $vnetConfig.vnetID ) {
            $vnets = Get-AzureRmVirtualNetwork

            $vnetIndex = 0
            ForEach ($v in $vnets) {
                if (-not (Get-Member -InputObject $v -name "Number")) {
                    Add-Member -InputObject $v -Name "Number" -Value "" -MemberType NoteProperty
                }
                $v.Number = ++$vnetIndex
            }

            Write-Host "`nPlease provide the VNet information that the Cloud Access connectors, gateways, and remote workstations will be using"
            Write-Host "Please enter the number of the vnet in the following list or the complete VNet ID in"
            Write-Host "the form /subscriptions/{subscriptionID}/resourceGroups/{vnetResourceGroupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}`n"
            Write-Host "The service principal account for this Cloud Access Manager deployment will be provided access rights to the selected virtual network" -ForegroundColor Yellow
            $vnets | Select-Object -Property Number, Name, ResourceGroupName, Location | Format-Table

            $chosenVnet = Read-Host "VNet"
            $chosenVnetIndex = 0
            [int]::TryParse($chosenVnet, [ref]$chosenVnetIndex) | Out-Null # chosenVnetIndex will be 0 on parse failure

            if (( $chosenVnetIndex -ge 1) -and ( $chosenVnetIndex -le $vnets.Length)) {
                # have selected a valid index - use that and substitute
                $vnetConfig.vnetID = $vnets[$chosenVnetIndex - 1].Id
            }
            else {
                # otherwise interpret as a resource ID
                $vnetConfig.vnetID = $chosenVnet.Trim()
            }
        }
        # vnetID is a reference ID that is like: 
        # "/subscriptions/{subscription}/resourceGroups/{vnetRG}/providers/Microsoft.Network/virtualNetworks/{vnetName}"
        $vnetName = $vnetConfig.vnetID.split("/")[-1]
        $vnetRgName = $vnetConfig.vnetID.split("/")[4]
        if ( (-not $vnetRgName) -or (-not $vnetName) -or `
            (-not (Get-AzureRmResource -ResourceGroupName $vnetRgName `
            -ResourceType "Microsoft.Network/virtualNetworks" `
            -Name $vnetName `
            -ErrorAction SilentlyContinue)) ) {
                # Does not exist
                Write-Host-Warning "$($vnetConfig.vnetID) not found"
                $vnetConfig.vnetID = $null
        }
    } while (-not $vnetConfig.vnetID)

    # Now select subnets
    $vnet = Get-AzureRmVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRgName
    
    # Only check if we are deploying to an existing CAM deployment, not to an existing domain controller.
    # Domain controller version can use a different location, so we check that one later.
    if(-not $domainController){
        Check-Location-Cores -rgLocation $vnet.Location -neededCores $reqCores
    }

    Write-Host "Using VNet: $($vnet.Id)`n"

    $subnets = $vnet.Subnets
    $subnetIndex = 0
    ForEach ($s in $subnets) {
        if (-not (Get-Member -inputobject $s -name "Number")) {
            Add-Member -InputObject $s -Name "Number" -Value "" -MemberType NoteProperty
        }
        $s.Number = ++$subnetIndex
    }

    # connector Subnet
    do {
        if ( -not $vnetConfig.CSsubnetName ) {
            Write-Host "Please provide the Cloud Access connector subnet number from the list below, or name"
            $subnets | Select-Object -Property Number, Name | Format-Table
            $chosenSubnet = Read-Host "Subnet"
            $subnetIndex = 0
            [int]::TryParse($chosenSubnet, [ref]$subnetIndex) | Out-Null  # subnetIndex will be 0 on parse failure
        
            if (( $subnetIndex -ge 1) -and ( $subnetIndex -le $subnets.Count)) {
                # selected a valid index - use that and substitute
                $vnetConfig.CSsubnetName = $subnets[$subnetIndex - 1].Name
            }
            else {
                # otherwise interpret as a subnet name
                $vnetConfig.CSsubnetName = $chosenSubnet.Trim()
            }
        }
        if ( -not ($vnet.Subnets | ?{$_.Name -eq $vnetConfig.CSsubnetName}) ) {
            # Does not exist
            Write-Host-Warning "$($vnetConfig.CSsubnetName) not found in '$($vnet.Name)'"
            $vnetConfig.CSsubnetName = $null
        }
    } while (-not $vnetConfig.CSsubnetName)
    Write-Host "Cloud Access connector subnet: $($vnetConfig.CSsubnetName)`n"

    # Application Gateway Subnet
    do {
        if ( -not $vnetConfig.GWsubnetName ) {
            Write-Host "Please provide Application Gateway subnet number from the list below, or name"
            $subnets | Select-Object -Property Number, Name | Format-Table
            $chosenSubnet = Read-Host "Subnet"
            $subnetIndex = 0
            [int]::TryParse($chosenSubnet, [ref]$subnetIndex) | Out-Null  # subnetIndex will be 0 on parse failure
        
            if (( $subnetIndex -ge 1) -and ( $subnetIndex -le $subnets.Count)) {
                # selected a valid index - use that and substitute
                $vnetConfig.GWsubnetName = $subnets[$subnetIndex - 1].Name
            }
            else {
                # otherwise interpret as a subnet name
                $vnetConfig.GWsubnetName = $chosenSubnet.Trim()
            }
        }
        if ( -not ($vnet.Subnets | ?{$_.Name -eq $vnetConfig.GWsubnetName}) ) {
            # Does not exist
            Write-Host-Warning "$($vnetConfig.GWsubnetName) not found in '$($vnet.Name)'"
            $vnetConfig.GWsubnetName = $null
        }
    } while (-not $vnetConfig.GWsubnetName)
    Write-Host "Application Gateway subnet: $($vnetConfig.GWsubnetName)`n"
    
    # Remote Workstation Subnet
    if(-not $setRWSubnet) {return}  # <--- early return!
    do {
        if ( -not $vnetConfig.RWsubnetName ) {
            Write-Host "Please provide Remote Workstation subnet number from the list below, or name"
            $subnets | Select-Object -Property Number, Name | Format-Table
            $chosenSubnet = Read-Host "Subnet"
            $subnetIndex = 0
            [int]::TryParse($chosenSubnet, [ref]$subnetIndex) | Out-Null  # subnetIndex will be 0 on parse failure
        
            if (( $subnetIndex -ge 1) -and ( $subnetIndex -le $subnets.Count)) {
                # selected a valid index - use that and substitute
                $vnetConfig.RWsubnetName = $subnets[$subnetIndex - 1].Name
            }
            else {
                # otherwise interpret as a subnet name
                $vnetConfig.RWsubnetName = $chosenSubnet.Trim()
            }
        }
        if ( -not ($vnet.Subnets | ?{$_.Name -eq $vnetConfig.RWsubnetName}) ) {
            # Does not exist
            Write-Host-Warning "$($vnetConfig.RWsubnetName) not found in '$($vnet.Name)'"
            $vnetConfig.RWsubnetName = $null
        }
    } while (-not $vnetConfig.RWsubnetName)
    Write-Host "Remote Workstation subnet: $($vnetConfig.RWsubnetName)`n"
}


# Prompt for and update RADIUS Settings in the Keyvault
function Set-RadiusSettings() {
    Param(
        [parameter(Mandatory=$true)]
        [string]$VaultName,

        [parameter(Mandatory=$true)]
        $enableExternalAccess,

        [parameter(Mandatory = $false)]
        $enableRadiusMfa=$null,
    
        [parameter(Mandatory=$false)]
        [String]
        $radiusServerHost,
    
        [parameter(Mandatory=$false)]
        [int]
        $radiusServerPort,
    
        [parameter(Mandatory=$false)]
        [SecureString]
        $radiusSharedSecret  
    )
    # Check current MFA settings
    $secret = Get-KVSecret -kvName $VaultName -secretName "enableRadiusMfa"
    if($secret.SecretValueText) {
        $isRadiusMfaEnabledSecret = $secret.SecretValueText
    } else {
        $isRadiusMfaEnabledSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
    }
    $isRadiusMfaEnabled = ([bool]($isRadiusMfaEnabledSecret.ToLower() -eq "true"))

    $secret = Get-KVSecret -kvName $VaultName -secretName "radiusServerHost"
    if($secret.SecretValueText) {
        $currentRadiusHostSecret = $secret.SecretValueText
    } else {
        $currentRadiusHostSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
    }
    $currentRadiusHost = ([string]$currentRadiusHostSecret)

    $secret = Get-KVSecret -kvName $VaultName -secretName "radiusServerPort"
    if($secret.SecretValueText) {
        $currentRadiusPortSecret = $secret.SecretValueText
    } else {
        $currentRadiusPortSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
    }
    $currentRadiusPort = ([string]$currentRadiusPortSecret)

    $secret = Get-KVSecret -kvName $VaultName -secretName "radiusSharedSecret"
    if($secret.SecretValueText) {
        $currentRadiusSecretSecret = $secret.SecretValueText
    } else {
        $currentRadiusSecretSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
    }
    $currentRadiusSecret = ([string]$currentRadiusSecretSecret)

    # Prompt for RADIUS configuration if RADIUS has not been already explicitly been disabled
    if ($ignorePrompts -and ($enableRadiusMfa -eq $null)) {
        $enableRadiusMfa = $isRadiusMfaEnabled
    }

    # Check if any settings are different
    $changeRadiusSettings = `
        (($enableRadiusMfa -ne $null)   -and ($enableRadiusMfa -notmatch $isRadiusMfaEnabled)) -or `
        ($radiusServerHost              -and ($radiusServerHost -notmatch $currentRadiusHost)) -or `
        ($radiusServerPort              -and ($radiusServerPort -notmatch $currentRadiusPort)) -or `
        ($radiusSharedSecret)

    # Update RADIUS Settings appropriately
    if ( $changeRadiusSettings -or (-not $ignorePrompts) ) {
        # Load provided RADIUS Configuration Parameters
        $radiusConfig = @{ 
            enableRadiusMfa = $isRadiusMfaEnabled
            radiusServerHost =  $currentRadiusHost
            radiusServerPort =  $currentRadiusPort
            radiusSharedSecret =  ConvertTo-SecureString $currentRadiusSecret -AsPlainText -Force
        }

        # Prompt for whether to enable RADIUS integration
        if ( ($enableRadiusMfa -eq $null) -and (-not $ignorePrompts) ) {
            $currentRadiusSetting = "disabled"
            if ($isRadiusMfaEnabled) {
                $currentRadiusSetting = "enabled"
            }
            $enableRadiusMfa = (confirmDialog "RADIUS Multi-Factor Authentication is currently $($currentRadiusSetting), do you want to enable Multi-Factor Authentication using your RADIUS Server?") -eq 'y'
        } elseif ( ($enableRadiusMfa -eq $null) -and $ignorePrompts ) {
            $enableRadiusMfa = $isRadiusMfaEnabled
        }
        $radiusConfig.enableRadiusMfa = $enableRadiusMfa

        if ( $radiusConfig.enableRadiusMfa -and (-not $enableExternalAccess)) {
            Write-Error "Multi-Factor Authentication for internal deployments is not supported"
            exit
        }

        if ($radiusConfig.enableRadiusMfa) {
            if ((-not $radiusServerHost) -and (-not $ignorePrompts)) {
                if((confirmDialog "RADIUS Server Host is currently $($currentRadiusHost), do you want to change your RADIUS Server Host?") -eq 'y') {
                    do {
                        $radiusConfig.radiusServerHost = (Read-Host "Enter your RADIUS Server's Hostname or IP").Trim()
                    } while (-not $radiusConfig.radiusServerHost)
                }
            } elseif ($radiusServerHost) {
                $radiusConfig.radiusServerHost = $radiusServerHost
            }

            if ((-not $radiusServerPort) -and (-not $ignorePrompts)) {
                if((confirmDialog "RADIUS Server Port is currently $($currentRadiusPort), do you want to change your RADIUS Server Port?") -eq 'y') {
                    do {
                        $radiusPort = 0
                        $portString = (Read-Host  "Enter your RADIUS Server's Listening port")
                        [int]::TryParse($portString, [ref]$radiusPort) | Out-Null # radiusPort will be 0 on parse failure
                        $radiusConfig.radiusServerPort = $radiusPort
                        if ( ($radiusConfig.radiusServerPort -le 0) -or ($radiusConfig.radiusServerPort -gt 65535) ) {
                            Write-Host-Warning "Entered port is invalid, it should be between 1 and 65535"
                            $radiusConfig.radiusServerPort = $null
                        }      
                    } while (-not $radiusConfig.radiusServerPort )
                }
            } elseif ( $radiusServerPort ) {
                $radiusConfig.radiusServerPort = $radiusServerPort
                $portValid = $false
                do {
                    if ( ($radiusConfig.radiusServerPort -le 0) -or ($radiusConfig.radiusServerPort -gt 65535) ) {
                        Write-Host-Warning "Entered port is invalid, it should be between 1 and 65535"
                        $portValid = $false
                    } else {
                        $portValid=$true
                    }
                    if (-not $portValid ) {
                        $radiusPort = 0
                        $portString = (Read-Host  "Enter your RADIUS Server's Listening port")
                        [int]::TryParse($portString, [ref]$radiusPort) | Out-Null # radiusPort will be 0 on parse failure
                        $radiusConfig.radiusServerPort = $radiusPort
                        if (-not $radiusConfig.radiusServerPort) {
                            $portValid = $false
                            Write-Host-Warning "Entered port is not an Integer"
                        }  
                    }
                } while (-not $portValid )
            }

            if ((-not $radiusSharedSecret) -and (-not $ignorePrompts)) {
                if((confirmDialog "Do you want to change your RADIUS Server Shared Secret?") -eq 'y') {
                    do {
                        $radiusConfig.radiusSharedSecret = Read-Host -AsSecureString "Enter your RADIUS Server's Shared Secret"
                    } while (-not $radiusConfig.radiusSharedSecret )
                }
            } elseif ( $radiusSharedSecret ) {
                $radiusConfig.radiusSharedSecret = $radiusSharedSecret
            }
        }

        # Store required keys as CamConfig Object
        $camConfig = @{
            parameters=@{}
        }
        foreach ($key in $radiusConfig.keys) {
            if ($radiusConfig[$key].GetType() -eq [SecureString]) {
                # RadiusSharedSecret is already a SecureString
                $camConfig.parameters[$key] = @{
                    value=$radiusConfig[$key]
                }
            } else {
                $camConfig.parameters[$key] = @{
                    value=(ConvertTo-SecureString $radiusConfig[$key] -AsPlainText -Force)
                }
            }
        }

        # Update KeyVault
        Add-SecretsToKeyVault `
            -kvName $VaultName `
            -CAMConfig $camConfig
    }
}

# Get secret with retries
function Get-KVSecret(){
    param(
        [parameter(Mandatory=$true)]
        [string]$kvName,

        [parameter(Mandatory=$true)]
        [string]$secretName
    )

    try {
        $retryCount = 3
        while($retryCount -ge 0) {
            $retryCount--; 
            try {
                $secret = Get-AzureKeyVaultSecret `
                    -VaultName $kvName `
                    -Name $secretName `
                    -ErrorAction stop
                break
            } catch {
                if($retryCount -eq 0){
                    throw
                }
                Write-Host "Unsuccessful retrieval of $key - retries remaining: $retryCount" 
                Start-Sleep -Seconds 5
            }
        }
    } catch {
        Write-Error "Failed to retrieve secret $key from Key Vault"
        exit
    }

    return $secret
}

# Set secret with retries
function Set-KVSecret(){
    param(
        [parameter(Mandatory=$true)]
        [string]$kvName,

        [parameter(Mandatory=$true)]
        [string]$secretName,

        [parameter(Mandatory=$true)]
        $secretValue
    )

    try {
        Write-Host "Writing secret $secretName to Key Vault"
        $retryCount = 3
        while($retryCount -ge 0){
            $retryCount--
            try {
                Set-AzureKeyVaultSecret `
                    -VaultName $kvName `
                    -Name $secretName `
                    -SecretValue $secretValue `
                    -ErrorAction stop | Out-Null
                break
            } catch {
                if($retryCount -eq 0) {
                    throw
                }
                Write-Host "Unsuccessful write of $secretName to Key Vault - retries remaining: $retryCount"
                Start-Sleep -Seconds 5
            }
        }
    } catch {
        Write-Error "Failed to write secret $secretName to Key Vault"
        exit
    }
}

# Gives the currently authenticated user Secret access to the key vault and returns
# $true on success and $false on failure
function Set-KeyVaultAccess()
{
    param(
        $CAMRootKeyvault
        )

    $claims = Get-Claims # Current logged in user info

    $kvName = $CAMRootKeyvault.name
    try {
        # We don't need the secret but need to know we can get it.
        Get-AzureKeyVaultSecret `
            -VaultName $kvName `
            -Name "AzureSPClientID" `
            -ErrorAction stop | Out-Null
        return $true
    }
    catch {
        $err = $_
        if ($err.Exception.Message -eq "Access denied") {
            Write-Host "Cannot access Key Vault secret, attempting to set access policy for vault $kvName for user $($claims.unique_name)"
            try {
                Set-AzureRmKeyVaultAccessPolicy `
                    -VaultName $kvName `
                    -ObjectId $claims.oid `
                    -PermissionsToSecrets Get, Set, List `
                    -ErrorAction stop | Out-Null
                return $true
            }
            catch {
                Write-Host "`nFailed to set access policy for vault $kvName for user $($claims.unique_name)"
                Write-Host "Please use the Azure Portal to provide the current logged-in account with get, list, and set access"
                Write-Host "to the secrets in $kvName"
                return $false
            }
        }
        else {
            # Something strange - re-throw.
            throw $err
        }
    }
}

# Returns if s1 contains s2 with a case-insensitive check
function Test-StringInString
{
    param ( $s1,$s2 )

    return ($s1.ToUpper()).Contains($s2.ToUpper())
}

# Test-StringInString "Blah" "z"  # $False
# Test-StringInString "Blah" "b"  # $True
# Test-StringInString "Blah" "B"  # $True
# Test-StringInString "Blah" "ah" # $True
# Test-StringInString "Blah" "aH" # $True
# Test-StringInString "aH" "Blah" # $False

function Test-PasswordComplexity
{
    param ( $userName, $pass )
    $complexEnough = $true

    # password can't contain username
    if (Test-StringInString $pass $userName) {
        Write-Host-Warning "Password cannot contain the user's username"
        $complexEnough = $false
    }

    # Must be 12 characters long (or 8? we think 12...)
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
    if ($pass.Length -lt 12) {
        Write-Host-Warning "Password must be a minimum of 12 characters long"
        $complexEnough = $false
    }

    # $symbols = "~!@#$%^&*_-+=``|\(){}[]:;`"'<>,.?/"
    $escapedSymbols = "~!@#$%\^&\*_\-\+=``\|\\\(\)\{\}\[\]:;`"'<>,\.\?/"

    $count =  [int]($pass -cmatch '(?=.*\d)')                # digits
    $count += [int]($pass -cmatch '(?=.*[A-Z])')             # uppercase characters
    $count += [int]($pass -cmatch '(?=.*[a-z])')             # lowercase characters
    $count += [int]($pass -cmatch "(?=.*[$escapedSymbols])") # symbols
    
    if ($count -lt 3) { # three of the above are needed
        Write-Host-Warning ("Password must contain at least three of the following categories:`n" +
                            "Uppercase letters, lowercase letters, digits, and symbols")

        $complexEnough = $false
    }
    return $complexEnough
}

# Update the CAM Azure KeyVault with new secrets that get added with updates
function Update-CAMAzureKeyVault() {
    param(
        [String]
        $VaultName,

        [parameter(Mandatory=$false)]
        $camManagementUserGroup=$null,

        [parameter(Mandatory=$false)]
        $AzureSPObjectId=$null
    )

    # Add camManagementUserGroup if it is not set
    $secret = Get-AzureKeyVaultSecret `
        -VaultName $VaultName `
        -Name "camManagementUserGroup" `
        -ErrorAction stop
    
    if(-not $secret) {
        do {
            if ($camManagementUserGroup -eq $null -and (-not $ignorePrompts)) {
                $camManagementUserGroup = Read-Host "Enter the Distinguished Name for the User Group to log into the CAM Management Interface. Default is 'Domain Admins'. (eg, 'CN=CAM Admins,CN=Users,DC=example,DC=com')"
                if(-not $camManagementUserGroup) {
                    $camManagementUserGroup = "Domain Admins"
                    break
                }
            } elseif (-not $camManagementUserGroup -and $ignorePrompts) {
                $camManagementUserGroup = "Domain Admins"
                break
            }
            if( -not ($camManagementUserGroup.Contains("DC=") -and $camManagementUserGroup.Contains("CN=")))
            {
                Write-Host "Specified Distinguished Name is not valid"
                $camManagementUserGroup=$null
            }
        } while ($camManagementUserGroup -eq $null)

        Set-KVSecret `
            -kvName $VaultName `
            -secretName "camManagementUserGroup" `
            -secretValue (ConvertTo-SecureString $camManagementUserGroup -Force -AsPlainText)
    }

    # Add AzureSPObjectId if it is not set
    $secret = Get-AzureKeyVaultSecret `
        -VaultName $VaultName `
        -Name "AzureSPObjectId" `
        -ErrorAction stop
    
    if($AzureSPObjectId -and -not $secret) {
        Set-KVSecret `
            -kvName $VaultName `
            -secretName "AzureSPObjectId" `
            -secretValue (ConvertTo-SecureString $AzureSPObjectId -Force -AsPlainText)
    }

    # Update Application Gateway Certificate
    $secret = Get-AzureKeyVaultSecret `
        -VaultName $VaultName `
        -Name "CAMCSCertificate" `
        -ErrorAction stop
    if($secret) {
        if (-not $tempDir) {
            $tempDir = $env:TEMP
        }
        if($secret.SecretValueText) {
            $certDataSecret = $secret.SecretValueText
        } else {
            $certDataSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
        }
        [System.IO.File]::WriteAllBytes("$tempDir/cert.pfx", [System.Convert]::FromBase64String($certDataSecret))
        $secret = Get-AzureKeyVaultSecret `
            -VaultName $VaultName `
            -Name "CAMCSCertificatePassword" `
            -ErrorAction stop
        if($secret.SecretValueText) {
            $certPassword = $secret.SecretValueText
        } else {
            $certPassword = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
        }
        $cert = openssl pkcs12 -in "$tempDir/cert.pfx" -passin pass:$certPassword -passout pass:$certPassword -info
        $certSubject = $cert | grep "subject"
        $subject = "subject=/CN=*.cloudapp.net,/CN=localhost,/O=Teradici Corporation,/OU=SoftPCoIP,/L=Burnaby,/ST=BC,/C=CA"
        if($subject.ToLower() -eq $certSubject.ToLower()) {
            # Update Cert
            $certInfo = Get-CertificateInfoForAppGateway
            Set-KVSecret `
                -kvName $VaultName `
                -secretName "CAMCSCertificate" `
                -secretValue $certInfo.cert
            Set-KVSecret `
                -kvName $VaultName `
                -secretName "CAMCSCertificatePassword" `
                -secretValue $certInfo.passwd
        }
    }
}

# Test-PasswordComplexity "C0mplex!"           # $False
# Test-PasswordComplexity "abc123456789"       # $False
# Test-PasswordComplexity "ABC123456789"       # $False
# Test-PasswordComplexity "ABC12345678!"       # $True
# Test-PasswordComplexity "aBC123456789"       # $True
# Test-PasswordComplexity "Abc123456789!@#$%^" # $True


##############################################
############# Script starts here #############
##############################################

if (-not (Confirm-ModuleVersion) ) {
    exit
}


# Get the correct modules and assemblies
Add-Type -AssemblyName System.Web


# Setup a vnet config and populate with command line parameters
$vnetConfig = @{}
$vnetConfig.vnetID = $vnetID
$vnetConfig.CSsubnetName = $ConnectionServiceSubnetName
$vnetConfig.GWsubnetName = $GatewaySubnetName
$vnetConfig.RWsubnetName = $RemoteWorkstationSubnetName

# Get the user's subscription
$rmContext = Get-AzureRmContext
$subscriptions = Get-AzureRmSubscription -WarningAction Ignore
$subscriptionsToDisplay = $subscriptions | Where-Object { $_.State -eq 'Enabled' }

$chosenSubscriptionIndex = $null
if ($subscriptionsToDisplay.Length -lt 1) {
    Write-Host-Warning "Account $($rmContext.Account.Id) has access to no enabled subscriptions"
    exit
}

# Match up subscriptions with the current context and let the user choose 
$subscriptionIndex = 0
$currentSubscriptionIndex = $null
ForEach ($s in $subscriptionsToDisplay) {
    if (-not (Get-Member -inputobject $s -name "Current")) {
        Add-Member -InputObject $s -Name "Current" -Value "" -MemberType NoteProperty
    }
    if (-not (Get-Member -inputobject $s -name "Number")) {
        Add-Member -InputObject $s -Name "Number" -Value "" -MemberType NoteProperty
    }

    if (($s.SubscriptionId -eq $rmContext.Subscription.Id) -and ($s.TenantId -eq $rmContext.Tenant.Id)) {
        $s.Current = "*"
        $currentSubscriptionIndex = $subscriptionIndex
    }
    else {
        $s.Current = ""
    }

    $s.Number = ($subscriptionIndex++) + 1

}

if ($subscriptionsToDisplay.Length -eq 1) {
    Write-Host ("Account " + $rmContext.Account.Id + " has access to a single enabled subscription")
    $chosenSubscriptionNumber = 0
}
else {
    # Let user choose since it's sometimes not obvious...
    $subscriptionsToDisplay | Select-Object -Property Current, Number, Name, SubscriptionId, TenantId | Format-Table

    $currentSubscriptionNumber = $currentSubscriptionIndex + 1

    $chosenSubscriptionNumber = 0 #invalid
    while ( -not (( $chosenSubscriptionNumber -ge 1) -and ( $chosenSubscriptionNumber -le $subscriptionsToDisplay.Length))) {
        if( -not $ignorePrompts ) {
            $chosenSubscriptionNumber = `
            if (($chosenSubscriptionNumber = Read-Host "Enter the number of the subscription you would like to use or press enter to accept the current one [$currentSubscriptionNumber]") -eq '') `
            {$currentSubscriptionNumber} else {[int]$chosenSubscriptionNumber}
        }
        else {
            $chosenSubscriptionNumber = $currentSubscriptionNumber
        }
    }
    Write-Host "Chosen Subscription:"
}

$chosenSubscriptionIndex = $chosenSubscriptionNumber - 1

Write-Host ($subscriptionsToDisplay[$chosenSubscriptionIndex] | Select-Object -Property Current, Number, Name, SubscriptionId, TenantId | Format-Table | Out-String)
$rmContext = Set-AzureRmContext -SubscriptionId $subscriptionsToDisplay[$chosenSubscriptionIndex].SubscriptionId -TenantId $subscriptionsToDisplay[$chosenSubscriptionIndex].TenantId

# The Context doesn't always seem to take the tenant depending on who is logged in - so making a copy from the selected subscription
$selectedTenantId = $subscriptionsToDisplay[$chosenSubscriptionIndex].TenantId
$selectedSubcriptionId = $subscriptionsToDisplay[$chosenSubscriptionIndex].SubscriptionId

# Pull the full list of Resource Providers for manipulation
$providerList = Get-AzureRmResourceProvider

checkResource -resourceProviderList $providerList -resourceName "Microsoft.Keyvault" -ignorePrompts $ignorePrompts -rmContext $rmContext
checkResource -resourceProviderList $providerList -resourceName "Microsoft.Compute" -ignorePrompts $ignorePrompts -rmContext $rmContext
checkResource -resourceProviderList $providerList -resourceName "Microsoft.Network" -ignorePrompts $ignorePrompts -rmContext $rmContext

# Determine if we're upgrading a current deployment
# This section returns a resource group name in $ResourceGroupName if one was found.
$CAMKeyVaults = (Get-AzureRmResource -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue) | Where-object {$_.Name -like "CAM-*"}

$deploymentIndex = 0
ForEach ($s in $CAMKeyVaults) {
    if (-not (Get-Member -inputobject $s -name "Number")) {
        Add-Member -InputObject $s -Name "Number" -Value "" -MemberType NoteProperty
    }

    $s.Number = ++$deploymentIndex
}

if((-not $ResourceGroupName) -and ($deploymentIndex -gt 0)) {
    while ($true) {

        Write-Host "`nCloud Access Manager deployments in this subscription"
        Write-Host ($CAMKeyVaults | Select-Object -Property Number, ResourceGroupName | Format-Table | Out-String)
    
    
        Write-Host ("To upgrade or modify a Cloud Access Manager Deployment, select the resource group of the`n" +
           "Cloud Access Manager deployment root by number, or hit enter to create a new deployment")
        $rgIdentifier = (Read-Host "Resource group").Trim()
        
        # If empty string just exit loop
        if(-not $rgIdentifier) {
            break
        }
    
        $rgIndex = 0
        $rgIsInt = [int]::TryParse($rgIdentifier, [ref]$rgIndex) # rgIndex will be 0 on parse failure
    
        $rgArrayLength = if ($CAMKeyVaults -is [Array]) {$CAMKeyVaults.Length} else {1}
         
        if ( -not (( $rgIndex -ge 1) -and ( $rgIndex -le $rgArrayLength))) {
            # Invalid range try again
            Write-Host-Warning "Please enter a range between 1 and $rgArrayLength, or hit enter to create a new deployment"
        }
        else {
            # Use the selected resource group for selection below
            $ResourceGroupName = $CAMKeyVaults[$rgIndex - 1].ResourceGroupName
            break
        }
    }
}

# Now we (might) have a $ResourceGroupName that (might) point to a resource group that has a CAM keyvault in it.
# Let's double check what type.
# At this point we have a subscription and a root resource group - check if there is already a deployment in it
$CAMRootKeyvault = $null
try{
    $CAMRootKeyvault = Get-AzureRmResource `
        -ResourceGroupName $ResourceGroupName `
        -ResourceType "Microsoft.KeyVault/vaults" `
        -ErrorAction Stop `
        | Where-object {$_.Name -like "CAM-*"}
}
catch {
    # silently swallow - if we had an error we couldn't find the key vault, usually because the resource group didn't exist.
}

$claims = Get-Claims

$upn = ""
if (-not ([string]::IsNullOrEmpty($claims.upn)))
{
    $upn = $claims.upn
}

# If there is a root keyvault, verify there is only one and then query for connector deployment.
if ($CAMRootKeyvault) {
    if ($CAMRootKeyvault -is [Array]) {
        Write-Host "More than one CAM Key Vault found in this resource group, please move or remove all but one"
        return   # early return!
    }

    Write-Host "The resource group $ResourceGroupName has a CAM deployment"
    Write-Host "Using Key Vault $($CAMRootKeyvault.Name)"

    # Ensure this user account can get secrets from the key vault
    $hasKVAccess = Set-KeyVaultAccess -CAMRootKeyvault $CAMRootKeyvault
    if(-not $hasKVAccess) {return}

    Write-Host "`nCreating a new Cloud Access connector for this Cloud Access Manager deployment`n"

    if (-not $AzureSPObjectId) {
        if($spCredential) {
            $AzureSPObjectId = (Get-AzureRmADApplication -ApplicationId $spCredential.UserName).ObjectId
        } else {
            $AzureSPObjectId = (Get-AzureRmADApplication -DisplayNameStartWith "CAM-$ResourceGroupName").ObjectId
        }
    }
    # Update KeyVault with new Secrets
    Update-CAMAzureKeyVault `
        -camManagementUserGroup $camManagementUserGroup `
        -AzureSPObjectId $AzureSPObjectId `
        -VaultName $CAMRootKeyvault.Name

    $externalAccessPrompt = "Do you want to enable external network access for this connector?"

    if ($enableExternalAccess -eq $null) {
        $enableExternalAccess = (confirmDialog $externalAccessPrompt -defaultSelected 'Y') -eq 'y'
    }

    # For automation, to deploy in a different region then CSSubnetName and GWSubnetName need to be passed on the
    # command line and the prompt will be bypassed.

    if ((-not $vnetConfig.CSSubnetName) -or (-not $vnetConfig.GWSubnetName))
    {
        $rootLocation = (Get-AzureRmResourceGroup -ResourceGroupName $ResourceGroupName -ErrorAction stop).location
        $reselectNetwork = (confirmDialog "Do you want to deploy into a different region than $($rootLocation)?" -defaultSelected 'N') -eq 'y'

        if($reselectNetwork) {
            # We don't need the RWSubnetName so don't prompt
            if(-not $vnetConfig.RWSubnetName) {
                $vnetConfig.RWSubnetName = "dummy"
            }

            Set-VnetConfig  -vnetConfig $vnetConfig -setRWSubnet $false -reqCores $minCoresAddConn
        }
        else {
            # Populate from key vault

            Check-Location-Cores -rgLocation $rootLocation -neededCores $minCoresAddConn

            $secret = Get-AzureKeyVaultSecret `
                -VaultName $CAMRootKeyvault.Name `
                -Name "connectionServiceSubnet" `
                -ErrorAction stop
            if($secret.SecretValueText) {
                $connectionServiceSubnetSecret = $secret.SecretValueText
            } else {
                $connectionServiceSubnetSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
            }
            $vnetConfig.vnetID = ($connectionServiceSubnetSecret.split('/'))[0..8] -join '/'
            $vnetConfig.CSSubnetName = $connectionServiceSubnetSecret.split("/")[-1]

            $secret = Get-AzureKeyVaultSecret `
                -VaultName $CAMRootKeyvault.Name `
                -Name "gatewaySubnet" `
                -ErrorAction stop
            if($secret.SecretValueText) {
                $gatewaySubnetSecret = $secret.SecretValueText
            } else {
                $gatewaySubnetSecret = ConvertFrom-SecureString $secret.SecretValue -AsPlainText
            }
            $vnetConfig.GWSubnetName = $gatewaySubnetSecret.split("/")[-1]
        }
    }
        
    Write-Host "Deploying a new Cloud Access connector"

    New-ConnectionServiceDeployment `
        -RGName $ResourceGroupName `
        -subscriptionId $selectedSubcriptionId `
        -tenantId $selectedTenantId `
        -keyVault $CAMRootKeyvault `
        -testDeployment $testDeployment `
        -tempDir $tempDir `
        -enableExternalAccess $enableExternalAccess `
        -enableRadiusMfa $enableRadiusMfa `
        -radiusServerHost $radiusServerHost `
        -radiusServerPort $radiusServerPort `
        -radiusSharedSecret $radiusSharedSecret `
        -vnetConfig $vnetConfig `
        -camSaasUri $camSaasUri.Trim().TrimEnd('/') `
        -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate `
        -ownerTenantId $claims.tid `
        -ownerUpn $upn `
        -updateSPCredential:$updateSPCredential `
        -camManagementUserGroup $camManagementUserGroup `
        -brokerRetrieveAgentState $retrieveAgentState `
        -clientShowAgentState $showAgentState `
        -brokerCacheTimeoutSeconds $brokerCacheTimeoutSeconds `
        -brokerCacheSize $brokerCacheSize `
        -isBrokerCacheEnabled $isBrokerCacheEnabled `
        -Tag $tag
}
else {
    # New CAM deployment. 

    # EULA and Privacy Policy
    if( -not $ignorePrompts) {
        Write-Host "`nBy deploying Cloud Access Manager, you accept the terms of the Teradici Cloud Access Software End User License Agreement"
        Write-Host "http://www.teradici.com/eula/1609005 and Privacy Policy https://www.teradici.com/privacy-policy/cloud-access-manager"
        Write-Host "and have read and agree to be bound by the software license for use of the third-party drivers"

        $acceptEULA = (confirmDialog "Do you accept the policies and agreements?") -eq 'y'

        if(-not $acceptEULA) {
            exit 
        }
    }

    # Figure out if deploying over a current DC and vnet (in which case we know the location so don't need to prompt)

    if($deployOverDC -eq $null) {
        $deployOverDC = (confirmDialog "Do you want to connect to an existing domain?" -defaultSelected 'Y') -eq 'y'
    }

    if($deployOverDC) {
        # Don't create new DC and vnet - prompt for which vnet and subnets to use
        Set-VnetConfig -vnetConfig $vnetConfig -domainController $true
        $vnetLocation = (Get-AzureRmResource -ResourceId $vnetConfig.vnetID -ErrorAction Stop).Location

        if($location) {
            Write-Host-Warning "Overriding provided location of $location to $vnetLocation"
        }
        else {
            Write-Host "Using the virtual network location $vnetLocation"
        }
        $location = $vnetlocation
    }

    # Find the CAM root RG.
    $resourceGroups = Get-AzureRmResourceGroup

    # if a user has provided ResourceGroupName as parameter:
    # - Check if user group exists. If it does deploy there.
    # - If it doesn't, create it in which case location parameter must be provided 

    $rgIndex = 0
    ForEach ($r in $resourceGroups) {
        if (-not (Get-Member -inputobject $r -name "Number")) {
            Add-Member -InputObject $r -Name "Number" -Value "" -MemberType NoteProperty
        }

        $r.Number = ($rgIndex++) + 1
    }

    $selectedRGName = $false
    $rgIsInt = $false
    $rgMatch = $null
    while (-not $selectedRGName) {
        if($ResourceGroupName) {
            $rgIdentifier = $ResourceGroupName
        } else {
            Write-Host "`nAvailable Resource Groups"
            Write-Host ($resourceGroups | Select-Object -Property Number, ResourceGroupName, Location | Format-Table | Out-String)
            Write-Host ("`nSelect the root resource group of the new Cloud Access Manager deployment by number`n" +
            "or type in a new resource group name")
            $rgIdentifier = (Read-Host "Resource group").Trim()
        }

        $ResourceGroupName = $null # clear out parameter if passed to avoid infinite retry loop

        if (!$rgIdentifier) {
            Write-Host-Warning "Value not provided"
            continue       
        }

        $rgIndex = 0
        $rgIsInt = [int]::TryParse($rgIdentifier, [ref]$rgIndex) # rgIndex will be 0 on parse failure

        # If we are doing an existing domain controller deploy, it will only add the connection vms instead of the full set
        if($deployOverDC){
            $deployCost = $minCoresAddConn
        }else{
            $deployCost = $minCoresFullDeploy
        }

        if ($rgIsInt) {
            # entered an integer - we are not supporting integer names here for new resource groups
            $rgArrayLength = $resourceGroups.Length
            if ( -not (( $rgIndex -ge 1) -and ( $rgIndex -le $rgArrayLength))) {
                #invalid range 
                Write-Host-Warning "Please enter a range between 1 and $rgArrayLength or the name of a new resource group"
            }
            else {
                $rgMatch = $resourceGroups[$rgIndex - 1]
                
                Check-Location-Cores -rgLocation $rgMatch.Location -neededCores $deployCost
                $selectedRGName = $true
            }
            continue
        }
        else {
            # entered a name. Let's see if it matches any resource groups first
            $rgMatch = $resourceGroups | Where-Object {$_.ResourceGroupName -eq $rgIdentifier}
            if ($rgMatch) {
                
                Check-Location-Cores -rgLocation $rgMatch.Location -neededCores $deployCost
                $selectedRGName = $true
            }
            else {
                # make a new resource group and on failure go back to RG selection.
                $inputRgName = $rgIdentifier
                $newRgResult = $null

                $azureLocation = Get-AzureRMLocation
                $locations = @(($azureLocation | Select-Object Location).location) + @(($azureLocation | Select-Object DisplayName).Displayname)
                while ($true) {
                    if($location){
                        $newRGLocation = $location
                    }
                    else {
                        Write-Host("`nAvailable Azure Locations")
                        Write-Host ($azureLocation | Select-Object -Property Location, DisplayName | Format-Table | Out-String )
                        $newRGLocation = (Read-Host "`nEnter resource group location").Trim()
                    }
                    $location = $null # clear out parameter if passed to avoid infinite retry loop

                    if ($locations -Contains $newRGLocation){
                        break
                    }
                    Write-Host-Warning "$newRGLocation is not a valid location"
                }
                
                Check-Location-Cores  -rgLocation $newRGLocation -neededCores $deployCost
                Write-Host "Creating Cloud Access Manager root resource group $inputRgName"
                $newRgResult = New-AzureRmResourceGroup -Name $inputRgName -Location $newRGLocation -Tag $tag
                if ($newRgResult) {
                    # Success!
                    $selectedRGName = $true
                    $rgMatch = Get-AzureRmResourceGroup -Name $inputRgName
                }
            }
        }
    }


    Write-Host "Using root resource group: $($rgMatch.ResourceGroupName)"


    # At this point we have a subscription and a root resource group - check if there is already a deployment in it
    $CAMRootKeyvault = Get-AzureRmResource `
        -ResourceGroupName $rgMatch.ResourceGroupName `
        -ResourceType "Microsoft.KeyVault/vaults" `
        | Where-object {$_.Name -like "CAM-*"}

    if ($CAMRootKeyvault) {
        # Connector upgrades should have been caught above. If we got here they manually typed in a resource
        # group that already had a deployment. Abort.

        Write-Host "The selected resource group already has a CAM deployment, please select a different"
        Write-Host "resource group for a new Cloud Access Manager deployment"
        return   # early return!
    }

    # a new CAM deployment - check external access
    $externalAccessPrompt = "Do you want to enable external network access for your Cloud Access Manager deployment?"

    if ($enableExternalAccess -eq $null) {
        $enableExternalAccess = (confirmDialog $externalAccessPrompt -defaultSelected 'Y') -eq 'y'
    }

    if( -not $deployOverDC ) {

        # CAM in a box - create new DC and vnet. Default values are populated here if not provided on command line.
        if( -not $vnetConfig.vnetID ) {
            $vnetConfig.vnetID = "/subscriptions/$selectedSubcriptionId/resourceGroups/$($rgMatch.ResourceGroupName)/providers/Microsoft.Network/virtualNetworks/vnet-CloudAccessManager"
        }
        if( -not $vnetConfig.CSSubnetName ) {
            $vnetConfig.CSSubnetName = "CloudAccessConnectors"
        }
        if( -not $vnetConfig.GWSubnetName ) {
            $vnetConfig.GWSubnetName = "ApplicationGateways"
        }
        if( -not $vnetConfig.RWSubnetName ) {
            $vnetConfig.RWSubnetName = "RemoteWorkstations"
        }
    }

    # Now let's create the other required resource groups

    $csRGName = $rgMatch.ResourceGroupName + "-CN1"
    $rwRGName = $rgMatch.ResourceGroupName + "-RW"

    $csrg = Get-AzureRmResourceGroup -ResourceGroupName $csRGName -ErrorAction SilentlyContinue
    if($csrg)
    {
        # assume it's there for a reason? Alternately we could fail but...
        Write-Host "Using Cloud Access connector resource group $csRGName"
    }
    else {
        Write-Host "Creating Cloud Access connector resource group $csRGName"
        $csrg = New-AzureRmResourceGroup -Name $csRGName -Location $rgMatch.Location -ErrorAction Stop -Tag $tag
    }

    $rwrg = Get-AzureRmResourceGroup -ResourceGroupName $rwRGName -ErrorAction SilentlyContinue
    if($rwrg)
    {
        # assume it's there for a reason? Alternately we could fail but...
        Write-Host "Using remote workstation resource group $rwRGName"
    }
    else {
        Write-Host "Creating remote workstation resource group $rwRGName"
        $rwrg = New-AzureRmResourceGroup -Name $rwRGName -Location $rgMatch.Location -ErrorAction Stop -Tag $tag
    }


    # allow interactive input of a bunch of parameters. spCredential is handled in the SP functions elsewhere in this file

    do {
        if ( -not $domainName ) {
            if( -not $deployOverDC ) {
                $domainNameMessage = "`nEnter a new FQDN of the domain which will be created, including a '.' such as example.com"
            }
            else {
                $domainNameMessage = "`nEnter the FQDN of the domain which will be connected to by the Cloud Access Manager"
            }
            Write-Host $domainNameMessage
            $domainName = (Read-Host "Domain name").Trim()
        }

        # https://social.technet.microsoft.com/Forums/scriptcenter/en-US/db2d8388-f2c2-4f67-9f84-c17b060504e1/regex-for-computer-fqdn?forum=winserverpowershell
        if (-not $($domainName -imatch '(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)')) {
            Write-Host-Warning "Invalid domain name, please see https://support.microsoft.com/en-ca/help/909264/naming-conventions-in-active-directory-for-computers-domains-sites-and for valid domain names"
            $domainName = $null
            continue
        }

        # Must have a dot
        if (-not $($domainName -imatch '\.')) {
            Write-Host-Warning "The name must include a '.' such as example.com"
            $domainName = $null
        }

    } while (-not $domainName)

    # Username
    $username = $null
    if ($domainAdminCredential) {
        $username = $domainAdminCredential.UserName
    }
    do {
        # prompted if username is not provided
        if ( -not $username) {
            if( -not $deployOverDC ) {
                $domainAdminMessage = "Enter the new domain administrator username for the new domain being created"
            }
            else {
                $domainAdminMessage = "Enter the service account username for `"$domainName`" to be used by Cloud Access Manager"
            }
            $username = (Read-Host $domainAdminMessage).Trim()
        }

        # only check if it is not deployOverDC
        if (-not $deployOverDC) {
            if ((-not ($username -imatch '^[A-Za-z\d]+(?:[\._-][A-Za-z\d]+)*$')) -or ($username.Length -gt 64)) {
                Write-Host-Warning "Please enter a valid username, it can only contain letters and numbers and cannot be longer than 64 characters"
                $username = $null
                continue
            }
            # reserved usernames
            # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/faq
            $reservedUsername = @('administrator', 'admin', 'user', 'user1', 'test', 'user2', 'test1', 'user3', 'admin1', '1', '123', 'a',
                                  'actuser', 'adm', 'admin2', 'aspnet', 'backup', 'console', 'david', 'guest', 'john', 'owner', 'root', 'server',
                                  'sql', 'support', 'support_388945a0', 'sys', 'test2', 'test3', 'user4', 'user5' )
            
            if ($username -in $reservedUsername) {
                Write-Host-Warning "$username is a reserved username, please try again"
                $username = $null
                continue                
            }
        }
        break
    } while ( $true )

    # Password
    $password = $null
    if ($domainAdminCredential) {
        $password = $domainAdminCredential.GetNetworkCredential().Password
    }
    do {
        if ( -not $password ) {
            if( -not $deployOverDC ) {
                Write-Host "`nEnter the password for the new domain administrator"
                Write-Host "It must be a minimum of 12 characters long, it must not contain the username"
                Write-Host "and it must contain at least three of the following categories:"
                Write-Host "Uppercase letters, lowercase letters, digits, and symbols`n"

                $pawdMessage = "Enter the domain administrator password"
            }
            else {
                $pawdMessage = "Enter the service account password"
            }


            $psw = Read-Host -AsSecureString $pawdMessage
            $password = ConvertTo-Plaintext $psw
        }

        # Don't check password if deploying over DC since in that case it's the DC's password complexity rules.
        if (-not $deployOverDC ) {
            if (-not (Test-PasswordComplexity $username $password)) {
                $password = $null
                continue
            }
        }

        if ($psw) {
            if( -not $deployOverDC ) {
                $pawdMessage = "Re-enter the domain administrator password"
            }
            else {
                $pawdMessage = "Re-enter the service account password"
            }
            $confirmedPassword = Read-Host -AsSecureString $pawdMessage
            $clearConfirmedPassword = ConvertTo-Plaintext $confirmedPassword
            if (-not ($password -ceq $clearConfirmedPassword)) {
                Write-Host-Warning "Entered passwords do not match, try again"
                $password = $null
                continue
            }
        }
        break
    } while ( $true )

    $secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
    $domainAdminCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)

    # Load provided RADIUS Configuration Parameters (Some of these may be $null at this point)
    $radiusConfig = @{
        enableRadiusMfa = $enableRadiusMfa
        radiusServerHost = $radiusServerHost
        radiusServerPort = $radiusServerPort 
        radiusSharedSecret = $radiusSharedSecret
    }

    do {
        if ($camManagementUserGroup -eq $null -and (-not $ignorePrompts)) {
            $camManagementUserGroup = Read-Host "Enter the Distinguished Name for the User Group to log into the CAM Management Interface. Default is 'Domain Admins'. (eg, 'CN=CAM Admins,CN=Users,DC=example,DC=com')"
            if(-not $camManagementUserGroup) {
                $camManagementUserGroup = "Domain Admins"
                break
            }
        } elseif (-not $camManagementUserGroup -and $ignorePrompts) {
            $camManagementUserGroup = "Domain Admins"
            break
        }
        if( -not ($camManagementUserGroup.Contains("DC=") -and $camManagementUserGroup.Contains("CN=")))
        {
            Write-Host "Speicifed Distinguished Name is not valid"
            $camManagementUserGroup=$null
        }
    } while ($camManagementUserGroup -eq $null)

    # Prompt for RADIUS configuration if RADIUS has not been already explicitly been disabled
    if ( -not ($enableRadiusMfa -eq $false) ) {
        # Prompt for whether to enable RADIUS integration
        if ( $enableRadiusMfa -eq $null -and (-not $ignorePrompts) ) {
            $enableRadiusMfa = (confirmDialog "Do you want to enable Multi-Factor Authentication using your RADIUS Server?") -eq 'y'
        } elseif ( $enableRadiusMfa -eq $null -and $ignorePrompts ) {
            $enableRadiusMfa = $false
        }

        if ( $enableRadiusMfa -and (-not $enableExternalAccess)) {
            Write-Error "Multi-Factor Authentication for internal deployments is not supported"
            exit
        }

        if ($enableRadiusMfa) {
            do {
                if (-not $radiusConfig.radiusServerHost ) {
                    $radiusConfig.radiusServerHost = (Read-Host "Enter your RADIUS Server's Hostname or IP").Trim()
                }
            } while (-not $radiusConfig.radiusServerHost)

            do {
                if (-not $radiusConfig.radiusServerPort ) {
                    $radiusPort = 0
                    $portString = (Read-Host  "Enter your RADIUS Server's Listening port")
                    [int]::TryParse($portString, [ref]$radiusPort) | Out-Null # radiusPort will be 0 on parse failure
                    $radiusConfig.radiusServerPort = $radiusPort
                }
                if ( ($radiusConfig.radiusServerPort -le 0) -or ($radiusConfig.radiusServerPort -gt 65535) ) {
                    Write-Host-Warning "Entered port is invalid, it should be between 1 and 65535"
                    $radiusConfig.radiusServerPort = $null
                }
            } while (-not $radiusConfig.radiusServerPort )

            do {
                if (-not $radiusConfig.radiusSharedSecret ) {
                    $radiusConfig.radiusSharedSecret = Read-Host -AsSecureString "Enter your RADIUS Server's Shared Secret"
                }
            } while (-not $radiusConfig.radiusSharedSecret )
        }
    }    
    if ( -not $enableRadiusMfa) {
        # Set a default value if not set already
        $radiusConfig.enableRadiusMfa = $false
        if (-not $radiusConfig.radiusSharedSecret ) {
            $radiusConfig.radiusSharedSecret = ConvertTo-SecureString "radiusSecret" -AsPlainText -Force
        }
        if (-not $radiusConfig.radiusServerPort ) {
            $radiusConfig.radiusServerPort = 1812
        }
        if (-not $radiusConfig.radiusServerHost ) {
            $radiusConfig.radiusServerHost = "radiusServer"
        }
    } else {
        # Make sure this is boolean
        $radiusConfig.enableRadiusMfa = $true
    }

    do {
        if (-not $registrationCode ) {
            $registrationCode = (Read-Host -AsSecureString "Enter your Cloud Access registration code")
        }

        # Need plaintext registration code to check length
        $clearRegCode = ConvertTo-Plaintext $registrationCode
        if ($clearRegCode.Length -lt 21) {
            #too short- try again.
            Write-Host-Warning "The registration code is at least 21 characters long"
            $registrationCode = $null
        }
    } while (-not $registrationCode )

    
    Deploy-CAM `
        -domainAdminCredential $domainAdminCredential `
        -domainName $domainName `
        -registrationCode $registrationCode `
        -camSaasUri $camSaasUri.Trim().TrimEnd('/') `
        -verifyCAMSaaSCertificate $verifyCAMSaaSCertificate `
        -CAMDeploymentTemplateURI $CAMDeploymentTemplateURI `
        -binaryLocation $binaryLocation.Trim().TrimEnd('/') `
        -outputParametersFileName $outputParametersFileName `
        -subscriptionId $selectedSubcriptionId `
        -RGName $rgMatch.ResourceGroupName `
        -csRGName $csRGName `
        -rwRGName $rwRGName `
        -spCredential $spCredential `
        -tenantId $selectedTenantId `
        -testDeployment $testDeployment `
        -certificateFile $certificateFile `
        -certificateFilePassword $certificateFilePassword `
        -AgentChannel $AgentChannel `
        -deployOverDC $deployOverDC `
        -radiusConfig $radiusConfig `
        -vnetConfig $vnetConfig `
        -ownerTenantId $claims.tid `
        -ownerUpn $upn `
        -enableExternalAccess $enableExternalAccess `
        -domainControllerOsType $domainControllerOsType `
        -defaultIdleShutdownTime $defaultIdleShutdownTime `
        -camUserGroup $camUserGroup `
        -camManagementUserGroup $camManagementUserGroup `
        -brokerRetrieveAgentState $retrieveAgentState `
        -clientShowAgentState $showAgentState `
        -brokerCacheTimeoutSeconds $brokerCacheTimeoutSeconds `
        -brokerCacheSize $brokerCacheSize `
        -isBrokerCacheEnabled $isBrokerCacheEnabled `
        -AzureSPObjectId $AzureSPObjectId `
        -Tag $tag
}
