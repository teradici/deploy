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
#
# Install-ConnectionServer.ps1
# Compile to a local .zip file via this command:
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-ConnectionServer.ps1 -ConfigurationArchivePath .\Install-CAM.ps1.zip
# And then push to GitHUB.
#
# Or to push to Azure Storage:
#
# example:
#
# $StorageAccount = 'teradeploy'
# $StorageKey = '<put key here>'
# $StorageContainer = 'binaries'
# 
# $StorageContext = New-AzureStorageContext -StorageAccountName $StorageAccount -StorageAccountKey $StorageKey
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-ConnectionServer.ps1  -ContainerName $StorageContainer -StorageContext $StorageContext
#
#
Configuration InstallConnectionServer
{
    # One day pull from Oracle as per here? https://github.com/gregjhogan/cJre8/blob/master/DSCResources/cJre8/cJre8.schema.psm1
    param
    (
        [string]
        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPCAMInstall",

        [Parameter(Mandatory)]
        [String]$sourceURI,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$CAMDeploymentInfo,

        [string]
        $javaInstaller = "jdk-8u144-windows-x64.exe",

        [string]
        $openSSL = "Win64OpenSSL_Light-1_0_2o.exe",

        [string]
        $sumoConf = "sumo.conf",

        [string]
        $tomcatInstaller = "apache-tomcat-8.5.23-windows-x64.zip",

        [string]
        $brokerWAR = "pcoip-broker.war",

        [string]
        $adminWAR = "CloudAccessManager.war",

        [string]
        $agentARM = "server2016-standard-agent.json",

        [string]
        $gaAgentARM = "server2016-graphics-agent.json",

        [string]
        $linuxAgentARM = "rhel-standard-agent.json",

        [Parameter(Mandatory)]
        [String]$domainName,

        [Parameter(Mandatory)]
        [String]$remoteWorkstationDomainGroup,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$DomainAdminCreds,

        [Parameter(Mandatory)]
        [String]$gitLocation,

        [Parameter(Mandatory)]
        [String]$sumoCollectorID,

        [Parameter(Mandatory=$false)]
        [String]$brokerPort = "8444",

        [Parameter(Mandatory = $false)]
        [String]$enableRadiusMfa,

        [bool] $brokerRetrieveAgentState = $true,
        [bool] $clientShowAgentState = $true,

        [Parameter(Mandatory = $false)]
        [bool] $isBrokerCacheEnabled = $false,
    
        [Parameter(Mandatory = $false)]
        [int] $brokerCacheSize,
    
        [Parameter(Mandatory = $false)]
        [int] $brokerCacheTimeoutSeconds
    )

    # Get DC information
    # The alternate way is to do a nslookup for the dns srv record for: _ldap._tcp.dc._msdcs.<DOMAIN>

    Write-Host "Looking for domain controllers found for domain $domainName"
    
    $adminUsername = $DomainAdminCreds.GetNetworkCredential().Username
    $adminPassword = $DomainAdminCreds.GetNetworkCredential().Password

    $directoryContext = new-object 'System.DirectoryServices.ActiveDirectory.DirectoryContext' `
        ("domain", $domainName, $adminUsername, $adminPassword)
    $dcs = [System.DirectoryServices.ActiveDirectory.DomainController]::FindAll($directoryContext)
   
    if($dcs.Count) {
        Write-Host "Number of domain controllers found: $($dcs.Count)"
    }
    else {
        throw "No domain controllers found for domain $domainName"
    }

    $dcvmfqdn = $dcs[0].Name
    Write-Host "Using domain controller: $dcvmfqdn"

    $pbvmfqdn = "$env:computername"
    $family   = "Windows Server 2016"

    #Java locations
    $JavaRootLocation = "$env:systemdrive\Program Files\Java\jdk1.8.0_144"
    $JavaBinLocation = $JavaRootLocation + "\bin"
    $JavaLibLocation = $JavaRootLocation + "\jre\lib"

    #Tomcat locations
    $localtomcatpath = "$env:systemdrive\tomcat"
    $CatalinaHomeLocation = "$localtomcatpath\apache-tomcat-8.5.23"
    $CatalinaBinLocation = $CatalinaHomeLocation + "\bin"

    $brokerServiceName = "CAMBroker"
    $AUIServiceName = "CAMAUI"

    # CAM Deployment Info
    Add-Type -AssemblyName System.Web
    $CAMDeploymentInfoJSONDecoded = [System.Web.HttpUtility]::UrlDecode( `
        $CAMDeploymentInfo.GetNetworkCredential().Password)
    $CAMDeploymentInfoDecoded = ConvertFrom-Json $CAMDeploymentInfoJSONDecoded

    # Retry for CAM Registration
    $retryCount = 3
    $delay = 10
    $orderNumArray = @('1st', '2nd', '3rd')
   
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

        xRemoteFile Download_Sumo_Conf 
        {
                Uri = "$gitLocation/$sumoConf"
                DestinationPath = "$LocalDLPath\$sumoConf"
                MatchSource = $false
        }

        xRemoteFile Download_OpenSSL
        {
                Uri = "$sourceURI/$openSSL"
                DestinationPath = "$LocalDLPath\$openSSL"
                MatchSource = $false
        }

        File Sumo_Directory 
        {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = "C:\sumo"
        }

        # Aim to install the collector first and start the log collection before any 
        # other applications are installed.
        Script Install_SumoCollector
        {
            DependsOn  = @("[xRemoteFile]Download_Sumo_Conf","[File]Sumo_Directory")
            GetScript  = { @{ Result = "Install_SumoCollector" } }

            TestScript = { 
                return Test-Path "C:\sumo\$using:sumoConf" -PathType leaf
                }

            SetScript  = {
                Write-Verbose "Install_SumoCollector"

                $dest = "C:\sumo"
                $installerFileName = "SumoCollector.exe"

                $sourceArray = @()
                $destArray = @()

                $sourceArray += "$using:gitLocation/$using:sumoConf"
                $destArray += "$dest\$using:sumoConf"

                $sourceArray += "$using:gitLocation/sumo-admin-vm.json"
                $destArray += "$dest\sumo-admin-vm.json"

                $sourceArray += "https://collectors.sumologic.com/rest/download/win64"
                $destArray += "$dest\$installerFileName"

                $orderNumArray = $using:orderNumArray
                $retryMax = $using:retryCount
                $downIdx = 0;
                # sumologic server require TLS 1.2
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                foreach ($source in $sourceArray) {
                    $destFile = $destArray[$downIdx]

                    for ($idx = 0; $idx -lt $retryMax; $idx++) {
                        Write-Verbose ('It is the {0} try downloading file from {1} ...' -f $orderNumArray[$idx], $source)
                        Try{
                            Invoke-WebRequest $source -OutFile $destFile -UseBasicParsing -PassThru  -ErrorAction Stop
                            break
                        }Catch{
                            $errMsg = "Attempt {0} of {1} to download file from {2} failed. Error Infomation: {3} " -f ($idx + 1), $retryMax, $source, $_.Exception.Message 
                            Write-Verbose $errMsg
                            if ($idx -ne ($retryMax - 1)) {
                                Start-Sleep -s $using:delay
                            } else {
                                $errMsg = "Failed to install sumo collector because file {0} could not be downloaded" -f $source
                                Write-Verbose $errMsg
                                return                                 
                            }
                        }
                    }

                    $downIdx += 1
                }

                # Insert unique ID
                $collectorID = "$using:sumoCollectorID"
                $destConf = "$dest\$using:sumoConf"
                Write-Host "Insert collector unique ID: $collectorID"
                (Get-Content -Path $destConf).Replace("collectorID", $collectorID) | Set-Content -Path $destConf
                
                # Install the collector
                Write-Host "Installing the collector"
                $command = "$dest\$installerFileName -console -q"
                Invoke-Expression $command

                # Wait for collector to be installed before exiting this configuration.
                $retryCount = 1800
                while ($retryCount -gt 0)
                {
                    try
                    {
                        Get-Service sumo-collector -ErrorAction Stop
                        break
                    }
                    catch
                    {
                        Start-Sleep -s 1;
                        $retryCount = $retryCount - 1;
                        if ( $retryCount -eq 0)
                        {
                            throw "Sumo collector not installed in time."
                        }
                        else
                        {
                            Write-Host "Waiting for Sumo collector to be installed"
                        }
                    }
                }
            }
        }
        #
        # One day can split this to 'install java' and 'configure java environemnt' and use 'package' dsc like here:
        # http://stackoverflow.com/questions/31562451/installing-jre-using-powershell-dsc-hangs
        Script Install_Java
        {
            DependsOn  = "[xRemoteFile]Download_Java_Installer"
            GetScript  = { @{ Result = "Install_Java" } }

            #TODO: Just check for a directory being present? What to do when Java version changes? (Can also check registry key as in SetScript.)
            TestScript = {
                return Test-Path "$using:JavaBinLocation"
            }
            SetScript  = {
                Write-Verbose "Install_Java"

                # Run the installer. Start-Process does not work due to permissions issue however '&' calling will not wait so looks for registry key as 'completion.'
                # Start-Process $LocalDLPath\$javaInstaller -ArgumentList '/s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"' -Wait
                & "$using:LocalDLPath\$using:javaInstaller" /s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"

                $retrycount = 1800
                while ($retryCount -gt 0)
                {
                    $readyToConfigure = ( Get-Item "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F64180144F0}"    -ErrorAction SilentlyContinue )
                    # don't wait for {64A3A4F4-B792-11D6-A78A-00B0D0180144} - that's the JDK. The JRE is installed 2nd {26A...} so wait for that.

                    if ($readyToConfigure)
                    {
                        break   #success
                    }
                    else
                    {
                        Start-Sleep -s 1;
                        $retrycount = $retrycount - 1;
                        if ( $retrycount -eq 0)
                        {
                            throw "Java not installed in time."
                        }
                        else
                        {
                            Write-Host "Waiting for Java to be installed"
                        }
                    }
                }

                Write-Host "Setting up Java paths and environment"

                #set path. Don't add strings that are already there...

                $NewPath = $env:Path
                if ($NewPath -notlike "*"+$using:JavaBinLocation+"*")
                {
                    #put java path in front of the Oracle defined path
                    $NewPath= $using:JavaBinLocation + ";" + $NewPath
                }

                [System.Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
                [System.Environment]::SetEnvironmentVariable("JAVA_HOME", $using:JavaRootLocation, "Machine")
                [System.Environment]::SetEnvironmentVariable("classpath", $using:JavaLibLocation, "Machine")
                $env:Path = $NewPath
                $env:JAVA_HOME = $using:JavaRootLocation
                $env:classpath = $using:JavaLibLocation


                Write-Host "Waiting for JVM.dll"
                $JREHome = $using:JavaRootLocation + "\jre"
                $JVMServerdll = $JREHome + "\bin\server\jvm.dll"

                $retrycount = 1800
                while ($retryCount -gt 0)
                {
                    $readyToConfigure = ( Get-Item $JVMServerdll -ErrorAction SilentlyContinue )

                    if ($readyToConfigure)
                    {
                        break   #success
                    }
                    else
                    {
                        Start-Sleep -s 1;
                        $retrycount = $retrycount - 1;
                        if ( $retrycount -eq 0)
                        {
                            throw "JVM.dll not installed in time."
                        }
                        else
                        {
                            Write-Host "Waiting for JVM.dll to be installed"
                        }
                    }
                }

                # Reboot machine - seems to need to happen to get Tomcat to install??? Perhaps not after environment fixes. Needs testing.
                $global:DSCMachineStatus = 1
            }
        }

        Script Install_Tomcat
        {
            DependsOn = @("[xRemoteFile]Download_Tomcat_Installer", "[Script]Install_Java", "[xRemoteFile]Download_Keystore")
            GetScript  = { @{ Result = "Install_Tomcat" } }

            TestScript = { 
                if ( $env:CATALINA_HOME )
                {
                    return $true
                }
                else
                {
                    return $false
                }
            }
            SetScript  = {
                Write-Verbose "Install_Tomcat"

                #just going 'manual' now since installer has been a massive PITA
                #(but perhaps unfairly so since it might have been affected by some Java install issues I had previously as well.)

                $LocalDLPath = $using:LocalDLPath
                $tomcatInstaller = $using:tomcatInstaller
                $localtomcatpath = $using:localtomcatpath
                $CatalinaHomeLocation = $using:CatalinaHomeLocation
                $CatalinaBinLocation = $using:CatalinaBinLocation

                #make sure we get a clean install
                Remove-Item $localtomcatpath -Force -Recurse -ErrorAction SilentlyContinue

                Expand-Archive "$LocalDLPath\$tomcatInstaller" -DestinationPath $localtomcatpath


                Write-Host "Setting Paths and Tomcat environment"

                $NewPath = $env:Path
                if ($NewPath -notlike "*"+$CatalinaBinLocation+"*")
                {
                    #put tomcat path at the end
                    $NewPath= $NewPath + ";" + $CatalinaBinLocation
                }

                [System.Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
                [System.Environment]::SetEnvironmentVariable("CATALINA_HOME", $CatalinaHomeLocation, "Machine")
                $env:Path = $NewPath
                $env:CATALINA_HOME = $CatalinaHomeLocation
            }
        }

        Script Setup_AUI_Service
        {
            DependsOn = @("[Script]Install_Tomcat", "[xRemoteFile]Download_Keystore")
            GetScript  = { @{ Result = "Setup_AUI_Service" } }

            TestScript = {
                return !!(Get-Service $using:AUIServiceName -ErrorAction SilentlyContinue)
            }

            SetScript = {

                Write-Host "Configuring Tomcat for $using:AUIServiceName service"

                $catalinaHome = $using:CatalinaHomeLocation
                $catalinaBase = "$catalinaHome" #\$using:AUIServiceName" <---- don't change this without changing log collector location currently in sumo-admin-vm.json

                $env:CATALINA_BASE = $catalinaBase

                # make new instance location - copying the directories specified
                # here: https://tomcat.apache.org/tomcat-8.0-doc/windows-service-howto.html

                # clear out any old cruft first
#                Remove-Item "$catalinaBase" -Force -Recurse -ErrorAction SilentlyContinue
#                Copy-Item "$catalinaHome\conf" "$catalinaBase\conf" -Recurse -ErrorAction SilentlyContinue
#                Copy-Item "$catalinaHome\logs" "$catalinaBase\logs" -Recurse -ErrorAction SilentlyContinue
#                Copy-Item "$catalinaHome\temp" "$catalinaBase\temp" -Recurse -ErrorAction SilentlyContinue
#                Copy-Item "$catalinaHome\webapps" "$catalinaBase\webapps" -Recurse -ErrorAction SilentlyContinue
#                Copy-Item "$catalinaHome\work" "$catalinaBase\work" -Recurse -ErrorAction SilentlyContinue

                $serverXMLFile = $catalinaBase + '\conf\server.xml'
                $origServerXMLFile = $catalinaBase + '\conf\server.xml.orig'

                # back up server.xml file if not done in a previous round
                if( -not ( Get-Item ($origServerXMLFile) -ErrorAction SilentlyContinue ) )
                {
                    Copy-Item -Path ($serverXMLFile) `
                        -Destination ($origServerXMLFile)
                }

                #update server.xml file
                $xml = [xml](Get-Content ($origServerXMLFile))

                # port 8080 unencrypted connector - is there by default
                #$unencConnector = [xml] ('<Connector port="8080" protocol="HTTP/1.1" connectionTimeout="20000" redirectPort="8443" />')

                #$xml.Server.Service.InsertBefore(
                    # new child
                #    $xml.ImportNode($unencConnector.Connector,$true),
                    #ref child
                #    $xml.Server.Service.Engine )

                $NewConnector = [xml] ('<Connector
                    port="8443"
                    protocol="org.apache.coyote.http11.Http11NioProtocol"
                    SSLEnabled="true"
                    keystoreFile="'+$using:LocalDLPath+'\.keystore"
                    maxThreads="2000" scheme="https" secure="true"
                    clientAuth="false" sslProtocol="TLS"
                    SSLEngine="on" keystorePass="changeit"
                    SSLPassword="changeit"
                    sslEnabledProtocols="TLSv1.0,TLSv1.1,TLSv1.2"
                    ciphers="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA"
                    />')

                # port 8443 encrypted connector 

                $xml.Server.Service.InsertBefore(
                    # new child
                    $xml.ImportNode($NewConnector.Connector,$true),
                    #ref child
                    $xml.Server.Service.Engine )

                $xml.save($ServerXMLFile)



                Write-Host "Opening port 8443 and 8080"

                #open port in firewall
                netsh advfirewall firewall add rule name="Tomcat Port 8443" dir=in action=allow protocol=TCP localport=8443
                netsh advfirewall firewall add rule name="Tomcat Port 8080" dir=in action=allow protocol=TCP localport=8080


                # Install and set service to start automatically

                & "$using:CatalinaBinLocation\service.bat" install $using:AUIServiceName
                Write-Host "Tomcat Installer exit code: $LASTEXITCODE"
                Start-Sleep -s 10  #TODO: Is this sleep ACTUALLY needed?

                Write-Host "Starting Tomcat Service for $using:AUIServiceName"
                Set-Service $using:AUIServiceName -startuptype "automatic"
            }
        }

        Script Install_AUI
        {
            DependsOn  = @("[xRemoteFile]Download_Admin_WAR",
                           "[Script]Setup_AUI_Service")

            GetScript  = { @{ Result = "Install_AUI" } }

            TestScript = {
                $CatalinaHomeLocation = $using:CatalinaHomeLocation
                $catalinaBase = "$CatalinaHomeLocation" # \$using:AUIServiceName"
                $WARPath = "$catalinaBase\webapps\$using:adminWAR"

                return Test-Path $WARPath -PathType Leaf
            }

            SetScript  = {
                $LocalDLPath = $using:LocalDLPath
                $adminWAR = $using:adminWAR
                $localtomcatpath = $using:localtomcatpath
                $CatalinaHomeLocation = $using:CatalinaHomeLocation
                $catalinaBase = "$CatalinaHomeLocation" #\$using:AUIServiceName"

                Write-Verbose "Ensure Nuget Package Provider and AzureRM module are installed"

                If(-not [bool](Get-PackageProvider -ListAvailable | where {$_.Name -eq "NuGet"}))
                {
                    Write-Verbose "Installing NuGet"
                    Install-packageProvider -Name NuGet -Force
                }

                If(-not [bool](Get-InstalledModule | where {$_.Name -eq "AzureRM"}))
                {
                    Write-Verbose "Installing AzureRM"
                    Install-Module -Name AzureRM -MaximumVersion 4.4.1 -Force
                }

                Write-Verbose "Install_CAM"

                Copy-Item "$LocalDLPath\$adminWAR" ($catalinaBase + "\webapps")

                $svc = Get-Service $using:AUIServiceName
                if ($svc.Status -ne "Stopped") {$svc.stop()}

                Write-Host "Re-generating CAM configuration file."

                #Now create the new output file.
                #TODO - really only a couple parameters are used and set properly now. Needs cleanup.
                $domainsplit = $using:domainName
                $domainsplit = $domainsplit.split(".".2)
                $domainleaf = $domainsplit[0]  # get the first part of the domain name (before .local or .???)
                $domainroot = $domainsplit[1]  # get the second part of the domain name
                $date = Get-Date
                $domainControllerFQDN = $using:dcvmfqdn
                $regInfo = $using:camDeploymentInfoDecoded.RegistrationInfo
                $remoteWorkstationResourceGroup = $regInfo.CAM_RESOURCEGROUP

                $auProperties = @"
#$date
cn=Users
dom=$domainleaf
dcDomain = $domainleaf
dc=$domainroot
adServerHostAddress=$domainControllerFQDN
resourceGroupName=$remoteWorkstationResourceGroup
CAMSessionTimeoutMinutes=480
domainGroupAppServersJoin="$using:remoteWorkstationDomainGroup"
ldapHost=ldaps://$domainControllerFQDN
"@

                $targetDir = "$CatalinaHomeLocation\adminproperty"
                $configFileName = "$targetDir\config.properties"

                if(-not (Test-Path $targetDir))
                {
                    New-Item $targetDir -type directory
                }

                if(-not (Test-Path $configFileName))
                {
                    New-Item $configFileName -type file
                }

                Set-Content $configFileName $auProperties -Force
                Write-Host "CAM configuration file re-generated."

                Write-Host "Redirecting ROOT to Cloud Access Manager."

                $redirectString = '<%response.sendRedirect("CloudAccessManager/login.jsp");%>'
                $targetDir = "$CatalinaBase\webapps\ROOT"
                $indexFileName = "$targetDir\index.jsp"

                if(-not (Test-Path $targetDir))
                {
                    New-Item $targetDir -type directory
                }

                if(-not (Test-Path $indexFileName))
                {
                    New-Item $indexFileName -type file
                }

                Set-Content $indexFileName $redirectString -Force

            }
        }

        Script Install_Auth_file
        {
            DependsOn  = @("[Script]Install_AUI")

            GetScript  = { @{ Result = "Install_Auth_file" } }

            TestScript = {
                $targetDir = "$env:CATALINA_HOME\adminproperty"
                $authFilePath = "$targetDir\authfile.txt"
 
                return Test-Path $authFilePath -PathType Leaf
            }
            SetScript  = {


                Write-Host "Writing auth file."

                # Auth file format as documented here: https://github.com/Azure/azure-sdk-for-java/blob/master/AUTH.md
                Add-Type -AssemblyName System.Web
                $authFileContent = [System.Web.HttpUtility]::UrlDecode($using:CAMDeploymentInfoDecoded.AzureAuthFile)
                $targetDir = "$env:CATALINA_HOME\adminproperty"
                $authFilePath = "$targetDir\authfile.txt"

                if(-not (Test-Path $authFilePath))
                {
                    New-Item $authFilePath -type file
                }

                Set-Content $authFilePath $authFileContent -Force


                Write-Host "Update environment so AZURE_AUTH_LOCATION points to auth file."

                [System.Environment]::SetEnvironmentVariable("AZURE_AUTH_LOCATION", $authFilePath, "Machine")
                $env:AZURE_AUTH_LOCATION = $authFilePath


                ################################

                #login to Azure and get storage context so we can pull the right files out of the blob storage

                $regInfo = $using:camDeploymentInfoDecoded.RegistrationInfo

                $spName = $regInfo.CAM_USERNAME
                $spPass = ConvertTo-SecureString $regInfo.CAM_PASSWORD -AsPlainText -Force
                $tenantID = $regInfo.CAM_TENANTID

                Write-Host "Logging in SP $spName with tenantID $tenantID"

                $spCreds = New-Object -TypeName pscredential -ArgumentList  $spName, $spPass

                Add-AzureRmAccount `
                    -ServicePrincipal `
                    -Credential $spCreds `
                    -TenantId $tenantID `
                    -ErrorAction Stop

                # Now get Keyvault Secrets
                $kvName = $regInfo.CAM_KEY_VAULT_NAME
                $saSecretName = $regInfo.CAM_USER_STORAGE_ACCOUNT_NAME
                $sakeySecretName = $regInfo.CAM_USER_STORAGE_ACCOUNT_KEY

                $container_name = "cloudaccessmanager"
                $storageAccount = Get-AzureKeyVaultSecret -VaultName $kvName -Name $saSecretName
                $storageAccountKey = Get-AzureKeyVaultSecret -VaultName $kvName -Name $sakeySecretName

                $ctx = New-AzureStorageContext `
                    -StorageAccountName $storageAccount.SecretValueText `
                    -StorageAccountKey $storageAccountKey.SecretValueText

                Write-Host "Creating default template parameters files"

                #now make the default parameters filenames - same root name but different suffix as the templates
                $agentARM = $using:agentARM
                $gaAgentARM = $using:gaAgentARM
                $linuxAgentARM = $using:linuxAgentARM

                Write-Host "Pulling in Agent machine deployment templates."

                $templateLoc = "$using:CatalinaHomeLocation\ARMtemplateFiles"
                
                if(-not (Test-Path $templateLoc))
                {
                    New-Item $templateLoc -type directory
                }

                #clear out whatever was stuffed in from the deployment WAR file
                Remove-Item "$templateLoc\*" -Recurse
                

                $agentARMparam = ($agentARM.split('.')[0]) + ".customparameters.json"
                $gaAgentARMparam = ($gaAgentARM.split('.')[0]) + ".customparameters.json"
                $linuxAgentARMparam = ($linuxAgentARM.split('.')[0]) + ".customparameters.json"

                $ParamTargetDir = $using:CatalinaHomeLocation + "\ARMParametertemplateFiles"
                $ParamTargetFilePath = "$ParamTargetDir\$agentARMparam"
                $GaParamTargetFilePath = "$ParamTargetDir\$gaAgentARMparam"
                $LinuxParamTargetFilePath = "$ParamTargetDir\$linuxAgentARMparam"
                $ARMTargetFilePath = "$templateLoc\$agentARM"
                $GaARMTargetFilePath = "$templateLoc\$gaAgentARM"
                $linuxARMTargetFilePath = "$templateLoc\$linuxAgentARM"

                if(-not (Test-Path $ParamTargetDir))
                {
                    New-Item $ParamTargetDir -type directory
                }

                #clear out whatever was stuffed in from the deployment WAR file
                Remove-Item "$ParamTargetDir\*" -Recurse

                $ARMFiles = @(
                    $ParamTargetFilePath,
                    $GaParamTargetFilePath,
                    $LinuxParamTargetFilePath,
                    $ARMTargetFilePath,
                    $GaARMTargetFilePath,
                    $linuxARMTargetFilePath
                )


                # download the files from the blob

                ForEach($item in $ARMFiles) {
                    $targetpath = $item
                    $filename = Split-Path $targetpath -leaf
                    $sourcepath = "remote-workstation-template/$filename"

                    Write-Host "Downloading $sourcepath from blob container $container_name.."
                    Get-AzureStorageBlobContent `
                        -Destination $targetpath `
                        -Container $container_name `
                        -Blob $sourcepath `
                        -Context $ctx
                }

                Write-Host "Finished Creating default template parameters file data."
            }
        }

        Script Setup_Broker_Service
        {
            DependsOn = @("[Script]Install_Tomcat", "[xRemoteFile]Download_Keystore")
            GetScript  = { @{ Result = "Setup_Broker_Service" } }

            TestScript = {
                return !!(Get-Service $using:brokerServiceName -ErrorAction SilentlyContinue)
            }
            SetScript  = {
                Write-Host "Configuring Tomcat for $using:brokerServiceName service"

                $catalinaHome = $using:CatalinaHomeLocation
                $catalinaBase = "$catalinaHome\$using:brokerServiceName"

                #set the current (temporary) environment
                $env:CATALINA_BASE = $catalinaBase

                # make new broker instance location - copying the directories specified
                # here: https://tomcat.apache.org/tomcat-8.0-doc/windows-service-howto.html

                # clear out any old cruft first
                Remove-Item "$catalinaBase" -Force -Recurse -ErrorAction SilentlyContinue
                Copy-Item "$catalinaHome\conf" "$catalinaBase\conf" -Recurse -ErrorAction SilentlyContinue
                Copy-Item "$catalinaHome\logs" "$catalinaBase\logs" -Recurse -ErrorAction SilentlyContinue
                Copy-Item "$catalinaHome\temp" "$catalinaBase\temp" -Recurse -ErrorAction SilentlyContinue
                Copy-Item "$catalinaHome\work" "$catalinaBase\work" -Recurse -ErrorAction SilentlyContinue

                # Make empty webapps directory if it does not exist. 
                New-Item -ItemType Directory -Force -Path "$catalinaBase\webapps"

                $serverXMLFile = $catalinaBase + '\conf\server.xml'
                $origServerXMLFile = $catalinaBase + '\conf\server.xml.orig'

                # back up server.xml file if not done in a previous round
                if( -not ( Get-Item ($origServerXMLFile) -ErrorAction SilentlyContinue ) )
                {
                    Copy-Item -Path ($serverXMLFile) `
                        -Destination ($origServerXMLFile)
                }

                # --------- update server.xml file ---------
                $xml = [xml](Get-Content ($origServerXMLFile))

                # Set the local server control port to something different than the default 8005 to enable the service to start.
                $xml.server.port = "8006"

                #remove unwanted default connectors
                ($xml.Server.Service.Connector) | ForEach-Object { [void]$_.ParentNode.removeChild($_) }

                $NewConnector = [xml] ('<Connector
                    port="'+$using:brokerPort+'"
                    protocol="org.apache.coyote.http11.Http11NioProtocol"
                    SSLEnabled="true"
                    keystoreFile="'+$using:LocalDLPath+'\.keystore"
                    maxThreads="2000" scheme="https" secure="true"
                    clientAuth="false" sslProtocol="TLS"
                    SSLEngine="on" keystorePass="changeit"
                    SSLPassword="changeit"
                    sslEnabledProtocols="TLSv1.0,TLSv1.1,TLSv1.2"
                    ciphers="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA"
                    />')

                $xml.Server.Service.InsertBefore(
                    # new child
                    $xml.ImportNode($NewConnector.Connector,$true),
                    #ref child
                    $xml.Server.Service.Engine )

                $xml.save($serverXMLFile)



                Write-Host "Opening port $using:brokerPort"

                #open port in firewall
                netsh advfirewall firewall add rule name="Open Port $using:brokerPort" dir=in action=allow protocol=TCP localport=$using:brokerPort

                # Install and start service for new config

                & "$using:CatalinaBinLocation\service.bat" install $using:brokerServiceName
                Write-Host "Tomcat Installer exit code: $LASTEXITCODE"
                Start-Sleep -s 10  #TODO: Is this sleep ACTUALLY needed?

                Write-Host "Setting Tomcat Service for $using:brokerServiceName to automatically startup."
                Set-Service $using:brokerServiceName -startuptype "automatic"
            }
        }

        Script Install_OpenSSL
        {
            DependsOn = @("[xRemoteFile]Download_OpenSSL")
            GetScript = {@{Result = "Install_OpenSSL"}}
            TestScript = {return Test-Path "C:\OpenSSL-Win64\" -PathType Container}
            SetScript = {
                Write-Verbose "Install_OpenSSL"
                Start-Process "$using:LocalDLPath\$using:OpenSSL" -ArgumentList '/SP /SILENT' -Wait
            }            
        }

        Script Install_Broker
        {
            DependsOn  = @("[xRemoteFile]Download_Broker_WAR", "[Script]Setup_Broker_Service", "[Script]Install_OpenSSL")
            GetScript  = { @{ Result = "Install_Broker" } }

            TestScript = {
                $WARPath = "$using:CatalinaHomeLocation\$using:brokerServiceName\webapps\$using:brokerWAR"
 
                return Test-Path $WARPath -PathType Leaf
            }
            SetScript  = {
                Write-Verbose "Install_Broker"

                $catalinaHome = $using:CatalinaHomeLocation
                $catalinaBase = "$catalinaHome\$using:brokerServiceName"

                Copy-Item "$using:LocalDLPath\$using:brokerWAR" ($catalinaBase + "\webapps")

                # $svc = get-service $using:brokerServiceName
                # if ($svc.Status -ne "Stopped") {$svc.stop()}

                Write-Host "Generating broker configuration file."
                $targetDir = $catalinaBase + "\brokerproperty"
                $cbPropertiesFile = "$targetDir\connectionbroker.properties"

                if(-not (Test-Path $targetDir))
                {
                    New-Item $targetDir -type directory
                }

                if(-not (Test-Path $cbPropertiesFile))
                {
                    New-Item $cbPropertiesFile -type file
                }

                $firstIPv4IP = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"} | select -First 1
                $ipaddressString = $firstIPv4IP.IPAddress

                $cbProperties = @"
ldapHost=ldaps://$Using:dcvmfqdn
brokerHostName=$Using:pbvmfqdn
brokerProductName=CAM Connection Broker
brokerPlatform=$Using:family
brokerProductVersion=1.0
brokerIpaddress=$ipaddressString
brokerLocale=en_US
domainName=$using:domainName
isRetrieveAgentState=$using:brokerRetrieveAgentState
isDisplayAgentState=$using:clientShowAgentState
brokerCacheTimeoutSeconds=$using:brokerCacheTimeoutSeconds
brokerCacheSize=$using:brokerCacheSize
isBrokerCacheEnabled=$using:isBrokerCacheEnabled

"@
              
                $isMfa = $using:enableRadiusMfa
#                Write-Host "MFA setting is $isMfa"
#stick in RADIUS MFA related attributes if RADIUS MFA is turned on
                if($isMfa -eq "True") {
                    $radiusProperties =@"
isMultiFactorAuthenticate=$isMfa
"@
                    $cbProperties = $cbProperties + "`n" + $radiusProperties
                }

                Set-Content $cbPropertiesFile $cbProperties
                Write-Host "Broker configuration file generated."

                #----- setup security trust for LDAP certificate from DC -----

                $srvName = "_ldap._tcp.$using:domainName"
                try{
                    $ldapHosts = (Resolve-DnsName -Name $srvName -Type 'SRV').NameTarget
                }catch {
                    Write-Host "Failed to retrieve ldap hosts using $srvName from Dns Server because $_"
                    # fall back to single passing ldap
                    $ldapHosts = @($using:dcvmfqdn)
                }                

                forEach($dcvmfqdn in $ldapHosts) {
                    try {
                        #second, get the certificate file
                        $compName = $dcvmfqdn.split(".")[0]
                        $issuerCertFileName = "${compName}_issuercert.crt"
                        Write-Host "Looking for Issuer certificate for $dcvmfqdn"

                        $foundCert = $false
                        $caCert = $null
                        $loopCountRemaining = 30

                        # LDAPS Port and Host
                        $port=636
                        $hostname=$dcvmfqdn
                        $url="https://${hostname}:${port}"
                        #loop until it's created
                        while(-not $foundCert)
                        {
                            $cert = $null
                            try {
                                # Try to use multiple .NET methods to get Issuer Cert, fall back to openSSL if they fail
                                Write-Host "Looking for LDAPS certificate for $hostname"
                                $tcpclient = new-object System.Net.Sockets.tcpclient
                                $tcpclient.Connect($hostname,$port)

                                # Authenticate with SSL - trusting all certificates
                                $sslstream = new-object System.Net.Security.SslStream -ArgumentList $tcpclient.GetStream(),$false,{$true}

                                $sslstream.AuthenticateAsClient($hostname)
                                $cert =  [System.Security.Cryptography.X509Certificates.X509Certificate2]($sslstream.remotecertificate)
                                Write-Host "Found Certificate for $hostname, looking for Issuer Certificate"

                                $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
                                # Build the certificate chain from the file certificate
                                if( -not $chain.Build($cert) ) {
                                    Write-Host "Failed to build certificate chain, trying another method..."
                                    Write-Host "Looking for LDAPS certificate for $hostname"
                                    $WebRequest = [Net.WebRequest]::CreateHttp($url)
                                    $WebRequest.AllowAutoRedirect = $true
                                    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
                                    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                                                
                                    #Request website
                                    try {$Response = $WebRequest.GetResponse()} catch {}

                                    Write-Host "Found Certificate for $hostname, looking for Issuer Certificate"
                                    #Creates Certificate
                                    $cert = $WebRequest.ServicePoint.Certificate.Handle
                                            
                                    #Build chain
                                    if( $chain.Build($cert) ) {
                                        $listOfCertificates = ($chain.ChainElements | ForEach-Object {$_.Certificate})
                                    } else {
                                        # Use OpenSSL if chain couldn't be built
                                        Write-Host "Failed to build certificate change, trying another method..."
                                        Write-Host "Looking for LDAPS certificate for $hostname"

                                        Start-Process C:\OpenSSL-Win64\bin\openssl.exe -ArgumentList "s_client -showcerts -connect ${hostname}:${port}" -RedirectStandardOutput "$env:systemdrive\certInfo.txt"
                                        # Wait a bit to ensure that the previous command completes
                                        Sleep 30

                                        Write-Host "Found Certificate for $hostname, looking for Issuer Certificate"
                                        $openSSLOutput = Get-Content "$env:systemdrive\certInfo.txt" -Raw
                                        $certMatches = $openSSLOutput | Select-String '(?smi)(-----BEGIN CERTIFICATE-----((?!-----END).)+-----END CERTIFICATE-----)' -AllMatches | % {$_.Matches}
                                        if ($certMatches.Count) {
                                            #last one is the root in chain
                                            $certMatches[-1].Value | Out-File -FilePath "$env:systemdrive\$issuerCertFileName" -Encoding ascii
                                            $foundCert=$true
                                        } else {
                                            Write-Host "Final method failed to get full certificate chain, using certificates that were found instead"
                                        }

                                    }
                                    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
                                } else {
                                    $listOfCertificates = ($chain.ChainElements | ForEach-Object {$_.Certificate})
                                }

                                if ($listOfCertificates) {
                                    #last one is the root in chain
                                    $caCert = $listOfCertificates[-1]
                                    $content = @(
                                        '-----BEGIN CERTIFICATE-----'
                                        [System.Convert]::ToBase64String($caCert.RawData, 'InsertLineBreaks')
                                        '-----END CERTIFICATE-----'
                                    )
                                            
                                    $content | Out-File -FilePath "$env:systemdrive\$issuerCertFileName" -Encoding ascii
                                    $foundCert=$true
                                }
                            } catch {
                                Write-Host "Failed to retrieve issuer certificate from ${hostname}:${port} because $_"
                            } finally {
                                #cleanup
                                if ($sslStream) {
                                    $sslstream.close()  | Out-Null
                                }
                                if ($tcpclient) {
                                    $tcpclient.close()  | Out-Null
                                }
                                Start-Process Taskkill -ArgumentList '/F /IM "openssl.exe"' -Wait
                            }
                                        
                            if($foundCert) {
                                Write-Host "Root Issuer Cert found!"
                            } else {
                                Start-Sleep -Seconds 10
                                $loopCountRemaining = $loopCountRemaining - 1
                                if( $loopCountRemaining -eq 0 ) {
                                    throw "Unable to get Issuer Certificate after multiple tries"
                                }
                            }
                        }

                        # Have the certificate file, add to keystore

                        # keytool seems to be causing an error but succeeding. Ignore and continue.
                        $eap = $ErrorActionPreference
                        $ErrorActionPreference = 'SilentlyContinue'
                        & "keytool" -import -file "$env:systemdrive\$issuerCertFileName" -keystore ($env:classpath + "\security\cacerts") -storepass changeit -noprompt -alias $compName
                        $ErrorActionPreference = $eap

                        if($foundCert) {
                            # Break out of For loop if we have the root cert
                            break
                        }
                    } catch {
                        Write-Host "Failed to retrieve issuer certificate from ${dcvmfqdn} because $_"
                    }
                }
                if(-not $foundCert) {
                    throw "Unable to find root CA certificate for $using:domainName on DC(s): ${ldapHosts}"
                }
                Write-Host "Finished importing LDAP certificate to keystore."
            }
        }


        Script Set_CAM_Envionment_And_Reboot
        {
            # depends on both services being installed to ensure the reboot at the end will start both services properly.
            DependsOn  = @("[Script]Install_Auth_file", "[Script]Install_Broker")
            GetScript  = { @{ Result = "Set_CAM_Envionment_And_Reboot" } }

            TestScript = { 
                [bool]( $env:CAM_USERNAME `
                   -and $env:CAM_PASSWORD `
                   -and $env:CAM_TENANTID `
                   -and $env:CAM_URI `
                   -and $env:CAM_DEPLOYMENTID)
            }

            SetScript  = {
                ##
                $regInfo = $using:camDeploymentInfoDecoded.RegistrationInfo

                # now have an object with key value pairs - set environment (to be active after reboot)
                $regInfo.psobject.properties | Foreach-Object {
                    [System.Environment]::SetEnvironmentVariable($_.Name, $_.Value, "Machine")
                }

                # Setup primary domain search suffix to match the domain we're brokering
                $networkRegKey = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
                
                Set-ItemProperty -Path $networkRegKey -Name "Domain" -Type String -Value $using:domainName
                Set-ItemProperty -Path $networkRegKey -Name "NV Domain" -Type String -Value $using:domainName

                # Reboot machine to ensure all changes are picked up by all services.
                $global:DSCMachineStatus = 1
            }
        }
    }
}

