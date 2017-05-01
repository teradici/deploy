# Install-CAM.ps1
# Compile to a local .zip file via this command:
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-CAM.ps1 -ConfigurationArchivePath .\Install-CAM.ps1.zip
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
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-CAM.ps1  -ContainerName $StorageContainer -StorageContext $StorageContext
#
#
Configuration InstallCAM
{
	# One day pull from Oracle as per here? https://github.com/gregjhogan/cJre8/blob/master/DSCResources/cJre8/cJre8.schema.psm1
    param
    (
        [string]
        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPCAMInstall",

        [Parameter(Mandatory)]
		[String]$sourceURI,

        [string]
        $javaInstaller = "jdk-8u91-windows-x64.exe",

        [string]
        $tomcatInstaller = "apache-tomcat-8.0.39-windows-x64.zip",

        [string]
        $adminWAR = "CloudAccessManager.war",

        [string]
        $agentARM = "server2016-standard-agent.json",

        [Parameter(Mandatory)]
        [String]$domainFQDN,

        [Parameter(Mandatory)]
        [String]$existingVNETName,

        [Parameter(Mandatory)]
        [String]$existingSubnetName,

        [Parameter(Mandatory)]
        [String]$storageAccountName,

	#[Parameter(Mandatory)]
	#[String]$sumoCollectorID,
        
	[Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$VMAdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$DomainAdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AzureCreds,

        [Parameter(Mandatory)]
        [String]$DCVMName, #without the domain suffix

        [Parameter(Mandatory)]
        [String]$RGName #Azure resource group name
	)

	$dcvmfqdn = "$DCVMName.$domainFQDN"

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
		}

		xRemoteFile Download_Tomcat_Installer
		{
			Uri = "$sourceURI/$tomcatInstaller"
			DestinationPath = "$LocalDLPath\$tomcatInstaller"
		}

		xRemoteFile Download_Firefox
		{
			Uri = "$sourceURI/Firefox Setup Stub 49.0.1.exe"
			DestinationPath = "$LocalDLPath\Firefox Setup Stub 49.0.1.exe"
		}

		xRemoteFile Download_Keystore
		{
			Uri = "$sourceURI/.keystore"
			DestinationPath = "$LocalDLPath\.keystore"
		}

		xRemoteFile Download_Admin_WAR
		{
			Uri = "$sourceURI/$adminWAR"
			DestinationPath = "$LocalDLPath\$adminWAR"
		}

		xRemoteFile Download_Agent_ARM
		{
			Uri = "$sourceURI/$agentARM"
			DestinationPath = "$LocalDLPath\$agentARM"
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
            DependsOn  = "[File]Sumo_Directory"
            GetScript  = { @{ Result = "Install_SumoCollector" } }

            TestScript = { return $false }
            SetScript  = {
                Write-Verbose "Install_SumoCollector"

                $sumo_package = "https://teradeploy.blob.core.windows.net/binaries/SumoCollector-windows-x64_19_182-25.exe"
                $sumo_config = "$using:gitLocation/sumo.conf"
                $sumo_collector_json = "$using:gitLocation/sumo-admin-vm.json"
                $dest = "C:\sumo"
                Invoke-WebRequest $sumo_config -OutFile "$dest\sumo.conf"
                Invoke-WebRequest $sumo_collecor_json -OutFile "$dest\sumo-admin-vm.json"
		        # Insert unique ID
		        (Get-Content "$dest\sumo.conf").Replace("collectorID", $using:sumoCollectorID) | Set-Content "$dest\sumo.conf"
                
                $installerFileName = "SumoCollector-windows-x64_19_182-25.exe"
		        Invoke-WebRequest $sumo_package -OutFile "$dest\$installerFileName"
                #install the collector
                & "$dest\$installerFileName"
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
				$JavaRootLocation = "$env:systemdrive\Program Files\Java\jdk1.8.0_91"
		       	$JavaBinLocation = $JavaRootLocation + "\bin"
				if ( Get-Item -path "$JavaBinLocation" -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
                Write-Verbose "Install_Java"

		        $LocalDLPath = $using:LocalDLPath
		        $javaInstaller = "jdk-8u91-windows-x64.exe"

				# Run the installer. Start-Process does not work due to permissions issue however '&' calling will not wait so looks for registry key as 'completion.'
				# Start-Process $LocalDLPath\$javaInstaller -ArgumentList '/s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"' -Wait
				& "$LocalDLPath\$javaInstaller" /s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"

				$retrycount = 1800
				while ($retryCount -gt 0)
				{
					$readyToConfigure = ( Get-Item "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F86418091F0}"  -ErrorAction SilentlyContinue )
					# don't wait for {64A3A4F4-B792-11D6-A78A-00B0D0180910} - that's the JDK. The JRE is installed 2nd {26A...} so wait for that.

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

				$JavaRootLocation = "$env:systemdrive\Program Files\Java\jdk1.8.0_91"
				$JavaBinLocation = $JavaRootLocation + "\bin"
				$JavaLibLocation = $JavaRootLocation + "\jre\lib"
				$Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"

				#set path. Don't add strings that are already there...

				$NewPath = (Get-ItemProperty -Path "$Reg" -Name PATH).Path

				#put java path in front of the oracle defined path
				if ($NewPath -notlike "*"+$JavaBinLocation+"*")
				{
				  $NewPath= $JavaBinLocation + ’;’ + $NewPath
				}

				Set-ItemProperty -Path "$Reg" -Name PATH –Value $NewPath
				Set-ItemProperty -Path "$Reg" -Name JAVA_HOME –Value $JavaRootLocation
				Set-ItemProperty -Path "$Reg" -Name classpath –Value $JavaLibLocation



				Write-Host "Waiting for JVM.dll"
				$JREHome = $JavaRootLocation + "\jre"
				$JVMServerdll = $JREHome + "\bin\server\jvm.dll"

				$retrycount = 1800
				while ($retryCount -gt 0)
				{
					$readyToConfigure = ( Get-Item $JVMServerdll -ErrorAction SilentlyContinue )
					# don't wait for {64A3A4F4-B792-11D6-A78A-00B0D0180910} - that's the JDK. The JRE is installed 2nd {26A...} so wait for that.

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

				# Reboot machine - seems to need to happen to get Tomcat to install??? Nope!
				$global:DSCMachineStatus = 1
            }
        }

		Script Install_Tomcat
        {
            DependsOn = @("[xRemoteFile]Download_Tomcat_Installer", "[Script]Install_Java", "[xRemoteFile]Download_Keystore")
            GetScript  = { @{ Result = "Install_Tomcat" } }

            TestScript = { 
				$Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"
				$CatalinaPath = (Get-ItemProperty -Path "$Reg" -Name CATALINA_BASE -ErrorAction SilentlyContinue)
				if ( $CatalinaPath )
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
		        $tomcatInstaller = "apache-tomcat-8.0.39-windows-x64.zip"
				$localtomcatpath = "$env:systemdrive\tomcat"
				$CatalinaHomeLocation = "$localtomcatpath\apache-tomcat-8.0.39"
				$CatalinaBinLocation = $CatalinaHomeLocation + "\bin"
				$ServerXMLFile = $CatalinaHomeLocation + '\conf\server.xml'

				#make sure we get a clean install
				Remove-Item $localtomcatpath -Force -Recurse -ErrorAction SilentlyContinue

				Expand-Archive "$LocalDLPath\$tomcatInstaller" -DestinationPath $localtomcatpath


				Write-Host "Setting Paths and Tomcat environment"



				$Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"

				$NewPath = (Get-ItemProperty -Path "$Reg" -Name PATH).Path

				#put tomcat path at the end
				if ($NewPath -notlike "*"+$CatalinaBinLocation+"*")
				{
				  $NewPath= $NewPath + ’;’ + $CatalinaBinLocation
				}

				Set-ItemProperty -Path "$Reg" -Name PATH –Value $NewPath
				Set-ItemProperty -Path "$Reg" -Name CATALINA_BASE –Value $CatalinaHomeLocation
				Set-ItemProperty -Path "$Reg" -Name CATALINA_HOME –Value $CatalinaHomeLocation

				#set the local CATALINE_HOME as well since the service installer will need that
				$env:CATALINA_BASE = $CatalinaHomeLocation
				$env:CATALINA_HOME = $CatalinaHomeLocation


				Write-Host "Configuring Tomcat"

				# back up server.xml file if not done in a previous round
				if( -not ( Get-Item ($CatalinaHomeLocation + '\conf\server.xml.orig') -ErrorAction SilentlyContinue ) )
				{
					Copy-Item -Path ($ServerXMLFile) `
						-Destination ($CatalinaHomeLocation + '\conf\server.xml.orig')
				}

				#
				# update server.xml file
				#

				$xml = [xml](Get-Content ($CatalinaHomeLocation + '\conf\server.xml.orig'))

				# port 8080 unencrypted connector 

				$unencConnector = [xml] ('<Connector port="8080" protocol="HTTP/1.1" connectionTimeout="20000" redirectPort="8443" />')

				$xml.Server.Service.InsertBefore(
					# new child
					$xml.ImportNode($unencConnector.Connector,$true),
					#ref child
					$xml.Server.Service.Engine )

				$NewConnector = [xml] ('<Connector
					port="8443"
					protocol="org.apache.coyote.http11.Http11NioProtocol"
					SSLEnabled="true"
					keystoreFile="'+$LocalDLPath+'\.keystore"
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


				# Install and start service for new config

				& "$CatalinaBinLocation\service.bat" install
				Write-Host "Tomcat Installer exit code: $LASTEXITCODE"
				Start-Sleep -s 10  #TODO: Is this sleep ACTUALLY needed?

				Write-Host "Starting Tomcat Service"
				Set-Service Tomcat8 -startuptype "automatic"

				# Reboot machine - seems to need to happen to get Tomcat to run reliably or is there a big delay required? reboot for now :)
				$global:DSCMachineStatus = 1
	        }
        }

        Script Install_AUI
        {
            DependsOn  = @("[xRemoteFile]Download_Admin_WAR", "[xRemoteFile]Download_Agent_ARM", "[Script]Install_Tomcat")
            GetScript  = { @{ Result = "Install_AUI" } }

            #TODO: Check for other agent types as well?
            TestScript = {
				$localtomcatpath = "$env:systemdrive\tomcat"
				$CatalinaHomeLocation = "$localtomcatpath\apache-tomcat-8.0.39"
				$adminWAR = $using:adminWAR
				$WARPath = $CatalinaHomeLocation + "\webapps" + $adminWAR
 
				if ( Get-Item $WARPath -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
		        $LocalDLPath = $using:LocalDLPath
				$adminWAR = $using:adminWAR
                $agentARM = $using:agentARM
				$localtomcatpath = "$env:systemdrive\tomcat"
				$CatalinaHomeLocation = "$localtomcatpath\apache-tomcat-8.0.39"

                Write-Verbose "Install Nuget and AzureRM packages"

				Install-packageProvider -Name NuGet -Force
				Install-Module -Name AzureRM -Force

                Write-Verbose "Install_CAM"

				copy "$LocalDLPath\$adminWAR" ($CatalinaHomeLocation + "\webapps")

				#Make sure the properties file exists - as enough proof that the .war file has been processed



		        #----- Update/overwrite the the file with configuration information -----
				# (Tomcat needs to be running for this to happen... Just kick it again in case.)
				$svc = get-service Tomcat8
				if ($svc.Status -eq "Stopped") {$svc.start()}
				elseIf ($svc.status -eq "Running") {Write-Host $svc.name "is running"}

				$auPropertiesFile = $catalinaHomeLocation + "\webapps\CloudAccessManager\WEB-INF\classes\config.properties"

				$exists = $null
				$loopCountRemaining = 600
				#loop until it's created
				while($exists -eq $null)
				{
					Write-Host "Waiting for CAM properties file. Seconds remaining: $loopCountRemaining"
					Start-Sleep -Seconds 1
					$exists = Get-Content $auPropertiesFile -ErrorAction SilentlyContinue
					$loopCountRemaining = $loopCountRemaining - 1
					if ($loopCountRemaining -eq 0)
					{
						throw "No properties file!"
					}
				}
				Write-Host "Got CAM configuration file. Re-generating."

				Stop-Service Tomcat8

				#Now create the new output file.
				#TODO - really only a couple parameters are used and set properly now. Needs cleanup.
				$domainsplit = $using:domainFQDN
				$domainsplit = $domainsplit.split(".".2)
				$domainleaf = $domainsplit[0]  # get the first part of the domain name (before .local or .???)
				$domainroot = $domainsplit[1]  # get the second part of the domain name
				$date = Get-Date
				$domainControllerFQDN = $using:dcvmfqdn

				$localAzureCreds = $using:AzureCreds

				$AzureUsernameLocal = $localAzureCreds.GetNetworkCredential().Username
				$AzurePasswordLocal = $localAzureCreds.GetNetworkCredential().Password

				$RGNameLocal        = $using:RGName

				$auProperties = @"
#$date
cn=Users
dom=$domainleaf
dcDomain = $domainleaf
dc=$domainroot
adServerHostAddress=$domainControllerFQDN
resourceGroupName=$RGNameLocal
"@

				$targetDir = "$env:CATALINA_HOME\adminproperty"
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

		        Write-Host "Redirecting ROOT to Cloud Access Manager."


                $redirectString = '<%response.sendRedirect("CloudAccessManager/login.jsp");%>'
				$targetDir = "$env:CATALINA_HOME\webapps\ROOT"
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


		        Write-Host "Pulling in Agent machine deployment script."

				$templateLoc = "$CatalinaHomeLocation\ARMtemplateFiles"
				
				if(-not (Test-Path $templateLoc))
				{
					New-Item $templateLoc -type directory
				}

				#clear out whatever was stuffed in from the deployment WAR file
				Remove-Item "$templateLoc\*" -Recurse
				
				copy "$LocalDLPath\$agentARM" $templateLoc

				#now make the default parameters file - same root name but different suffix
				$agentARMparam = ($agentARM.split('.')[0]) + ".customparameters.json"

				$localVMAdminCreds = $using:VMAdminCreds
				$VMAdminUsername = $localVMAdminCreds.GetNetworkCredential().Username
				$VMAdminPassword = $localVMAdminCreds.GetNetworkCredential().Password

				$localDomainAdminCreds = $using:DomainAdminCreds
				$DomainAdminUsername = $localDomainAdminCreds.GetNetworkCredential().Username
				$DomainAdminPassword = $localDomainAdminCreds.GetNetworkCredential().Password

				$armParamContent = @"
{
    "`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "existingSubnetName": { "value": "$using:existingSubnetName" },
        "domainUsername": { "value": "$DomainAdminUsername" },
        "dnsLabelPrefix": { "value": "tbd-vmname" },
        "vmAdminPassword": { "value": "$VMAdminPassword" },
        "existingVNETName": { "value": "$using:existingVNETName" },
        "domainPassword": { "value": "$DomainAdminPassword" },
        "vmAdminUsername": { "value": "$VMAdminUsername" },
        "domainToJoin": { "value": "$using:domainFQDN" },
        "storageAccountName": { "value": "$using:storageAccountName" },
        "_artifactsLocation": { "value": "https://raw.githubusercontent.com/teradici/deploy/master/dev/domain-controller/new-agent-vm" }
    }
}

"@
				$ParamTargetDir = "$CatalinaHomeLocation\ARMParametertemplateFiles"
				$ParamTargetFilePath = "$ParamTargetDir\$agentARMparam"

				if(-not (Test-Path $ParamTargetDir))
				{
					New-Item $ParamTargetDir -type directory
				}

				#clear out whatever was stuffed in from the deployment WAR file
				Remove-Item "$ParamTargetDir\*" -Recurse

				if(-not (Test-Path $ParamTargetFilePath))
				{
					New-Item $ParamTargetFilePath -type file
				}

				Set-Content $ParamTargetFilePath $armParamContent -Force


				Write-Host "Creating SP and writing auth file."

# create SP and write to credential file
# as documented here: https://github.com/Azure/azure-sdk-for-java/blob/master/AUTH.md

				Login-AzureRmAccount -Credential $localAzureCreds

				#Application name
				$appName = "CAM-$RGNameLocal"
				# 16 letter password
				$generatedPassword = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
				$generatedID = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
                $appURI = "https://www.$generatedID.com"


				Write-Host "Purge any registered app's with the same name."

				#first make sure if there is an app there (or more than one) that they're deleted.
                $appArray = Get-AzureRmADApplication -DisplayName $appName
                foreach($app in $appArray)
				{
                    $aoID = $app.ObjectId
					Write-Host "Removing previous SP application $appName  $aoID"
					Remove-AzureRmADApplication -ObjectId $aoID -Force
				}

				$app = New-AzureRmADApplication -DisplayName $appName -HomePage $appURI -IdentifierUris $appURI -Password $generatedPassword
				New-AzureRmADServicePrincipal -ApplicationId $app.ApplicationId

				#retry required since it can take a few seconds for the app registration to percolate through Azure.
				#(Online recommendation was sleep 15 seconds - this is both faster and more conservative)
				$rollAssignmentRetry = 120
				while($rollAssignmentRetry -ne 0)
				{
					$rollAssignmentRetry--

					try
					{
						New-AzureRmRoleAssignment -RoleDefinitionName Contributor -ResourceGroupName $RGNameLocal -ServicePrincipalName $app.ApplicationId -ErrorAction Stop
						break
					}
					catch
					{
						$exceptionCode = $_.Exception.Error.Code
						If ($exceptionCode -eq "PrincipalNotFound")
						{
							Write-Host "Waiting for service principal $rollAssignmentRetry"
							Start-sleep -Seconds 1
						}
						else
						{
						#re-throw whatever the original exception was
							throw
						}
					}
				}

				Write-Host "Create auth file."


				$sub = Get-AzureRmSubscription
				$subID = $sub.SubscriptionId
				$tenantID = $sub.TenantId
				$clientID = $app.ApplicationId

				$authFileContent = @"
subscription=$subID
client=$clientID
key=$generatedPassword
tenant=$tenantID
managementURI=https\://management.core.windows.net/
baseURL=https\://management.azure.com/
authURL=https\://login.windows.net/
graphURL=https\://graph.windows.net/
"@

$targetDir = "$env:CATALINA_HOME\adminproperty"
$authFilePath = "$targetDir\authfile.txt"

				if(-not (Test-Path $authFilePath))
				{
					New-Item $authFilePath -type file
				}

				Set-Content $authFilePath $authFileContent -Force


				Write-Host "Update registry so AZURE_AUTH_LOCATION points to auth file."

				$Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"

				Set-ItemProperty -Path "$Reg" -Name AZURE_AUTH_LOCATION –Value $authFilePath

		        Write-Host "Finished! Restarting Tomcat."

				Restart-Service Tomcat8
            }
        }
    }
}

