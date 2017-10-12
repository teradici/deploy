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
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-CAM.ps1	-ContainerName $StorageContainer -StorageContext $StorageContext
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

		[Parameter(Mandatory)]
		[String]$templateURI,

		[Parameter(Mandatory)]
		[String]$templateAgentURI,

		[Parameter(Mandatory)]
		[System.Management.Automation.PSCredential]$registrationCodeAsCred,

		[string]
		$javaInstaller = "jdk-8u144-windows-x64.exe",

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

	$standardVMSize = "Standard_D2_v2"
	$graphicsVMSize = "Standard_NV6"

	$dcvmfqdn = "$DCVMName.$domainFQDN"
	$pbvmfqdn = "$env:computername.$domainFQDN"
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

		xRemoteFile Download_Linux_Agent_ARM
		{
			Uri = "$templateAgentURI/$linuxAgentARM"
			DestinationPath = "$LocalDLPath\$linuxAgentARM"
			MatchSource = $false
		}

		File Sumo_Directory 
		{
			Ensure			= "Present"
			Type			= "Directory"
			DestinationPath = "C:\sumo"
		}

		# Aim to install the collector first and start the log collection before any 
		# other applications are installed.
		Script Install_SumoCollector
		{
			DependsOn  = "[File]Sumo_Directory"
			GetScript  = { @{ Result = "Install_SumoCollector" } }

			TestScript = { 
				return Test-Path "C:\sumo\sumo.conf" -PathType leaf
				}

			SetScript  = {
				Write-Verbose "Install_SumoCollector"

				$installerFileName = "SumoCollector_windows-x64_19_182-25.exe"
				$sumo_package = "$using:sourceURI/$installerFileName"
				$sumo_config = "$using:gitLocation/sumo.conf"
				$sumo_collector_json = "$using:gitLocation/sumo-admin-vm.json"
				$dest = "C:\sumo"
				Invoke-WebRequest -UseBasicParsing -Uri $sumo_config -PassThru -OutFile "$dest\sumo.conf"
				Invoke-WebRequest -UseBasicParsing -Uri $sumo_collector_json -PassThru -OutFile "$dest\sumo-admin-vm.json"
				#
				#Insert unique ID
				$collectorID = "$using:sumoCollectorID"
				(Get-Content -Path "$dest\sumo.conf").Replace("collectorID", $collectorID) | Set-Content -Path "$dest\sumo.conf"
				
				Invoke-WebRequest $sumo_package -OutFile "$dest\$installerFileName"
				
				#install the collector
				$command = "$dest\$installerFileName -console -q"
				Invoke-Expression $command

				# Wait for collector to be installed before exiting this configuration.
				#### Note if we change binary versions we will need to change registry path - 7857-4527-9352-4688 will change ####
				$retrycount = 1800
				while ($retryCount -gt 0)
				{
					$readyToConfigure = ( Get-Item "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7857-4527-9352-4688"  -ErrorAction SilentlyContinue )

					if ($readyToConfigure)
					{
						break	#success
					}
					else
					{
						Start-Sleep -s 1;
						$retrycount = $retrycount - 1;
						if ( $retrycount -eq 0)
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
					$readyToConfigure = ( Get-Item "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F64180144F0}"	-ErrorAction SilentlyContinue )
					# don't wait for {64A3A4F4-B792-11D6-A78A-00B0D0180144} - that's the JDK. The JRE is installed 2nd {26A...} so wait for that.

					if ($readyToConfigure)
					{
						break	#success
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
						break	#success
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
#				Remove-Item "$catalinaBase" -Force -Recurse -ErrorAction SilentlyContinue
#				Copy-Item "$catalinaHome\conf" "$catalinaBase\conf" -Recurse -ErrorAction SilentlyContinue
#				Copy-Item "$catalinaHome\logs" "$catalinaBase\logs" -Recurse -ErrorAction SilentlyContinue
#				Copy-Item "$catalinaHome\temp" "$catalinaBase\temp" -Recurse -ErrorAction SilentlyContinue
#				Copy-Item "$catalinaHome\webapps" "$catalinaBase\webapps" -Recurse -ErrorAction SilentlyContinue
#				Copy-Item "$catalinaHome\work" "$catalinaBase\work" -Recurse -ErrorAction SilentlyContinue

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
				#	$xml.ImportNode($unencConnector.Connector,$true),
					#ref child
				#	$xml.Server.Service.Engine )

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
						   "[xRemoteFile]Download_Agent_ARM",
						   "[Script]Setup_AUI_Service",
						   "[xRemoteFile]Download_Ga_Agent_ARM",
						   "[xRemoteFile]Download_Linux_Agent_ARM")

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
				$agentARM = $using:agentARM
				$gaAgentARM = $using:gaAgentARM
				$linuxAgentARM = $using:linuxAgentARM
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
					Install-Module -Name AzureRM -Force
				}
				

				Write-Verbose "Install_CAM"

				copy "$LocalDLPath\$adminWAR" ($catalinaBase + "\webapps")

				$svc = get-service $using:AUIServiceName
				if ($svc.Status -ne "Stopped") {$svc.stop()}

				Write-Host "Re-generating CAM configuration file."

				#Now create the new output file.
				#TODO - really only a couple parameters are used and set properly now. Needs cleanup.
				$domainsplit = $using:domainFQDN
				$domainsplit = $domainsplit.split(".".2)
				$domainleaf = $domainsplit[0]  # get the first part of the domain name (before .local or .???)
				$domainroot = $domainsplit[1]  # get the second part of the domain name
				$date = Get-Date
				$domainControllerFQDN = $using:dcvmfqdn
				$RGNameLocal		= $using:RGName

				$auProperties = @"
#$date
cn=Users
dom=$domainleaf
dcDomain = $domainleaf
dc=$domainroot
adServerHostAddress=$domainControllerFQDN
resourceGroupName=$RGNameLocal
CAMSessionTimeoutMinutes=480
domainGroupAppServersJoin="$using:domainGroupAppServersJoin"
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



				Write-Host "Pulling in Agent machine deployment script."

				$templateLoc = "$CatalinaHomeLocation\ARMtemplateFiles"
				
				if(-not (Test-Path $templateLoc))
				{
					New-Item $templateLoc -type directory
				}

				#clear out whatever was stuffed in from the deployment WAR file
				Remove-Item "$templateLoc\*" -Recurse
				
				copy "$LocalDLPath\$agentARM" $templateLoc
				copy "$LocalDLPath\$gaAgentARM" $templateLoc
				copy "$LocalDLPath\$linuxAgentARM" $templateLoc

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


				Write-Host "Creating SP if needed, creating keyvault, and writing auth file."

# create SP and write to credential file
# as documented here: https://github.com/Azure/azure-sdk-for-java/blob/master/AUTH.md

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

				$localAzureCreds = $using:AzureCreds
				$RGNameLocal	 = $using:RGName
				$tenantID		 = $using:tenantID

				if ((-not $tenantID) -or ($tenantID -eq "null"))
				{
					Write-Host "No tenant ID entered. Calling Azure Active Directory to make an app and a service principal."

					Login-AzureRmAccountWithBetterReporting -Credential $localAzureCreds

					#Application name
					$appName = "CAM-$RGNameLocal"
					# 16 letter password
					$generatedPassword = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
					$generatedID = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
					$appURI = "https://www.$generatedID.com"


					Write-Host "Purge any registered app's with the same name."

					# first make sure if there is an app there (or more than one) that they're deleted.
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

					Write-Host "Purge complete. Creating new app."

					# retry required on app registration (it seems) if there is a race condition with the deleted application.
					$newAppCreateRetry = 1800
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
					$SPCreateRetry = 1800
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
					$rollAssignmentRetry = 1800
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
							Write-Host "Waiting for service principal. Remaining: $rollAssignmentRetry"
							Start-sleep -Seconds 1
							if ($rollAssignmentRetry -eq 0)
							{
								#re-throw whatever the original exception was
								$exceptionContext = Get-AzureRmContext
								$exceptionSubscriptionId = $exceptionContext.Subscription.Id
								Write-Error "Failure to create Contributor role for $appName in ResourceGroup: $RGNameLocal Subscription: $exceptionSubscriptionId. Please check your subscription premissions."
								throw
							}
						}
					}

					# get SP credentials
					$spPass = ConvertTo-SecureString $generatedPassword -AsPlainText -Force
					$spCreds = New-Object -TypeName pscredential -ArgumentList	$sp.ApplicationId, $spPass

					# get tenant ID for this subscription
					$subForTenantID = Get-AzureRmSubscription
					$tenantID = $subForTenantID.TenantId
				}
				else
				{
					Write-Host "Tenant ID was provided."

					$spCreds = $localAzureCreds
				}

				$spName = $spCreds.UserName
				Write-Host "Logging in SP $spName with tenantID $tenantID"

				# retry required since it can take a few seconds for the app registration to percolate through Azure (and different to different endpoints... sigh).
				$LoginSPRetry = 1800
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
				


				Write-Host "Create auth file."
				
				$sub = Get-AzureRmSubscription
				$subID = $sub.Id
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

				#Get local version of passed-in credentials
				$localVMAdminCreds = $using:VMAdminCreds
				$VMAdminUsername = $localVMAdminCreds.GetNetworkCredential().Username
				$VMAdminPassword = $localVMAdminCreds.GetNetworkCredential().Password

				$localDomainAdminCreds = $using:DomainAdminCreds
				$DomainAdminUsername = $localDomainAdminCreds.GetNetworkCredential().Username
				$DomainAdminPassword = $localDomainAdminCreds.GetNetworkCredential().Password



				#KeyVault names must be globally (or at least regionally) unique, so make a unique string
				$generatedKVID = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
				$kvName = "CAM-$generatedKVID"

				Write-Host "Creating Azure KeyVault $kvName"


				$rg = Get-AzureRmResourceGroup -ResourceGroupName $RGNameLocal
				New-AzureRmKeyVault -VaultName $kvName -ResourceGroupName $RGNameLocal -Location $rg.Location -EnabledForTemplateDeployment -EnabledForDeployment

				Write-Host "Populating Azure KeyVault $kvName"
				
				$rcCred = $using:registrationCodeAsCred
				$registrationCode = $rcCred.Password

				$rcSecretName = 'cloudAccessRegistrationCode'
				$djSecretName = 'domainJoinPassword'

				$rcSecret = $null
				$djSecret = $null

				#keyvault populate retry is to catch the case where the DNS has not been updated
				#from the keyvault creation by the time we get here
				$keyVaultPopulateRetry = 360 # so ~30 minutes with a sleep of 5 seconds.
				while($keyVaultPopulateRetry -ne 0)
				{
					$keyVaultPopulateRetry--

					try
					{
						Set-AzureRmKeyVaultAccessPolicy -VaultName $kvName -ServicePrincipalName $spName -PermissionsToSecrets get, set -ErrorAction stop

						$rcSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $rcSecretName -SecretValue $registrationCode -ErrorAction stop
						$djSecret = Set-AzureKeyVaultSecret -VaultName $kvName -Name $djSecretName -SecretValue $localDomainAdminCreds.Password -ErrorAction stop
						break
					}
					catch
					{
						Write-Host "Waiting for key vault $keyVaultPopulateRetry"
						if ( $keyVaultPopulateRetry -eq 0)
						{
							#re-throw whatever the original exception was
							throw
						}
						Start-sleep -Seconds 5
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


				################################
				Write-Host "Creating application gateway"
				# This really should be a different configuration but putting here so it can reuse the same Azure login context, and passing variables between SetScripts seems problematic

				# create self signed certificate
				$certLoc = 'cert:Localmachine\My'
				$startDate = [DateTime]::Now.AddDays(-1)
				$subject = "CN=localhost,O=Teradici Corporation,OU=SoftPCoIP,L=Burnaby,ST=BC,C=CA"
				$cert = New-SelfSignedCertificate -certstorelocation $certLoc -DnsName "*.cloudapp.net" -Subject $subject -KeyLength 3072 `
					-FriendlyName "PCoIP Application Gateway" -NotBefore $startDate -TextExtension @("2.5.29.19={critical}{text}ca=1") `
					-HashAlgorithm SHA384 -KeyUsage DigitalSignature, CertSign, CRLSign, KeyEncipherment

				#generate pfx file from certificate
				$certPath = $certLoc + '\' + $cert.Thumbprint

				$pfxPath = 'C:\WindowsAzure'
				if (!(Test-Path -Path $pfxPath)) {
					New-Item $pfxPath -type directory
				}
				$certPfx = $pfxPath + '\mySelfSignedCert.pfx'

				#generate password for pfx file
				$certPswd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
				$secureCertPswd = ConvertTo-SecureString -String $certPswd -AsPlainText -Force

				#export pfx file
				Export-PfxCertificate -Cert $certPath -FilePath $certPfx -Password $secureCertPswd

				#read from pfx file and convert to base64 string
				$fileContentEncoded = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($certPfx))

				# deploy application gateway
				$parameters = @{}
				$parameters.Add("subnetRef", $using:AGsubnetRef)
				$parameters.Add("skuName", "Standard_Small")
				$parameters.Add("capacity", 1)
				$parameters.Add("backendIpAddressDefault", "$using:AGbackendIpAddressDefault")
				$parameters.Add("backendIpAddressForPathRule1", "$using:AGbackendIpAddressForPathRule1")
				$parameters.Add("pathMatch1", "/pcoip-broker/*")
				$parameters.Add("certData", "$fileContentEncoded")
				$parameters.Add("certPassword", "$certPswd")

				$LocalAGtemplateUri = $using:AGtemplateUri
				$tUri = $LocalAGtemplateUri.GetNetworkCredential().Password

				New-AzureRmResourceGroupDeployment -Mode Incremental -Name "DeployAppGateway" -ResourceGroupName $RGNameLocal -TemplateUri $tUri -TemplateParameterObject $parameters

				################################


				Write-Host "Creating default template parameters file data"


				$armParamContent = @"
{
	"`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
	"contentVersion": "1.0.0.0",
	"parameters": {
		"vmSize": { "value": "%vmSize%" },
		"CAMDeploymentBlobSource": { "value": "$using:sourceURI" },
		"existingSubnetName": { "value": "$using:existingSubnetName" },
		"domainUsername": { "value": "$DomainAdminUsername" },
		"domainPassword": {
			"reference": {
			  "keyVault": {
				"id": "/subscriptions/$subID/resourceGroups/$RGNameLocal/providers/Microsoft.KeyVault/vaults/$kvName"
			  },
			  "secretName": "$djSecretName"
			}		
		},
		"registrationCode": {
			"reference": {
			  "keyVault": {
				"id": "/subscriptions/$subID/resourceGroups/$RGNameLocal/providers/Microsoft.KeyVault/vaults/$kvName"
			  },
			  "secretName": "$rcSecretName"
			}
		},
		"dnsLabelPrefix": { "value": "tbd-vmname" },
		"existingVNETName": { "value": "$using:existingVNETName" },
		"vmAdminUsername": { "value": "$VMAdminUsername" },
		"vmAdminPassword": {
			"reference": {
			  "keyVault": {
				"id": "/subscriptions/$subID/resourceGroups/$RGNameLocal/providers/Microsoft.KeyVault/vaults/$kvName"
			  },
			  "secretName": "$laSecretName"
			}
		},
		"domainToJoin": { "value": "$using:domainFQDN" },
		"domainGroupToJoin": { "value": "$using:domainGroupAppServersJoin" },
		"storageAccountName": { "value": "$using:storageAccountName" },
		"_artifactsLocation": { "value": "https://raw.githubusercontent.com/teradici/deploy/master/end-user-application-machines/new-agent-vm" }
   }
}

"@


				$standardArmParamContent = $armParamContent -replace "%vmSize%",$using:standardVMSize
				$graphicsArmParamContent = $armParamContent -replace "%vmSize%",$using:graphicsVMSize
				$linuxArmParamContent = $armParamContent -replace "%vmSize%",$using:standardVMSize

				Write-Host "Creating default template parameters files"

				#now make the default parameters filenames - same root name but different suffix as the templates
				$agentARM = $using:agentARM
				$gaAgentARM = $using:gaAgentARM
				$linuxAgentARM = $using:linuxAgentARM

				$agentARMparam = ($agentARM.split('.')[0]) + ".customparameters.json"
				$gaAgentARMparam = ($gaAgentARM.split('.')[0]) + ".customparameters.json"
				$linuxAgentARMparam = ($linuxAgentARM.split('.')[0]) + ".customparameters.json"

				$ParamTargetDir = "$using:CatalinaHomeLocation\ARMParametertemplateFiles"
				$ParamTargetFilePath = "$ParamTargetDir\$agentARMparam"
				$GaParamTargetFilePath = "$ParamTargetDir\$gaAgentARMparam"
				$LinuxParamTargetFilePath = "$ParamTargetDir\$linuxAgentARMparam"

				if(-not (Test-Path $ParamTargetDir))
				{
					New-Item $ParamTargetDir -type directory
				}

				#clear out whatever was stuffed in from the deployment WAR file
				Remove-Item "$ParamTargetDir\*" -Recurse

				# Standard Agent Parameter file
				if(-not (Test-Path $ParamTargetFilePath))
				{
					New-Item $ParamTargetFilePath -type file
				}

				Set-Content $ParamTargetFilePath $standardArmParamContent -Force


				# Graphics Agent Parameter file
				if(-not (Test-Path $GaParamTargetFilePath))
				{
					New-Item $GaParamTargetFilePath -type file
				}

				Set-Content $GaParamTargetFilePath $graphicsArmParamContent -Force

				# Linux Agent Parameter file
				if(-not (Test-Path $LinuxParamTargetFilePath))
				{
					New-Item $LinuxParamTargetFilePath -type file
				}

				Set-Content $LinuxParamTargetFilePath $linuxArmParamContent -Force

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

		Script Install_Broker
		{
			DependsOn  = @("[xRemoteFile]Download_Broker_WAR", "[Script]Setup_Broker_Service")
			GetScript  = { @{ Result = "Install_Broker" } }

			TestScript = {
				$WARPath = "$using:CatalinaHomeLocation\$using:brokerServiceName\webapps\$using:brokerWAR"
 
				return Test-Path $WARPath -PathType Leaf
			}
			SetScript  = {
				Write-Verbose "Install_Broker"

				$catalinaHome = $using:CatalinaHomeLocation
				$catalinaBase = "$catalinaHome\$using:brokerServiceName"

				copy "$using:LocalDLPath\$using:brokerWAR" ($catalinaBase + "\webapps")

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

				#making another copy in catalinaHome until the paths are figured out...
				Write-Host "Generating broker configuration file in CatalinaHome."
				$targetDir = $catalinaHome + "\brokerproperty"
				$cbHomePropertiesFile = "$targetDir\connectionbroker.properties"

				if(-not (Test-Path $targetDir))
				{
					New-Item $targetDir -type directory
				}

				if(-not (Test-Path $cbHomePropertiesFile))
				{
					New-Item $cbHomePropertiesFile -type file
				}


				$firstIPv4IP = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"} | select -First 1
				$ipaddressString = $firstIPv4IP.IPAddress

				$localAdminCreds = $using:DomainAdminCreds
				$adminUsername = $localAdminCreds.GetNetworkCredential().Username
				$adminPassword = $localAdminCreds.GetNetworkCredential().Password


				$cbProperties = @"
ldapHost=ldaps://$Using:dcvmfqdn
ldapAdminUsername=$adminUsername
ldapAdminPassword=$adminPassword
ldapDomain=$Using:domainFQDN
brokerHostName=$Using:pbvmfqdn
brokerProductName=CAS Connection Broker
brokerPlatform=$Using:family
brokerProductVersion=1.0
brokerIpaddress=$ipaddressString
brokerLocale=en_US
"@

				Set-Content $cbPropertiesFile $cbProperties
				Set-Content $cbHomePropertiesFile $cbProperties
				Write-Host "Broker configuration file generated."

				#----- setup security trust for LDAP certificate from DC -----

				#second, get the certificate file

				$ldapCertFileName = "ldapcert.cert"
				$certStoreLocationOnDC = "c:\" + $ldapCertFileName

				$issuerCertFileName = "issuercert.cert"
				$issuerCertStoreLocationOnDC = "c:\" + $issuerCertFileName

				$certSubject = "CN=$using:dcvmfqdn"

				Write-Host "Looking for cert with $certSubject on $dcvmfqdn"

				$foundCert = $false
				$loopCountRemaining = 180
				#loop until it's created
				while(-not $foundCert)
				{
					Write-Host "Waiting for LDAP certificate. Seconds remaining: $loopCountRemaining"

					$DCSession = New-PSSession $using:dcvmfqdn -Credential $using:DomainAdminCreds

					$foundCert = `
						Invoke-Command -Session $DCSession -ArgumentList $certSubject, $certStoreLocationOnDC, $issuerCertStoreLocationOnDC `
						  -ScriptBlock {
								$cs = $args[0]
								$cloc = $args[1]
								$icloc = $args[2]

								$cert = get-childItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -eq $cs }
								if(-not $cert)
								{
									Write-Host "Did not find LDAP certificate."
									#maybe a certutil -pulse will help?
									# NOTE - must redirect stdout to $null otherwise the success return here pollutes the return value of $foundCert
									& "certutil" -pulse > $null
									return $false
								}
								else
								{
									Export-Certificate -Cert $cert -filepath  $cloc -force
									Write-Host "Exported LDAP certificate."

									#Now export issuer Certificate
									$issuerCert = get-childItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -eq $cert.Issuer }
									Export-Certificate -Cert $issuerCert -filepath	$icloc -force

									return $true
								}
							}

					if(-not $foundCert)
					{
						Start-Sleep -Seconds 10
						$loopCountRemaining = $loopCountRemaining - 1
						if ($loopCountRemaining -eq 0)
						{
							Remove-PSSession $DCSession
							throw "No LDAP certificate!"
						}
					}
					else
					{
						#found it! copy
						Write-Host "Copying certs and exiting DC Session"
						Copy-Item -Path $certStoreLocationOnDC -Destination "$env:systemdrive\$ldapCertFileName" -FromSession $DCSession
						Copy-Item -Path $issuerCertStoreLocationOnDC -Destination "$env:systemdrive\$issuerCertFileName" -FromSession $DCSession
					}
					Remove-PSSession $DCSession
				}

				# Have the certificate file, add to keystore

				# keytool seems to be causing an error but succeeding. Ignore and continue.
				$eap = $ErrorActionPreference
				$ErrorActionPreference = 'SilentlyContinue'
				& "keytool" -import -file "$env:systemdrive\$issuerCertFileName" -keystore ($env:classpath + "\security\cacerts") -storepass changeit -noprompt
				$ErrorActionPreference = $eap

				Write-Host "Finished importing LDAP certificate to keystore."
			}
		}
		
		Script RegisterCam
		{
			DependsOn  = @("[Script]Install_Auth_file", "[Script]Install_Broker")  # depends on both services being installed to ensure the reboot at the end will start both services properly.
			GetScript  = { @{ Result = "RegisterCam" } }

			TestScript = { 

				if ( $env:CAM_USERNAME -and $env:CAM_PASSWORD -and $env:CAM_TENANTID -and $env:CAM_URI -and $env:CAM_DEPLOYMENTID)
				{
					return $true
				} else {
					return $false
				}
			}

			SetScript  = {
				##
				$certificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy

				if (!$using:verifyCAMSaaSCertificate) {
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

				# Read in Authorization Information
				# Use this to retrieve client, key, tenant and subscription from the auth file
				Get-Content "$env:AZURE_AUTH_LOCATION" | Foreach-Object{
					$var = $_.Split('=', 2)
					New-Variable -Name $var[0] -Value $var[1]
				}

				$camSaasBaseUri = $using:camSaasUri
				$camSaasBaseUri = $camSaasBaseUri.Trim().TrimEnd('/')
				$camRegistrationError = ""
				for($idx = 0; $idx -lt $using:retryCount; $idx++) {
					try {
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

						[System.Environment]::SetEnvironmentVariable("CAM_USERNAME", $userRequest.username, "Machine")
						[System.Environment]::SetEnvironmentVariable("CAM_PASSWORD", $userRequest.password, "Machine")
						[System.Environment]::SetEnvironmentVariable("CAM_TENANTID", $userRequest.tenantId, "Machine")
						[System.Environment]::SetEnvironmentVariable("CAM_URI", $camSaasBaseUri, "Machine")
						$env:CAM_USERNAME = $userRequest.username
						$env:CAM_PASSWORD = $userRequest.password
						$env:CAM_TENANTID = $userRequest.tenantId
						$env:CAM_URI = $camSaasBaseUri

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

						$registrationCode = ($using:registrationCodeAsCred).GetNetworkCredential().password

						# Register Deployment
						$deploymentRequest = @{
							resourceGroup = $using:RGName
							subscriptionId = $subscription
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

						[System.Environment]::SetEnvironmentVariable("CAM_DEPLOYMENTID", $deploymentId, "Machine")
						$env:CAM_DEPLOYMENTID = $deploymentId

						Write-Host "Deployment has been registered succesfully with Cloud Access Manager"

						# Register Agent Machine
						$machineRequest = @{
							deploymentId = $deploymentId
							resourceGroup = $using:RGName
							machineName = $using:adminDesktopVMName
							subscriptionId = $subscription
						}
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
						Write-Host "Machine has been registered succesfully with Cloud Access Manager"
						$camRegistrationError = ""
						break;
					} catch {
						$camRegistrationError = $_
						Write-Verbose ( "Attempt {0} of $using:retryCount failed due to Error: {1}" -f ($idx+1), $camRegistrationError )
						Start-Sleep -s $using:delay
					}
				}
				if($camRegistrationError) {
					throw $camRegistrationError
				}

				# restore CertificatePolicy 
				[System.Net.ServicePointManager]::CertificatePolicy = $certificatePolicy

				# Reboot machine to ensure all changes are picked up by all services.
				$global:DSCMachineStatus = 1
			}
		}
	}
}

