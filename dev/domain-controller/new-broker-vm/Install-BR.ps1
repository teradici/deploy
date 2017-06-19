# Install-BR.ps1
# Compile to a local .zip file via this command:
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-BR.ps1 -ConfigurationArchivePath .\Install-BR.ps1.zip
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
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-BR.ps1  -ContainerName $StorageContainer -StorageContext $StorageContext
#
#
Configuration InstallBR
{
	# One day pull from Oracle as per here? https://github.com/gregjhogan/cJre8/blob/master/DSCResources/cJre8/cJre8.schema.psm1
    param
    (
        [string]
        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPBRInstall",

        [string]
        $sourceURI = "https://teradeploy.blob.core.windows.net/binaries",

        [string]
        $javaInstaller = "jdk-8u91-windows-x64.exe",

        [string]
        $tomcatInstaller = "apache-tomcat-8.0.39-windows-x64.zip",

        [string]
        $brokerWAR = "pcoip-broker.war",

        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Parameter(Mandatory)]
        [String]$DCVMName, #without the domain suffix

        [Parameter(Mandatory)]
        [String]$gitLocation,

        [Parameter(Mandatory)]
        [String]$sumoCollectorID
    )

	$dcvmfqdn = "$DCVMName.$DomainName"
	$pbvmfqdn = "$env:computername.$DomainName"
	$family   = "Windows Server 2016"
	$domaindns = $DomainName

	$JavaRootLocation = "$env:systemdrive\Program Files\Java\jdk1.8.0_91"
	$JavaBinLocation = $JavaRootLocation + "\bin"
	$JavaLibLocation = $JavaRootLocation + "\jre\lib"
	$JREHome = $JavaRootLocation + "\jre"

	$localtomcatpath = "$env:systemdrive\tomcat"
	$CatalinaHomeLocation = "$localtomcatpath\apache-tomcat-8.0.39"
	$CatalinaBinLocation = $CatalinaHomeLocation + "\bin"

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

		xRemoteFile Download_Keystore
		{
			Uri = "$sourceURI/.keystore"
			DestinationPath = "$LocalDLPath\.keystore"
		}

		xRemoteFile Download_Broker_WAR
		{
			Uri = "$sourceURI/$brokerWAR"
			DestinationPath = "$LocalDLPath\$brokerWAR"
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

            TestScript = { 
                return Test-Path "C:\sumo\sumo.conf" -PathType leaf
                }

            SetScript  = {
                Write-Verbose "Install_SumoCollector"
                #$sumo_package = "$CAMDeploymentBlobSource/SumoCollector_windows-x64_19_182-25.exe"
                $sumo_package = "https://teradeploy.blob.core.windows.net/binaries/SumoCollector_windows-x64_19_182-25.exe"
                $sumo_config = "$using:gitLocation/sumo.conf"
                $sumo_collector_json = "$using:gitLocation/sumo-broker-vm.json"
                $dest = "C:\sumo"
                Invoke-WebRequest -UseBasicParsing -Uri $sumo_config -PassThru -OutFile "$dest\sumo.conf"
                Invoke-WebRequest -UseBasicParsing -Uri $sumo_collector_json -PassThru -OutFile "$dest\sumo-broker-vm.json"
                #
                #Insert unique ID
                $collectorID = "$using:sumoCollectorID"
                (Get-Content -Path "$dest\sumo.conf").Replace("collectorID", $collectorID) | Set-Content -Path "$dest\sumo.conf"
                
                $installerFileName = "SumoCollector_windows-x64_19_182-25.exe"
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
						break   #success
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

		# One day can split this to 'install java' and 'configure java environemnt' and use 'package' dsc like here:
		# http://stackoverflow.com/questions/31562451/installing-jre-using-powershell-dsc-hangs
        Script Install_Java
        {
            DependsOn  = "[xRemoteFile]Download_Java_Installer"
            GetScript  = { @{ Result = "Install_Java" } }

            #TODO: Just check for a directory being present? What to do when Java version changes? (Can also check registry key as in SetScript.)
            TestScript = {
				if ( Get-Item -path "$using:JavaBinLocation" -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
                Write-Verbose "Install_Java"

				# Run the installer. Start-Process does not work due to permissions issue however '&' calling will not wait so looks for registry key as 'completion.'
				# Start-Process $LocalDLPath\$javaInstaller -ArgumentList '/s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"' -Wait
				& "$using:LocalDLPath\$using:javaInstaller" /s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"

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

				$Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"

				#set path. Don't add strings that are already there...

				$NewPath = (Get-ItemProperty -Path "$Reg" -Name PATH).Path

				#put java path in front of the oracle defined path
				if ($NewPath -notlike "*"+$using:JavaBinLocation+"*")
				{
				  $NewPath= $using:JavaBinLocation + ’;’ + $NewPath
				}

				Set-ItemProperty -Path "$Reg" -Name PATH –Value $NewPath
				Set-ItemProperty -Path "$Reg" -Name JAVA_HOME –Value $using:JavaRootLocation
				Set-ItemProperty -Path "$Reg" -Name classpath –Value $using:JavaLibLocation



				Write-Host "Waiting for JVM.dll"
				$JVMServerdll = $using:JREHome + "\bin\server\jvm.dll"

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

				$ServerXMLFile = $CatalinaHomeLocation + '\conf\server.xml'

				#make sure we get a clean install
				Remove-Item $using:localtomcatpath -Force -Recurse -ErrorAction SilentlyContinue

				Expand-Archive "$using:LocalDLPath\$using:tomcatInstaller" -DestinationPath $using:localtomcatpath


				Write-Host "Setting Paths and Tomcat environment"



				$Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"

				$NewPath = (Get-ItemProperty -Path "$Reg" -Name PATH).Path

				#put tomcat path at the end
				if ($NewPath -notlike "*"+$using:CatalinaBinLocation+"*")
				{
				  $NewPath= $NewPath + ’;’ + $using:CatalinaBinLocation
				}

				Set-ItemProperty -Path "$Reg" -Name PATH –Value $NewPath
				Set-ItemProperty -Path "$Reg" -Name CATALINA_BASE –Value $using:CatalinaHomeLocation
				Set-ItemProperty -Path "$Reg" -Name CATALINA_HOME –Value $using:CatalinaHomeLocation

				#set the current environment CATALINE_HOME as well since the service installer will need that
				$env:CATALINA_BASE = $using:CatalinaHomeLocation
				$env:CATALINA_HOME = $using:CatalinaHomeLocation


				Write-Host "Configuring Tomcat"

				#back up server.xml file if not done in a previous round
				if( -not ( Get-Item ($using:CatalinaHomeLocation + '\conf\server.xml.orig') -ErrorAction SilentlyContinue ) )
				{
					Copy-Item -Path ($ServerXMLFile) `
						-Destination ($using:CatalinaHomeLocation + '\conf\server.xml.orig')
				}

				#update server.xml file
				$xml = [xml](Get-Content ($using:CatalinaHomeLocation + '\conf\server.xml.orig'))

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

				$xml.Server.Service.InsertBefore(
					# new child
					$xml.ImportNode($NewConnector.Connector,$true),
					#ref child
					$xml.Server.Service.Engine )

				$xml.save($ServerXMLFile)



				Write-Host "Opening port 8443"

				#open port in firewall
				netsh advfirewall firewall add rule name="Open Port 8443" dir=in action=allow protocol=TCP localport=8443

				# Install and start service for new config

				& "$using:CatalinaBinLocation\service.bat" install
				Write-Host "Tomcat Installer exit code: $LASTEXITCODE"
				Start-Sleep -s 10  #TODO: Is this sleep ACTUALLY needed?

				Write-Host "Starting Tomcat Service"
				Set-Service Tomcat8 -startuptype "automatic"

				# Reboot machine - seems to need to happen to get Tomcat to run reliably or is there a big delay required? reboot for now :)
				$global:DSCMachineStatus = 1
	        }
        }

        Script Install_Broker
        {
            DependsOn  = @("[xRemoteFile]Download_Broker_WAR", "[Script]Install_Tomcat")
            GetScript  = { @{ Result = "Install_Broker" } }

            #TODO: Check for other agent types as well?
            TestScript = {
				$WARPath = $using:CatalinaHomeLocation + "\webapps" + $using:brokerWAR
 
				if ( Get-Item $WARPath -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
                Write-Verbose "Install_Broker"

				copy $using:LocalDLPath\$using:brokerWAR ($using:CatalinaHomeLocation + "\webapps")

				$svc = get-service Tomcat8
				if ($svc.Status -ne "Stopped") {$svc.stop()}

				Write-Host "Generating broker configuration file."
				$targetDir = $using:catalinaHomeLocation + "\brokerproperty"
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

				$localAdminCreds = $using:Admincreds
				$adminUsername = $localAdminCreds.GetNetworkCredential().Username
				$adminPassword = $localAdminCreds.GetNetworkCredential().Password


				$cbProperties = @"
ldapHost=ldaps://$Using:dcvmfqdn
ldapAdminUsername=$adminUsername
ldapAdminPassword=$adminPassword
ldapDomain=$Using:domaindns
brokerHostName=$Using:pbvmfqdn
brokerProductName=CAS Connection Broker
brokerPlatform=$Using:family
brokerProductVersion=1.0
brokerIpaddress=$ipaddressString
brokerLocale=en_US
"@

				Set-Content $cbPropertiesFile $cbProperties
				Write-Host "Broker configuration file generated."

				$backupPropertiesFile = New-Item "c:\backupCBProperties.txt" -type file
				Set-Content $backupPropertiesFile $cbProperties

				#----- setup security trust for LDAP certificate from DC -----

				#first, setup the Java options
				$Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"

				$jo_string = "-Djavax.net.ssl.trustStore=$using:JavaRootLocation\jre\lib\security\ldapcertkeystore.jks;-Djavax.net.ssl.trustStoreType=JKS;-Djavax.net.ssl.trustStorePassword=changeit"
				Set-ItemProperty -Path "$Reg" -Name PR_JVMOPTIONS –Value $jo_string

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

					$DCSession = New-PSSession $using:dcvmfqdn -Credential $using:Admincreds

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
									Export-Certificate -Cert $issuerCert -filepath  $icloc -force

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

				# Have the certificate file, add to a keystore 
		        Remove-Item "$env:systemdrive\ldapcertkeystore.jks" -ErrorAction SilentlyContinue

                # keytool seems to be causing an error but succeeding. Ignore and continue.
                $eap = $ErrorActionPreference
                $ErrorActionPreference = 'SilentlyContinue'
				& "keytool" -import -file "$env:systemdrive\$issuerCertFileName" -keystore "$env:systemdrive\ldapcertkeystore.jks" -storepass changeit -noprompt
                $ErrorActionPreference = $eap

		        Copy-Item "$env:systemdrive\ldapcertkeystore.jks" -Destination ($env:classpath + "\security")

		        Write-Host "Finished! Restarting Tomcat."

				Restart-Service Tomcat8
            }
        }
    }
}

