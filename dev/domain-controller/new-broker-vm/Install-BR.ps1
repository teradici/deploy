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
        [String]$DCVMName #without the domain suffix
    )

	$dcvmfqdn = "$DCVMName.$DomainName"
	$pbvmfqdn = "$env:computername.$DomainName"
	$family   = "Windows Server 2016"
	$domaindns = $DomainName

    $adminUsername = $Admincreds.GetNetworkCredential().Username
    $adminPassword = $Admincreds.GetNetworkCredential().Password

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

		xRemoteFile Download_Broker_WAR
		{
			Uri = "$sourceURI/$brokerWAR"
			DestinationPath = "$LocalDLPath\$brokerWAR"
		}

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

		        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPBRInstall"
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

				# Reboot machine - seems to need to happen to get Tomcat to install??? Nope!
				#$global:DSCMachineStatus = 1
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

		        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPBRInstall"
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

				#back up server.xml file if not done in a previous round
				if( -not ( Get-Item ($CatalinaHomeLocation + '\conf\server.xml.orig') -ErrorAction SilentlyContinue ) )
				{
					Copy-Item -Path ($ServerXMLFile) `
						-Destination ($CatalinaHomeLocation + '\conf\server.xml.orig')
				}

				#update server.xml file
				$xml = [xml](Get-Content ($CatalinaHomeLocation + '\conf\server.xml.orig'))

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

				$xml.Server.Service.InsertBefore(
					# new child
					$xml.ImportNode($NewConnector.Connector,$true),
					#ref child
					$xml.Server.Service.Engine )

				$xml.save($ServerXMLFile)



				Write-Host "Opening port 8443"

				#open port in firewall
				netsh advfirewall firewall add rule name="Open Port 8443" dir=in action=allow protocol=TCP localport=8443

				####### TODO: Make this a parameter and what to do about DC HA? Names? ############
				Set-Item wsman:\localhost\client\trustedhosts 10.0.0.10 -Force

				# Reboot machine
				# $global:DSCMachineStatus = 1

				# Install and start service for new config

				& "$CatalinaBinLocation\service.bat" install
				Write-Host "Tomcat Installer exit code: $LASTEXITCODE"
				Start-Sleep -s 10  #TODO: Is this sleep ACTUALLY needed?

				Write-Host "Starting Tomcat Service"
				Set-Service Tomcat8 -startuptype "automatic"
				Start-Sleep -s 10  #TODO: Is this sleep ACTUALLY needed?
				Start-Service Tomcat8
	        }
        }

        Script Install_Broker
        {
            DependsOn  = @("[xRemoteFile]Download_Broker_WAR", "[Script]Install_Tomcat")
            GetScript  = { @{ Result = "Install_Broker" } }

            #TODO: Check for other agent types as well?
            TestScript = {
				$localtomcatpath = "$env:systemdrive\tomcat"
				$CatalinaHomeLocation = "$localtomcatpath\apache-tomcat-8.0.39"
				$brokerWAR = "pcoip-broker.war"
				$WARPath = $CatalinaHomeLocation + "\webapps" + $brokerWAR
 
				if ( Get-Item $WARPath -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
				$LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPBRInstall"
				$brokerWAR = "pcoip-broker.war"
				$localtomcatpath = "$env:systemdrive\tomcat"
				$CatalinaHomeLocation = "$localtomcatpath\apache-tomcat-8.0.39"

                Write-Verbose "Install_Broker"

				copy $LocalDLPath\$brokerWAR ($CatalinaHomeLocation + "\webapps")

				#Make sure the properties file exists - as enough proof that the .war file has been processed



		        #----- Update/overwrite the the file with configuration information -----
				# (Tomcat needs to be running for this to happen... Just kick it again in case.)
				Start-Service Tomcat8  -ErrorAction SilentlyContinue

				$cbPropertiesFile = $catalinaHomeLocation + "\webapps\pcoip-broker\WEB-INF\classes\connectionbroker.properties"

				$exists = $null
				$loopCountRemaining = 600
				#loop until it's created
				while($exists -eq $null)
				{
					Write-Host "Waiting for broker properties file. Seconds remaining: $loopCountRemaining"
					Start-Sleep -Seconds 1
					$exists = Get-Content $cbPropertiesFile -ErrorAction SilentlyContinue
					$loopCountRemaining = $loopCountRemaining - 1
					if ($loopCountRemaining -eq 0)
					{
						throw "No properties file!"
					}
				}
				Write-Host "Got broker configuration file. Updating."

				$firstIPv4IP = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"} | select -First 1

				$cbProperties = @"
ldapHost=ldaps://<FQDN of LDAP host>
ldapAdminUsername=<username>
ldapAdminPassword=<password>
ldapDomain=<domain name>
brokerHostName=<FQDN of broker machine>
brokerProductName=Primesoft Connection Broker
brokerPlatform=<operating system platform>
brokerProductVersion=1.0
brokerIpaddress=<host name or IP address of broker machine>
brokerLocale=en_US
"@

				$cbProperties = $cbProperties -replace "<FQDN of LDAP host>", $Using:dcvmfqdn
				$cbProperties = $cbProperties -replace "<username>", $Using:adminUsername
				$cbProperties = $cbProperties -replace "<password>", $Using:adminPassword
				$cbProperties = $cbProperties -replace "<domain name>", $Using:domaindns
				$cbProperties = $cbProperties -replace "<FQDN of broker machine>",$Using:pbvmfqdn
				$cbProperties = $cbProperties -replace "<operating system platform>",$Using:family
				$cbProperties = $cbProperties -replace "<host name or IP address of broker machine>", $firstIPv4IP.IPAddress

				Set-Content $cbPropertiesFile $cbProperties

				#----- setup security trust for LDAP certificate from DC -----

				#first, setup the Java options
				$JavaRootLocation = "C:\Program Files\Java\jdk1.8.0_91"
				$JavaBinLocation = $JavaRootLocation + "\bin"
				$JavaLibLocation = $JavaRootLocation + "\jre\lib"
				$Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"

				$jo_string = "-Djavax.net.ssl.trustStore=$JavaRootLocation\jre\lib\security\ldapcertkeystore.jks;-Djavax.net.ssl.trustStoreType=JKS;-Djavax.net.ssl.trustStorePassword=changeit"
				Set-ItemProperty -Path "$Reg" -Name PR_JVMOPTIONS –Value $jo_string

				#second, get the certificate file

				$ldapCertFileName = "ldapcert.cert"
				$certStoreLocationOnDC = "c:\" + $ldapCertFileName
				$certSubject = "CN=$using:dcvmfqdn"
		
				$DCSession = New-PSSession $using:dcvmfqdn -Credential $using:Admincreds
			    Invoke-Command $DCSession `
			      -ScriptBlock {
					  $cert = get-childItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -eq $using:certSubject }
					  Export-Certificate -Cert $cert -filepath $using:certStoreLocationOnDC -force
				}
				Copy-Item -Path $certStoreLocationOnDC -Destination . -FromSession $DCSession
				Remove-PSSession $DCSession

				# Have the certificate file, add to a keystore 
		        Remove-Item ldapcertkeystore.jks -ErrorAction SilentlyContinue
#				Start-Process keytool -ArgumentList '-import -file ldapcert.cert -keystore ldapcertkeystore.jks -storepass changeit -noprompt' -Wait
				& "keytool" -import -file ldapcert.cert -keystore ldapcertkeystore.jks -storepass changeit -noprompt
				 
		        Copy-Item ldapcertkeystore.jks -Destination ($env:classpath + "\security")

		        Write-Host "Finished! Restarting Tomcat."

				Restart-Service Tomcat8
            }
        }
    }
}

