# Install-AUI.ps1
# Compile to a local .zip file via this command:
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-AUI.ps1 -ConfigurationArchivePath .\Install-AUI.zip
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
# Publish-AzureVMDscConfiguration -ConfigurationPath .\Install-AUI.ps1  -ContainerName $StorageContainer -StorageContext $StorageContext
#
#
Configuration InstallAUI
{
	# One day pull from Oracle as per here? https://github.com/gregjhogan/cJre8/blob/master/DSCResources/cJre8/cJre8.schema.psm1
    param
    (
        [string]
        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPAUIInstall",

        [string]
        $sourceURI = "https://teradeploy.blob.core.windows.net/binaries",

        [string]
        $javaInstaller = "jdk-8u91-windows-x64.exe",

        [string]
        $tomcatInstaller = "apache-tomcat-8.0.33.exe",

        [string]
        $adminWAR = "Powershell_Admin.war"
    )

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

		        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPAUIInstall"
		        $javaInstaller = "jdk-8u91-windows-x64.exe"

				# Run the installer. Start-Process does not work due to permissions issue however '&' calling will not wait so looks for registry key as 'completion.'
				# Start-Process $LocalDLPath\$javaInstaller -ArgumentList '/s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"' -Wait
				& "$LocalDLPath\$javaInstaller" /s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"

				$retrycount = 1800
				while ($retryCount -gt 0)
				{
					$readyToConfigure = ( Get-Item "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{64A3A4F4-B792-11D6-A78A-00B0D0180910}"  -ErrorAction SilentlyContinue )

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

				# Reboot machine - seems to need to happen to get Tomcat to install???
				$global:DSCMachineStatus = 1
            }
        }



		#Package Tomcat8
  #      {
		#	Ensure = 'Present'
		#	Name = 'Apache Tomcat 8.0 Tomcat8 (remove only)'  #If no productID then this must match the 'DisplayName' value in the 'uninstall' portion of the registry
		#	Path = "$LocalDLPath\$tomcatInstaller"
		#	Arguments = '/S'
		#	ReturnCode = 2   #2? Why? Seems like an error but that's what happens now...
		#	ProductId = ''   #This is not needed and can be empty but then Name must match.
  #          DependsOn = @("[xRemoteFile]Download_Tomcat_Installer", "[Script]Install_Java")
		#}

		Script Install_Tomcat
        {
			 #doesn't really need Firefox but that makes sure the dependancies pull it in. (Do we need that or is jsut being part of the configuration okay? Probably okay...)
            DependsOn = @("[xRemoteFile]Download_Tomcat_Installer", "[Script]Install_Java", "[xRemoteFile]Download_Firefox", "[xRemoteFile]Download_Keystore")
#            DependsOn  = @("[Package]Tomcat8")
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

		        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPAUIInstall"
		        $tomcatInstaller = "apache-tomcat-8.0.33.exe"

				# Run the installer. Start-Process does not work due to permissions issue however '&' calling will not wait so looks for registry key as 'completion.'
				# Start-Process $LocalDLPath\$tomcatInstaller -ArgumentList '/S' -Wait
				& "$LocalDLPath\$tomcatInstaller" /S

				Write-Host "Tomcat Installer exit code: $LASTEXITCODE"


				# this may exit before install is complete - so wait for service and server.xml to show up before doing anything


				Write-Host "Setting Paths and Tomcat environment"

				$CatalinaHomeLocation ="$env:systemdrive\Program Files\Apache Software Foundation\Tomcat 8.0"
				$CatalinaBinLocation = $CatalinaHomeLocation + "\bin"
				$ServerXMLFile = $CatalinaHomeLocation + '\conf\server.xml'

				$retrycount = 1800
				while ($retryCount -gt 0)
				{
					$readyToConfigure = ( get-service Tomcat8 -ErrorAction SilentlyContinue )

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
							throw "Tomcat not installed in time."
						}
						else
						{
							Write-Host "Waiting for Tomcat to be created"
						}
					}
				}

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

				Write-Host "Configuring Tomcat"


				#back up server.xml file
				Copy-Item -Path ($ServerXMLFile) `
					-Destination ($CatalinaHomeLocation + '\conf\server.xml.orig')

				#update server.xml file
				$xml = [xml](Get-Content ($CatalinaHomeLocation + '\conf\server.xml.orig'))

				$NewConnector = [xml] '<Connector
				port="8443"
				protocol="HTTP/1.1" SSLEnabled="true"
				keystoreFile="'+$LocalDLPath+'\.keystore"
				maxThreads="2000" scheme="https" secure="true"
				clientAuth="false" sslProtocol="TLS"
				SSLEngine="on" keystorePass="changeit"
				SSLPassword="changeit"
				sslEnabledProtocols="TLSv1.0,TLSv1.1,TLSv1.2"
				ciphers="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA"
				/>'

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

				# Restart service for new config
				Write-Host "Starting Tomcat Service"
				Set-Service Tomcat8 -startuptype "automatic"
				Start-Sleep -s 10  #TODO: Is this sleep ACTUALLY needed?
				Start-Service Tomcat8
	        }
        }

        Script Install_AUI
        {
            DependsOn  = @("[xRemoteFile]Download_Admin_WAR", "[Script]Install_Tomcat")
            GetScript  = { @{ Result = "Install_AUI" } }

            #TODO: Check for other agent types as well?
            TestScript = {
				$CatalinaHomeLocation ="$env:systemdrive\Program Files\Apache Software Foundation\Tomcat 8.0"
				$adminWAR = "Powershell_Admin.war"
				$WARPath = $CatalinaHomeLocation + "\webapps" + $adminWAR
 
				if ( Get-Item $WARPath -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
				$LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPAUIInstall"
				$adminWAR = "Powershell_Admin.war"
				$CatalinaHomeLocation ="$env:systemdrive\Program Files\Apache Software Foundation\Tomcat 8.0"

                Write-Verbose "Install_AUI"

				copy $LocalDLPath\$adminWAR ($CatalinaHomeLocation + "\webapps")

            }
        }
    }
}

