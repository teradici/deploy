# Install-AUI.ps1
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

#        File Download_Directory 
#        {
#            Ensure          = "Present"
#            Type            = "Directory"
#            DestinationPath = $LocalDLPath
#        }

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

		xRemoteFile Download_Admin_WAR
		{
			Uri = "$sourceURI/$adminWAR"
			DestinationPath = "$LocalDLPath\$adminWAR"
		}

        Script Install_Java
        {
            DependsOn  = "[xRemoteFile]Download_Java_Installer"
            GetScript  = { @{ Result = "Install_Java" } }

            #TODO: Just check for a directory being present? What to do when Java version changes?
            TestScript = { 
							$JavaRootLocation = "$env:systemdrive\Program Files\Java\jdk1.8.0_91"
		                	$JavaBinLocation = $JavaRootLocation + "\bin"
				if ( Get-Item -path "$JavaBinLocation" -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
                Write-Verbose "Install_Java"

				#Why do you need to use Start-Process? Don't know.
				Start-Process $LocalDLPath\$javaInstaller -ArgumentList '/s ADDLOCAL="ToolsFeature,SourceFeature,PublicjreFeature"' -Wait

				Write-Host "Setting up paths and environment"

				#setup path and environment

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
            }
        }

		Script Install_Tomcat
        {
            DependsOn  = @("[xRemoteFile]Download_Tomcat_Installer", "[Script]Install_Java")
            GetScript  = { @{ Result = "Install_Tomcat" } }

            TestScript = { 
				if ( get-service Tomcat8 -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
                Write-Verbose "Install_Tomcat"

				#Why do you need to use Start-Process? Don't know.
				Start-Process $LocalDLPath\$tomcatInstaller -ArgumentList '/S' -Wait

				Set-Service Tomcat8 -startuptype "automatic"

				Write-Host "Setting Paths and Tomcat environment"

				$CatalinaHomeLocation ="$env:systemdrive\Program Files\Apache Software Foundation\Tomcat 8.0"
				$CatalinaBinLocation = $CatalinaHomeLocation + "\bin"
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
				Copy-Item -Path ($CatalinaHomeLocation + '\conf\server.xml') `
					-Destination ($CatalinaHomeLocation + '\conf\server.xml.orig')

				#update server.xml file
				$xml = [xml](Get-Content ($CatalinaHomeLocation + '\conf\server.xml.orig'))

				$NewConnector = [xml] '<Connector
				port="8443"
				protocol="HTTP/1.1" SSLEnabled="true"
				keystoreFile="c:\dev\psbinaries\.keystore"
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

				$xml.save($CatalinaHomeLocation + '\conf\server.xml')

				Write-Host "Opening port 8443"

				#open port in firewall
				netsh advfirewall firewall add rule name="Open Port 8443" dir=in action=allow protocol=TCP localport=8443

				####### Maybe remove this later after moving more to machine name symantics ############
				# (Or at least use domain controller IP variable :) )
				Set-Item wsman:\localhost\client\trustedhosts 10.0.0.10 -Force

				# Reboot machine
				$global:DSCMachineStatus = 1 
	        }
        }

        Script Install_AUI
        {
            DependsOn  = @("[xRemoteFile]Download_Admin_WAR", "[Script]Install_Tomcat")
            GetScript  = { @{ Result = "Install_AUI" } }

            #TODO: Check for other agent types as well?
            TestScript = {
				$CatalinaHomeLocation ="$env:systemdrive\Program Files\Apache Software Foundation\Tomcat 8.0"
				$WARPath = $CatalinaHomeLocation + "\webapps" + $adminWAR
 
				if ( Get-Item $WARPath -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false}
			}
            SetScript  = {
				$CatalinaHomeLocation ="$env:systemdrive\Program Files\Apache Software Foundation\Tomcat 8.0"

                Write-Verbose "Install_AUI"

				copy $LocalDLPath\$adminWAR ($CatalinaHomeLocation + "\webapps")

            }
        }
    }
}

