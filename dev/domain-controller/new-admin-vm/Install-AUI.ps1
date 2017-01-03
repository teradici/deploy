# Install-AUI.ps1
Configuration InstallAUI
{
	# One day pull rom Oracle as per here? https://github.com/gregjhogan/cJre8/blob/master/DSCResources/cJre8/cJre8.schema.psm1
    param
    (
        [string]
        $LocalDLPath = "$env:systemdrive\WindowsAzure\PCoIPAUIInstall",

        [string]
        $sourceURI = "https://teradeploy.blob.core.windows.net/binaries",

        [string]
        $javaInstaller = "jdk-8u91-windows-x64.exe"
    )

    Node "localhost"
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

        File Download_Directory 
        {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = $LocalDLPath
        }

		Import-DscResource -ModuleName xPSDesiredStateConfiguration

		xRemoteFile Download_Java_Installer
		{
			Uri = "$sourceURI/$javaInstaller"
			DestinationPath = "$LocalDLPath\$javaInstaller"
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

        Script Install_AUI
        {
            DependsOn  = "[Script]Install_Java"
            GetScript  = { @{ Result = "Install_AUI" } }

            #TODO: Check for other agent types as well?
            TestScript = { if ( $true ) # Get-Item -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PCoIP Standard Agent" -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false} }
            SetScript  = {
                Write-Verbose "Install_AUI"
            }
        }

    }
}

