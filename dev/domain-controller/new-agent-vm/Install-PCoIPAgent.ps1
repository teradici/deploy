# Install-PCoIPAgent.ps1
Configuration InstallPCoIPAgent
{
    Node "localhost"
    {
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
                $sumo_config = "/new-admin-vm/sumo.conf"
                $sumo_collector_json = "/new-admin-vm/sumo-admin-vm.json"
                $dest = "C:\sumo"
                Invoke-WebRequest $sumo_config -OutFile "$dest\sumo.conf"
                Invoke-WebRequest $sumo_collecor_json -OutFile "$dest\sumo-admin-vm.json"
	        	# Insert unique ID
        		(Get-Content "$dest\sumo.conf").Replace("collectorID", $using:sumoCollectorID) | Set-Content "$dest\sumo.conf"
                
                $installerFileName = "SumoCollector-windows-x64_19_182-25.exe"
		        Invoke-WebRequest $sumo_package -OutFile "$dest\$installerFileName"
                #install the collector
                & "$dest\$installerFileName" /S
            }
        }

        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

        File Download_Directory 
        {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = "C:\WindowsAzure\PCoIPAgentInstaller"
        }

        Script Install_PCoIPAgent
        {
            DependsOn  = "[File]Download_Directory"
            GetScript  = { @{ Result = "Install_PCoIPAgent" } }

            #TODO: Check for other agent types as well?
            TestScript = { if ( Get-Item -path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PCoIP Standard Agent" -ErrorAction SilentlyContinue )
                            {return $true}
                            else {return $false} }
            SetScript  = {
                Write-Verbose "Install_PCoIPAgent"

                $source = "https://teradeploy.blob.core.windows.net/binaries/PCoIP_agent_release_installer_2.7.0.4060_standard.exe"
                $dest = "C:\WindowsAzure\PCoIPAgentInstaller"
                $installerFileName = "PCoIP_agent_release_installer_2.7.0.4060_standard.exe"
                Invoke-WebRequest $source -OutFile "$dest\$installerFileName"

                #install the agent
                & "$dest\$installerFileName" /S
            }
        }
    }
}

