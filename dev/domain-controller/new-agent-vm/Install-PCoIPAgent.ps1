# Install-PCoIPAgent.ps1
Configuration InstallPCoIPAgent
{
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

