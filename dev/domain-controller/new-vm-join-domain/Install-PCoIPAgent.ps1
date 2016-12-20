<# Custom Script for Windows to install a file from Azure Storage using the staging folder created by the deployment script #>
param (
    [string]$artifactsLocation,
    [string]$artifactsLocationSasToken,
    [string]$folderName,
    [string]$fileToInstall
)

#$source = $artifactsLocation + "\$folderName\$fileToInstall" + $artifactsLocationSasToken
#$dest = "C:\WindowsAzure\$folderName"
#New-Item -Path $dest -ItemType directory
#Invoke-WebRequest $source -OutFile "$dest\$fileToInstall"



$source = "https://teradeploy.blob.core.windows.net/pcoipagent/PCoIP_agent_release_installer_2.6.2.3771_standard.exe"
$dest = "C:\PCoIPAgentInstaller"
$installerFileName = "PCoIP_agent_release_installer_2.6.2.3771_standard.exe"
New-Item -Path $dest -ItemType directory
Invoke-WebRequest $source -OutFile "$dest\$installerFileName"

cd $dest

#stop any service that was running
Stop-Service PCoIPAgent 

#install the agent
& ".\$installerFileName" /S

#and wait until the service has started

$running = (Get-Service PCoIPAgent | Select -ExpandProperty Status -first 1) -eq "Running";
$loopCountRemaining = 1800; #seconds
#loop until it's installed and running
while($running -eq $false)
{
    if($loopCountRemaining % 10 -eq 0)
    {
        Write-Host "Waiting for Agent Install. Remaining: $loopCountRemaining"
    }

    Start-Sleep -Seconds 1;
    $running = (Get-Service PCoIPAgent -ErrorAction SilentlyContinue | Select -ExpandProperty Status -first 1) -eq "Running";
    $loopCountRemaining = $loopCountRemaining - 1
    if ($loopCountRemaining -eq 0)
    {
        throw "Install failed or took really long!"
    }
}




