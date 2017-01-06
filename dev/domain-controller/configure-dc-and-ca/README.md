# For an existing Virtual Machine, promote to Domain Controller of a new forest and also make it a CA for certificate services

If order to create the .DSC package (Install-DC-and-CA.ps1.zip) you need to be able to run a command like this:

Publish-AzureVMDscConfiguration -ConfigurationPath .\configure-dc-and-ca\Install-DC-and-CA.ps1  -ContainerName $StorageContainer -StorageContext $StorageContext -Force

In order for that to work, the custom cDisk package needs to be installed in the system generating the package.

The cDisk package used here seems to be an older version of the package referenced here: https://github.com/MickyBalladelli/cDisk

To install cDisk, copy the cDisk subfolder (NOT the one in MickyBalladelli's repo) to one of the folders in the PowerShell modules path.

How to find the folders? (Get-ChildItem Env:\PSModulePath).Value

Often, C:\Program Files\WindowsPowerShell\Modules should be there.

To ensure cDisk was installed you can use: Get-Module -ListAvailable and check for cDisk.


Also a number of standard Modules need to be installed for DSC packaging. Example: (please add to the list as you find out more.)
Install-Module –Name xAdcsDeployment

To find the other needed modules, you may need to do a search through the supported Microsoft repositories. Example:

$allResources = Find-DscResource
$allResources | Where-Object {$_.Modulename -like '*adcs*'} # This will find the xAdcsDeployment module you cna then install
