# What is Cloud Access Manager? #

[Teradici Cloud Access Manager](https://www.teradici.com/products/cloud-access/cloud-access-manager)
is a cloud service that simplifies and automates
deployments of Cloud Access Software.

## Deploying Cloud Access Manager ##

The Cloud Access Manager solution is deployed in your Microsoft Azure
subscription by running a few instructions in an Azure PowerShell
Cloud Shell session. Click on the following link for Cloud Access
Manager documentation:

[Instructions for deploying Cloud Access Manager](http://www.teradici.com/web-help/pcoip_cloud_access_manager/current/)

# Creating your own fork of Cloud Access Manager #

## Copying Artifacts and Binaries to Azure Storage Blob
This section outlines how to ensure that Cloud Access Connectors deployments are always the same version and stable, and are only updated after an internal review by copying the required artifacts and binaries to the Azure Storage Blob:

1. Create a publicly accessible copy of the https://github.com/teradici/deploy repository.
2. Create a public file store to store the required binaries for example, Azure Blob storage or S3 bucket. 
3. In Azure, create a Storage Account. Names must be globally unique to Azure:
```PowerShell
New-AzureRmResourceGroup -Name <ResourceGroupName> -Location <Location>
$acct = New-AzureRmStorageAccount -ResourceGroupName <ResourceGroupName> -AccountName <StorageAccountName> -Location <Location> -SKuName "Standard_LRS" -EnableHttpsTrafficOnly $false
```
4. Within that Storage Account create a container and set the permissions to be at the container level so that everything in it is publicly accessible.
```PowerShell
$container = New-AzureStorageContainer -Name <ContainerName> -Context $acct.Context -ErrorAction Stop -Permission Container
```
5. Upload the following files to the container:
    - PCoIP Connection Broker: https://teradeploy.blob.core.windows.net/binaries/pcoip-broker.war
    - CAM Management Interface: https://teradeploy.blob.core.windows.net/binaries/CloudAccessManager.war
    - Connection Manager/Security Gateway setup files: https://teradeploy.blob.core.windows.net/binaries/CM_SG.zip
    - Windows DSC script for provisioning Windows Remote Workstations: https://teradeploy.blob.core.windows.net/binaries/Install-PCoIPAgent.ps1.zip
    - Windows DSC script for provisioning a stand-alone Domain Controller for testing: https://teradeploy.blob.core.windows.net/binaries/Install-DC-and-CA.ps1.zip
    - Windows DSC script for provisioning Connection Server machine to run PCoIP Broker and Management Interface: https://teradeploy.blob.core.windows.net/binaries/Install-ConnectionServer.ps1.zip
    - Apache Tomcat binary used for running PCoIP Broker and Management Interface: https://teradeploy.blob.core.windows.net/binaries/apache-tomcat-8.5.47-windows-x64.zip
    - NVIDIA Grid Driver for Windows: https://teradeploy.blob.core.windows.net/binaries/391.58_grid_win10_server2016_64bit_international.exe
    - NVIDIA Grid Driver for Linux: https://teradeploy.blob.core.windows.net/binaries/NVIDIA-Linux-x86_64-390.57-grid.run
    - Java 8 JDK Installer: https://teradeploy.blob.core.windows.net/binaries/jdk-8u144-windows-x64.exe
    - OpenSSL for Windows binary used for downloading Domain Controller's LDAPS certificates: https://teradeploy.blob.core.windows.net/binaries/Win64OpenSSL_Light-1_0_2o.exe
6. Copy the binaries using this CloudShell script:
```PowerShell
mkdir $home/clouddrive/binaries
cd $home/clouddrive/binaries
$binaries = @(
"https://teradeploy.blob.core.windows.net/binaries/pcoip-broker.war",
"https://teradeploy.blob.core.windows.net/binaries/CloudAccessManager.war",
"https://teradeploy.blob.core.windows.net/binaries/CM_SG.zip",
"https://teradeploy.blob.core.windows.net/binaries/Install-PCoIPAgent.ps1.zip",
"https://teradeploy.blob.core.windows.net/binaries/Install-DC-and-CA.ps1.zip",
"https://teradeploy.blob.core.windows.net/binaries/Install-ConnectionServer.ps1.zip",
"https://teradeploy.blob.core.windows.net/binaries/apache-tomcat-8.5.47-windows-x64.zip",
"https://teradeploy.blob.core.windows.net/binaries/391.58_grid_win10_server2016_64bit_international.exe",
"https://teradeploy.blob.core.windows.net/binaries/NVIDIA-Linux-x86_64-390.57-grid.run",
"https://teradeploy.blob.core.windows.net/binaries/jdk-8u144-windows-x64.exe",
"https://teradeploy.blob.core.windows.net/binaries/Win64OpenSSL_Light-1_0_2o.exe")
ForEach ($binary in $binaries) {
    $fileName = ($binary -Split "/")[-1]
    Invoke-WebRequest `
        -Uri $binary `
        -OutFile $fileName
    Set-AzureStorageBlobContent `
        -Container $container.Name `
        -Context $acct.Context `
        -Blob "$fileName" `
        -File "./$fileName" `
        -Force
}
```
7. Run the `Deploy-CAM.ps1` script as you normal but specify the location of the source and binary files as follows:
```PowerShell
cd $home/clouddrive
Invoke-Webrequest -usebasicparsing "https://raw.githubusercontent.com/<yourGithubAccount>/deploy/master/Deploy-CAM.ps1" -OutFile Deploy-CAM.ps1
./Deploy-CAM.ps1 -binaryLocation <BaseUrlForContainer> -CAMDeploymentTemplateURI "https://raw.githubusercontent.com/<yourGithubAccount>/deploy/master/azuredeploy.json"
```

## Creating a DSC Zip File
This section outlines how to create a DSC zip file for the Cloud Access Connector for Azure:

1. Download the following required dependencies:
    - `Install-ConnectionServer`: 
        - xPSDeiredStateConfiguration v7.0.0.1 - https://github.com/dsccommunity/xPSDesiredStateConfiguration/archive/v7.0.0.tar.gz
    - `Install-PCoIPAgent`: 
        - xPSDeiredStateConfiguration v7.0.0.1 - https://github.com/dsccommunity/xPSDesiredStateConfiguration/archive/v7.0.0.tar.gz
    - `Install-DC-and-CA`: 
        - xActiveDirectory v2.16.0.0: https://github.com/dsccommunity/ActiveDirectoryDsc/archive/v2.16.0.tar.gz
        - xAdcsDeployment v1.2.0.0: https://github.com/dsccommunity/ActiveDirectoryCSDsc/archive/v1.2.0.tar.gz
        - xDisk v1.0: https://github.com/PowerShell/xDisk/archive/1.0-PSGallery.tar.gz
        - xNetworking v5.2.0.0: https://github.com/dsccommunity/NetworkingDsc/archive/v5.2.0.tar.gz
2. Create a folder with the DSC script at the root level.
3. Add each dependency to seperate folders, for example for `Install-ConnectionServer` the structure should look like:
    - dscmetadata.json
    - Install-ConnectionServer.ps1
    - xPSDesiredStateConfiguration\→ The contents of xPSDeiredStateConfiguration v7.0.0.1.tar.gz\xPSDesiredStateConfiguration-7.0.0.
3. The `dscmetadata.json` files is a simple JSON file that details location information for where to load modules from.
4. Zip ip the contents of the folders and name them appropriately. 

### Build DSC Zip Files with CloudShell
You can also run the following script in CloudShell to build the DSC zip files:

```PowerShell
$gitRepo="https://github.com/teradici/deploy.git"
$storageAccountName="<StorageAccountName>"
$stogareAccountResourceGroupName="<ResourceGroupName>"
$containerName="<ContainerName>"
mkdir -p $home/clouddrive/DSC/Install-PCoIPAgent
mkdir -p $home/clouddrive/DSC/Install-ConnectionServer
mkdir -p $home/clouddrive/DSC/Install-DC-and-CA
cd $home/clouddrive/DSC
git clone $gitRepo
 
cp ./deploy/remote-workstations/new-agent-vm/Install-PCoIPAgent.ps1 ./Install-PCoIPAgent/
cp ./deploy/connection-service/new-admin-vm/Install-ConnectionServer.ps1 ./Install-ConnectionServer/
cp ./deploy/root/configure-dc-and-ca/Install-DC-and-CA.ps1 ./Install-DC-and-CA/
cp -r ./deploy/root/configure-dc-and-ca/cDisk/ ./Install-DC-and-CA/
 
Invoke-WebRequest -Uri https://github.com/dsccommunity/xPSDesiredStateConfiguration/archive/v7.0.0.tar.gz -OutFile xPSDesiredStateConfiguration.tar.gz
mkdir xPSDesiredStateConfiguration
tar xf ./xPSDesiredStateConfiguration.tar.gz -C xPSDesiredStateConfiguration --strip-components 1
 
Invoke-WebRequest -Uri https://github.com/dsccommunity/ActiveDirectoryDsc/archive/v2.16.0.tar.gz -OutFile xActiveDirectory.tar.gz
mkdir xActiveDirectory
tar xf ./xActiveDirectory.tar.gz -C xActiveDirectory --strip-components 1
 
Invoke-WebRequest -Uri https://github.com/dsccommunity/ActiveDirectoryCSDsc/archive/v1.2.0.tar.gz -OutFile xAdcsDeployment.tar.gz
mkdir xAdcsDeployment
tar xf ./xAdcsDeployment.tar.gz -C xAdcsDeployment  --strip-components 1
 
Invoke-WebRequest -Uri https://github.com/PowerShell/xDisk/archive/1.0-PSGallery.tar.gz -OutFile xDisk.tar.gz
mkdir xDisk
tar xf ./xDisk.tar.gz -C xDisk --strip-components 1
 
Invoke-WebRequest -Uri https://github.com/dsccommunity/NetworkingDsc/archive/v5.2.0.tar.gz -OutFile xNetworking.tar.gz
mkdir xNetworking
tar xf ./xNetworking.tar.gz -C xNetworking --strip-components 1
 
cp -r xPSDesiredStateConfiguration ./Install-PCoIPAgent/
cp -r xPSDesiredStateConfiguration ./Install-ConnectionServer/
cp -r xActiveDirectory ./Install-DC-and-CA/
cp -r xAdcsDeployment ./Install-DC-and-CA/
cp -r xDisk ./Install-DC-and-CA/
cp -r xNetworking ./Install-DC-and-CA/
 
'{"Modules":["xPSDesiredStateConfiguration"]}' | Out-File ./Install-PCoIPAgent/dscmetadata.json
'{"Modules":["xPSDesiredStateConfiguration"]}' | Out-File ./Install-ConnectionServer/dscmetadata.json
'{"Modules":["xActiveDirectory","xAdcsDeployment","xDisk","xNetworking","cDisk"]}' | Out-File ./Install-DC-and-CA/dscmetadata.json
  
cd ./Install-PCoIPAgent
zip -qr ../Install-PCoIPAgent.ps1.zip .
cd ../Install-ConnectionServer
zip -qr ../Install-ConnectionServer.ps1.zip .
cd ../Install-DC-and-CA
zip -qr ../Install-DC-and-CA.ps1.zip .
cd ..
 
$dscs = @(
"Install-PCoIPAgent.ps1.zip",
"Install-DC-and-CA.ps1.zip",
"Install-ConnectionServer.ps1.zip")
 
$acct =  Get-AzureRmStorageAccount -Name $storageAccountName -ResourceGroupName $stogareAccountResourceGroupName
ForEach ($dsc in $dscs) {
    Set-AzureStorageBlobContent `
        -Container $containerName `
        -Context $acct.Context `
        -Blob "$dsc" `
        -File "./$dsc" `
        -Force
}
```


## License ##

Copyright (c) 2018 Teradici Corporation. All rights reserved.

With the exception of content based off of the Azure Quickstart Templates, the contents of this repository are otherwise licensed under the [MIT license](./LICENSE.md).

Azure Quickstart Templates are copyright (c) Microsoft Azure and licensed under the [MIT license](https://github.com/Azure/azure-quickstart-templates/blob/master/LICENSE).
