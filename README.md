# What is Cloud Access Manager?
Teradici Cloud Access Manager (CAM) is a one click deployment solution that provides a level of brokering on top of new Cloud Access Software (CAS) deployments. CAM will enable you to assign and revoke virtual machines to users, turn virtual machines on or off, as well as create and destroy virtual machines. 
 
The CAM solution is deployed in your Microsoft Azure subscription with an ARM template provided by Teradici. Once you have completed the template form on the Microsoft Azure Portal, you can start deployment. Information on deploying CAM, as well as additional information on the solutions architecture and deployment parameters are in the following sections.
 
The following image gives an outline of the CAM Technical Preview Architecture:

**CAM Architecture**

![Img](http://www.teradici.com/web-help/CAM/CAMPOCDiagram.png)


# Provisioning Template

The following template outlines the account requirements, deployment parameters, deployment procedures and post-deployment capabilities that the solution provides. 

## Deployment Prerequisites

You must have an Azure account and subscription. You must have a valid registration code for Teradici Cloud Access Software (CAS) to be able successfully connect to, and deploy, CAM. To purchase a CAS license or for more information on the solution visit [Teradici Cloud Access Software.](http://www.teradici.com/products/cloud-access/cloud-access-software)

**NOTE:** To learn how to deploy CAS on Microsoft Azure go to [Deploy Teradici Cloud Access Software on Azure.](https://github.com/teradici/pcoip-agent-azure-templates/blob/master/README.md)

By default, the CAM deployment scripts will create a service principal account for CAM to use after deployment. In order for the CAM deployment scripts to create this service principal, you must sign into Azure with an account which meets the following criteria:
* The account must have owner access to the subscription (to be able to set access policies)

If you are not in posession of an account which meets the criteria, you must create a service principal account before deploying CAM.

There are multiple ways to manually create a service principal account. See [Creating a Service Principal Account](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal) for instructions on how to do it from the Azure portal. Be sure to give the service principal account contributor access to the resource group that CAM is being deployed to. This may involve creating the Resource Group manually before starting the deployment.

The CAM deployment will use the created service principal account to interact with Azure.

In some instances you are required to register the keyvault policy for the subscription prior to deployment. Visit [Common Deployment Errors](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-common-deployment-errors#noregisteredproviderfound) for instructions on how to do this.


## Deployment Parameters
The following parameters are required to to begin deploying CAM:
* Administrative Domain User Credentials: The desired credentials for the administrator account to be created for the domain.
  * The username must be short form and not a User Principal Name (UPN). For example 'uname' is allowed and 'uname@example.com' is not allowed. There are certain names such as 'administrator' which are also not allowed. See [FAQs about Windows Virtual Machines.](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/faq)
  * It must not be an existing domain account.
* Domain Name: The FQDN of the Active Directory Domain to be created. **Must have a '.' like example.com or domain.local.**
  * The domain name does not need to be unique to get the system operational so if you're testing an isolated system you can use the same name for your deployments like 'mydomain.com.'
* Registration Code: The license registration code for the PCoIP CAS licenses. The CAS registration code is sent to you in an email once you have purchased a CAS license.
* *(Optional)* Service Principal Account: A manually generated Service Principal Account can be provided to be used by CAM. Otherwise one will be generated for CAM automatically.
 
## Deploying Cloud Access Manager with Azure Cloud Shell
The CAM solution consists of the following components:
 * Deployment Cloud Server (This provides the administration GUI)
 * Domain Controller (This will contain an active directory)
 * Connection Broker
 * Security Gateway
 * One or more user applications
 * ARM Templates
 * External data stores (CAM creates a data storage account for all virtual hardrives.)
 * Private data stores (CAM creates a data storage account for all Remote Workstation templates, configurations and scripts.)
 * Keyvault (This securely contains the required authentication credentials.)

The following steps outline the procedure for performing a deployment of CAM using Microsoft Azure: 

Click the **Deploy Azure** button to begin.

**NOTE:** Once you click the **Deploy Azure** button you will be taken to the Microsoft Azure account login page. It is important to read these steps to the end prior to clicking deploy or re-opening this file afterwards.

**NOTE:** In general it takes over an hour for the deployment to complete.

**NOTE:** By clicking one of the following Deploy on Azure buttons, you accept the terms of the Teradici Cloud Access Software End User License Agreement and you have read and agree to be bound by the software license for use of the third-party drivers.

<a target="_blank" href="https://portal.azure.com/">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

1. Select the Microsoft Azure account you want to use.
1. Enter your Password and click **Sign in.**
1. Launch an Azure Cloud Shell Powershell instance by clicking the Cloud Shell icon from the top panel of the Azure Portal (top right corner of the Azure Portal, close to the search bar). See [Overiew of Azure Cloud Shell](https://docs.microsoft.com/en-ca/azure/cloud-shell/overview?view=azurermps-5.0.0) for details on how to set this up. The rest of the setup steps will be run in the Azure Cloud Shell. It is recomended to maximize the Cloud Shell window so prompts can be properly seen.
1. Change to your Home directory.
    ```
    cd $HOME\
    ```
1. Download the CAM Deployment script.
    ```
    Invoke-WebRequest -URI https://raw.githubusercontent.com/teradici/deploy/bd/Deploy-CAM.ps1 -OutFile .\Deploy-CAM.ps1
    ```
1. Run the CAM Deployment script. This script can be run interactivley through prompts or directly through the command line. To run it interactvley, run the following command:
    ```
    .\Deploy-CAM.ps1
    ```
    1. You may now be prompted to select a subscription to use to deploy CAM in. Choose the number accordingly.
    1. Existing Resource Groups will be listed if there are Resource Groups available for CAM to be deployed into. Either select an existing Resource Group by selecting the number next to desired Resource Group or create a new Resource Group by providing a name for the new Resource Group.
    1. Available deployment locations will be listed. Select a location from one of the listed options by typing in the *Location* field for the desired location.
    1. Enter the desired username and password for the **Administrative Domain User**. This is a new account that will be created.
    1. Enter a **Domain Name** and ensure it finishes in *.something* (eg, *.com, .local, etc*).
    1. Enter the CAS license registration code for the **Registration Code**.
    1. When prompted for Service Principal credentials, either press 'Enter' to continue and let the script generate them or enter 'no' to provide manually generated credentials.

Alternativley, the prompts can be skipped by providing required parameters directly as follows:
    
    $domainCredentials = Get-Credential
    $secureRegistrationCode = ConvertTo-SecureString <Registration-Code> -AsPlainText -Force
    .\Deploy-CAM.ps1 `
        -domainAdminCredential $domainCredentials `
        -domainName <Domain-Name> `
        -registrationCode $secureRegistrationCode `
        -ResourceGroupName <Resource-Group-Name> `
        -location <Location-Code>
    
If you wish to provide your own Service Principal Credentials using this method, the additional parameter `-spCredential $spCredential` is required where `$spCredential` is set by:

    $spCredential = New-Object -TypeName pscredential -ArgumentList <Service-Principal-Client-ID>, (ConvertTo-SecureString <Service-Principal-Client-Secret> -AsPlainText -Force)

The deployment will now begin to run. 

You can track it through the Azure Portal. For a detailed view of your deployment click the **Resource Groups** icon in the Azure portal and click on your resource group.

**NOTE:** The Azure Cloud Shell will disconnect after 20 minutes of inactivity. This is expected behaviour. Once the deployment has begun, Azure will handle processing the deployment and the Azure Cloud Shell is no longer needed.

## Known Issues with Deploying the Solution

* This solution will only deploy machines in one region. If you wish to use NV series virtual machines for GPU accelerated graphics, then you must deploy the complete solution into one of the supported regions for NV series instance types. Currently this is limited to the following locations: EAST US, NORTH CENTRAL US, SOUTH CENTRAL US, SOUTH EAST ASIA and WEST EUROPE.
* For a smooth deployment, please ensure that your usernames and passwords meet Azure requirements. See [FAQs about Windows Virtual Machines.](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/faq)
* Occasionally other failures can happen such as 'timeout' or 'can't start WinRM service.' Start a new deployment from scratch in a new resource group and attempt to re-deploy.
* A common deployment failure is when the quota is reached for the subscription. In this case you have to either remove or deallocate virtual machines from the subscription, or request a core quota increase from Microsoft to alleviate the problem.
* If deployment fails with an error message stating 'Cannot find resource group < name >,' then this often occurs because the AzureAdminUsername account is associated with a different Microsoft Azure subscription than the subscription in which CAM is being deployed. Ensure that the AzureAdminUsername account manages the same Azure subscription that is being used for the deployment.
* If deployment fails with a message relating to a 'Keyvault error' then you may need to register Microsoft.Keyvault for the subscription and then re-deploy.
* If deployment fails with MSFT_xRemoteFile errors or issues in relation to the application gateway, then creating a new deployment in a new, empty resource group should correct it. This error is not related to incorrect parameters. 

## Post-Deployment Capabilities
Following successfull deployment of the CAM solution you can perform the following functions:
* **Administer the solution-**
  * To administer the deployment through the Cloud Access Manager GUI, https: to the public IP of the applicationGateway1 Application Gateway and login with the domain administrator credentials.
* **Connect to the pre-created desktop VM for the domain administrator-**
  * To connect to the pre-created Agent virtual machine, point the PCoIP client to the public IP of the applicationGateway1 Application gateway and login with the domain administrator credentials. To download the PCoIP client visit [PCoIP Client Downloads.](http://www.teradici.com/product-finder/client-downloads)
* **Connect to user provisioned machines-**
  * After new users have been created in the domain and machines have been provisioned for them, users can login to their PCoIP sessions by pointing the PCoIP client to the public IP of the applicationGateway1 Application gateway and login with the user credentials. 
* **Manage the domain-**
  * To manage the Active Directory Domain, RDP to the public IP address of vm-dc (the domain controller).
 
### Deploying Cloud Access Manager using Microsoft PowerShell

The following section outlines the procedure for performing a deployment of CAM using Microsoft PowerShell as an alternate method to using the Microsoft Azure Portal.

**Prerequisites**

Ensure that you have AzureRM and NuGet installed:

```
Install-packageProvider -Name NuGet -Force 
Install-Module -Name AzureRM -Force
```

1. Run Microsoft Powershell.
1. Log into Azure using one of the following methods

    a. Log in using Service Principal Account credentials:
    ```
    $spTenantId = "<Service-Principal-Tenant-ID>"
    $cred = Get-Credentials
    Login-AzureRMAccount -Credential $cred -tenantId $spTenantId
    ```
    b. Log in using Azure Credentials
    ```
    Login-AzureRMAccount
    ```
1. Follow the instructions from step 5 of the Azure Cloud Shell deployments instructions above.

Copyright 2017 Teradici Corporation. All Rights Reserved.

Some content is based off of the Azure Quickstart Templates, Copyright (c) Microsoft Azure. With the following license: https://github.com/Azure/azure-quickstart-templates/blob/master/LICENSE
