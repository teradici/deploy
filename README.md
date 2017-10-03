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

By default, the CAM deployment scripts will create a service principal account for CAM to use after deployment. In order for the CAM deployment scripts to create this service principal, you must pass an account to the **AzureAdminUsername** parameter which meets the following criteria:
1. The account must have owner access to the subscription (to be able to set access policies)
1. The account must be able to be programatically logged in without user interaction. This means:
   1. It must be an organizational account, not a Microsoft account.
   1. It must not require multi-factor authentication.

If you are not in posession of an account which meets the criteria, you must create a service principal account before deploying CAM.

There are multiple ways to manually create a service principal account. See [Creating a Service Principal Account](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal) for instructions on how to do it from the Azure portal. Once the service principal account has been created, complete the following steps so that CAM can use the account to sign in:
1. Give the service principal contributor access to a new resource group.
1. Deploy CAM into that resource group.
1. Enter the service principal name for **AzureAdminUsername.**
1. Enter the service principal secret for **AzureAdminPassword.**
1. Enter the service principal tenant ID for **Tenant ID** instead of null.

The CAM deployment will use the created service principal account to interact with Azure.

In some instances you are required to register the keyvault policy for the subscription prior to deployment. Visit [Common Deployment Errors](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-common-deployment-errors#noregisteredproviderfound) for instructions on how to do this.


## Deployment Parameters
The following parameters are the form fields you are required to fill in on the template in the Microsoft Azure Portal to begin deploying CAM:
* domainAdminUsername: The name of the administrator account to be created for the domain.
  * This username must be short form and not a User Principal Name (UPN). For example 'uname' is allowed and 'uname@example.com' is not allowed. There are certain names such as 'administrator' which are also not allowed. See [FAQs about Windows Virtual Machines.](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/faq)
  * You create this new domain account prior to deploying CAM. It is not an existing domain account.
  * This account's username and password also becomes the local admin account for each created machine.
* domainAdminPassword: The password for the administrator account of the new VM's and domain.
   * You create this new password for your unique domain account account prior to deploying CAM. It is not an existing password.
* domainName: The FQDN of the Active Directory Domain to be created. **Must have a '.' like example.com or domain.local.**
  * The domain name does not need to be unique to get the system operational so if you're testing an isolated system you can use the same name for your deployments like 'mydomain.com.'
* AzureAdminUsername: The UPN name of the Azure account with **owner** access to the subscription. This account cannot require MFA, or be a Service Principal, for example: uname@example.com.
  * This account is only required to deploy the system. During deployment it will create an application in the Azure Active Directory account associated with the current Azure subscription. The application name is 'CAM-\<resourceGroupName\>'. It will also create a Service Principal account as part of this application which has contributor access to the resource group it is being deployed to. After deployment, only the Service Principal account is used for interaction with Azure API's.
  * You must have a real Azure Admin Account with the correct rights to deploy CAM.
* AzureAdminPassword: The password of the Azure account with **owner** access to the subscription.
* tenantID: The Azure Active Directory TenantID for the directory that manages the Azure subscription. Leave this as **null** unless you have pre-created a Service Principal account to manage the subscription.
* registrationCode: The license registration code for the PCoIP CAS licenses. The CAS registration code is sent to you in an email once you have purchased a CAS license.
* adminVMBlobSource: The location of the blobs for admin GUI machine installation. Use the default unless you are specifically deploying with modified binaries.
* \_artifactsLocation: The location of resources that the template depends on. Use the default unless you are specifically deploying with modified templates or binaries.
* \_artifactsLocationSasToken: - an auto-generated token to access _artifactsLocation. If _artifactsLocation does not need an access token (which is the default) then this can be blank.
 
## Deploying Cloud Access Manager using Microsoft Azure
The CAM solution consists of the following components:
 * Deployment Cloud Server (This provides the administration GUI)
 * Domain Controller (This will contain an active directory)
 * Connection Broker
 * Security Gateway
 * One or more user applications
 * ARM Templates
 * External data stores (CAM creates a data storage account for all virtual hardrives.)
 * Keyvault (This securely contains the required authentication credentials.)

The following steps outline the procedure for performing a deployment of CAM using Microsoft Azure: 

Click the **Deploy Azure** button to  begin.

**NOTE:** Once you click the **Deploy Azure** button you will be taken to the Microsoft Azure account login page. It is important to read these steps to the end prior to clicking deploy or re-opening this file afterwards.

**NOTE:** In general it takes over an hour for the deployment to complete.

<a target="_blank" href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fazuredeploy.json">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

1. Select the Microsoft Azure account you want to access.
1. Enter your Password and click **Sign in.**
1. On the Customized Template page create a new Resource group by selecting the **Create New** icon and entering a name for the group. The Resource Group should be empty when you access the page.
    * You can also select a pre-defined Resource group by selecting the **Use Existing** icon and clicking on one of the groups from the dropdown menu.
4. Select a location from the dropdown menu.
5. Enter a Username for the **domainAdminUsername**. This is a new account.
6. Enter a password for the **domainAdminPassword**. This is a new password.
7. Enter a **domainName** and ensure it finishes in **.com**.
8. Enter your **AzureAdminUsername**. This must be the same account you logged into from step 1.
9. Enter your **AzureAdminPassword**. This must be the same password you used to log in from step 2.
10. Enter the CAS license registration code for the **registrationCode**.
11. Use the default addresses that are pre-entered for the **adminVMBlobSource** and **_artifactsLocation**. 
12. Read the Terms and Conditions and once you are satisified with the information you have entered click the **I Agree** icon.
13. Click **Purchase** to begin deployment.

The deployment will now begin to run. 

You can track it through the notifications icon or for a more detailed view of your deployment click the **Resource Groups** icon in the Azure portal and click on your resource group.


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
 1. Create the local parameters file by calling
   ```
   Invoke-Webrequest -Uri "https://raw.githubusercontent.com/teradici/deploy/master/azuredeploy.parameters.json" -OutFile "my.azuredeploy.parameters.json"
   ```
 3. Modify <samp>my.azuredeploy.parameters.json</samp> to include the necessary deployment parameters.
 1. Run the following script, substituting username, password, resource group name, and desired region:

```
$spUsername = "<username>@<example>.com"
$spPass = ConvertTo-SecureString "<password>" -AsPlainText -Force
$cred = New-Object -TypeName pscredential -ArgumentList $spUsername, $spPass
Login-AzureRMAccount -Credential $cred

$azureRGName = "<rgname>"
New-AzureRMResourceGroup -Name $azureRGName -Location "East US"
New-AzureRMResourceGroupDeployment -DeploymentName "ad1" -ResourceGroupName $azureRGName -TemplateFile "https://raw.githubusercontent.com/teradici/deploy/master/azuredeploy.json" -TemplateParameterFile "my.azuredeploy.parameters.json"

```

If you do not want credentials in the file just go directly to <samp>Login-AzureAccount</samp> without the <samp>-Credential</samp> parameter and it will give you a prompt.

Copyright 2017 Teradici Corporation. All Rights Reserved.

Some content is based off of the Azure Quickstart Templates, Copyright (c) Microsoft Azure. With the following license: https://github.com/Azure/azure-quickstart-templates/blob/master/LICENSE
