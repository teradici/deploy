 ## What is Cloud Access Manager?
 Teradici Cloud Access Manager (CAM) is a one click deployment solution that provides a level of brokering on top of existing CAS deployments. CAM will enable you to assign and revoke virtual machines to users as well as creating and destroying virtual workstations. The CAM solution consists of the following components:
 * Deployment Cloud Server
 * Domain Controller
 * Connection Broker
 * Security Gateway
 * Publicly available binaries
 * Licensing information
 * An Active Directory
 * One or more virtual workstations
 * ARM Templates
 * External data stores
 
 ## Account Requirements
In order to successfully deploy CAM you are required to have the following external data stores:
* Private Deployment Metadata
* Standard Deployment ARM Templates
* Standard Deployment DSC packages and binaries

NOTE: For customised deployments the Customer Deployment and DSC package and binaries store will need to be available.

You must have an Azure account and subscription that does not require multi-factor authentication. You must have a valid activation code for PCoIP Standard Agent to be able successfully connect and deploy CAM.  

## Deployment Parameters
* domainAdminUsername: The name of the administrator account to be created for the domain.
  * This username must be short form and not UPN. The name cannot be 'admin.'For example 'uname' is allowed and 'uname@example.com' is not allowed.
  * This accounts username and password also becomes the local admin account for each created machine.
* domainAdminPassword: The password for the administrator account of the new VM's and domain.
* domainName: The FQDN of the Active Directory Domain to be created. **Must have a '.' like example.com or domain.local.**
  * The domain name does not need to be unique to get the system operational so if you're testing an isolated system you can use the same name for your deployments like 'mydomain.com.'
* AzureAdminUsername: The UPN name of the Azure account with **owner** access to the subscription. This account cannot require MFA, or be a Service Principal, for example: uname@example.com.
  * This account is only required to deploy the system. During deployment it will create an application in the Azure Active Directory account associated with the current Azure subscription. The application name is 'CAM-\<resourceGroupName\>'. It will also create a Service Principal account as part of this application which has contributor access to the resource group it is being deployed to. After deployment, only the Service Principal account is used for interaction with Azure API's.
* AzureAdminPassword: The password of the Azure account with **owner** access to the subscription.
* registrationCode: The license registration code for the PCoIP CAS licenses.
* adminVMBlobSource: The location of the blobs for admin GUI machine installation. Use the default unless you are specifically deploying with modified binaries.
* \_artifactsLocation: The location of resources, such as templates and DSC modules, that the template depends on. Use the default unless you are specifically deploying with modified templates or binaries.
* \_artifactsLocationSasToken: - an auto-generated token to access _artifactsLocation. If _artifactsLocation does not need an access token (which is the default) then this can be blank.

 ## Deployment Template 
 This section will enable you to perform a deployment using the deployment parameters set out above.
 This template will deploy 5 virtual machines (along with a new VNet, Storage Account, Load Balancer, Azure KeyVault, and Gateway).

 To administer the deployment through the Cloud Access Manager GUI, https: to the public IP of the applicationGateway1 Application Gateway. To connect to the pre-created Agent virtual machine, point the PCoIP client to the public IP of the applicationGateway1 Application gateway and login with the administrator credentials. To manage the Active Directory Domain, RDP to the public IP address of vm-dc (the domain controller).

The following steps outline the procedure for performing a deployment of CAM using Microsoft Azure: 

 Click the <b> Deploy Azure </b> button to  begin.

<a target="_blank" href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

1. Select the Microsoft Azure account you want to access.
1. Enter your Password and click <b>Sign in</b>
1. ON the Customized Template page create a new Resource group by selecting the <b>Create New</b> icon and entering a name for the group.
* You can also select a pre-defined Resource group by selecting the <b>Use Existing</b> icon and clicking on one of the groups from the dropdown menu.

4. Select a location from the dropdown menu.
5. Enter a Username for the <b>Domain Admin Username</b>.
6. Enter a password for the <b>Domain Admin Password</b>.
7. Enter a <b>Domain Name</b> and ensure it finishes in <b>.com</b>.
8. Enter your <b>Azure Admin Username</b>. This must be the same account you logged into from step 1.
9. Enter your <b>Azure Admin Password</b>. This must be the same password you used to log in from step 2.
10. Enter the CAS license registration code for the <b>Registration Code</b>. If you do not have a registration code contact a member of the Cloud BU team.
11. Use the default addresses that are pre-entered for the <b>CAM Deployment Blob Source</b> and <b>_artifacts Location</b>. 
12. Read the Terms and Conditions and once you are satisified with the information you have entered click the <b> I Agree</b> icon.
13. Click <b>Purchase</b> to begin deployment.

The deployment will now begin to run. You can track it through the notifications icon or for a more detailed view of your deployment click the <b>Resource Groups </b> icon located on the left hand side of the page and click on your resource group.

## Known Issues with Deploying the Solution

* This solution will only deploy machines in one region. If you wish to use NV series virtual machines for GPU accelerated graphics, then you must deploy the complete solution into one of the supported regions for NV series instance types. Currently this is limited to the following locations: EAST US, NORTH CENTRAL US, SOUTH CENTRAL US, SOUTH EAST ASIA and WEST EUROPE.
* Do not use passwords with the '%' symbol as it is currently not supported.
* The current certificate that is deployed is expired so PCoIP clients must be configured for security_mode=0 (verification is not required) in order to connect. See here for instructions: http://www.teradici.com/web-help/TWAS_UG22_HTML5/08_AppA_Security.htm
* Occasionally the Azure Application Gateway can fail with an 'internal error.' If this happens, you can quickly redeploy the application gateway to recover.
 1. In the Azure Portal select the resource group you created.
 1. Go to Deployments -> CreateAppGateway
 1. Click <b>Redeploy</b>. This will bring you to the custom deployment screen.
 1. Click <b>use existing</b> and select the resource group you are using.
 1. Leave all the other parameters the same.
 1. Accept the terms and conditions.
 1. Click <b>Purchase</b>.
 1. The Application gateway should deploy successfully.
* Occasionally other failures can happen such as 'timeout' or 'can't start WinRM service.' Start a new deployment from scratch in a new resource group and attempt to re-deploy.
* A common deployment failure is when the quota is reached for the subscription. In this case you have to either remove or deallocate virtual machines from the subscription, or request a core quota increase from Microsoft to alleviate the problem.

        
To visualize the structure of this deployment template, click here:

<a target="_blank" href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>



Copyright 2017 Teradici Corporation. All Rights Reserved.

Some content is based off of the Azure Quickstart Templates, Copyright (c) Microsoft Azure. With the following license: https://github.com/Azure/azure-quickstart-templates/blob/master/LICENSE
