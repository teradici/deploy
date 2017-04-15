# Create a complete deployment of the Cloud Access Manager solution including a Domain Controller

This template will deploy 5 virtual machines (along with a new VNet, Storage Account, Load Balancer, and Gateway).

To administer the deployment through the Cloud Access Manager GUI, https: to the public IP of the applicationGateway1 Application Gateway.

To connect to the pre-created Agent virtual machine, point the PCoIP client to the public IP of the applicationGateway1 Application gateway and login with the administrator credentials.

To manage the Active Directory Domain, RDP to the domain controller by initiating an RDP session to the adLoadBalancer Load Balancer public IP.


Click the button below to deploy

<a target="_blank" href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

## Deployment Parameters

* domainAdminUsername: The name of the administrator account to be created for the domain.
  * Short form, not UPN. Name cannot be 'admin.' Examples: 'uname' is allowed. 'uname@example.com' is not allowed.
  * This account username and password also becomes the local admin account for each created machine.
* domainAdminPassword: The password for the administrator account of the new VM's and domain.
* domainName: The FQDN of the Active Directory Domain to be created. **Must have a '.' like example.com or domain.local.**
* AzureAdminUsername: The UPN name of the Azure account with **owner** access to the subscription. This account cannot require MFA, or be a Service Principal. Example: uname@example.com.
  * This account is only required to deploy the system. During deployment, it will create an application in the Azure Active Directory account associated with the current Azure subscription. The application name is 'CAM-\<resourceGroupName\>'. It will also create a Service Principal account as part of this application which has contributor access to the resource group being deployed to. After deployment, only the Service Principal account is used for interaction with Azure API's.
* AzureAdminPassword: The password of the Azure account with **owner** access to the subscription.
* activationCode: The license activation code for the PCoIP CAS licenses. This key must be a CAS standard agent licence for the License Server. If the license expires or needs to be changed, this can be accomblished by SSH'ing to the connection manager/security gateway/licence manager machine.
* adminVMBlobSource: The location of the blobs for admin GUI machine installation. The default is fine unless you are specifically requiring a different version of the solution.
* _artifactsLocation: The location of resources, such as templates and DSC modules, that the template depends on. The default is fine unless you have customized the deployment.
* _artifactsLocationSasToken: - an auto-generated token to access _artifactsLocation. If _artifactsLocation does not need an access token then this can be blank.

## Known issues with deploying the solution

* Occasionally the Azure Application gateway can fail with an 'internal error.' If this happens, you can quickly redeploy the application gateway to recover.
  1. In the Azure Portal, in Resource Groups, select the resource group.
  1. Go to Deployments -> CreateAppGateway
  1. Click on the 'Redeploy' button. This will bring you to the 'custom deployment' screen.
  1. Select 'use existing resource group' and select the resource gorup you're using.
  1. Leave all the other parameters the same.
  1. Accept the terms and contitions.
  1. Click Purchase.
  1. The Application gateway should deploy successfully.
* Occasionally other failures can happen such as 'timeout' or 'can't start WinRM service.' Start the deployment from scratch in a new resource group.
* A commpn deployment failure is when the quota is reached for the subscription. In this case you have to either remove or deallocate virtual machines from the subscription, or request a core quota increase from Microsoft to alleviate the problem.

        
To visualize the structure of this deployment template, click here:

<a target="_blank" href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>



Copyright 2017 Teradici Corporation. All Rights Reserved.

Some content is based off of the Azure Quickstart Templates, Copyright (c) Microsoft Azure. With the following license: https://github.com/Azure/azure-quickstart-templates/blob/master/LICENSE
