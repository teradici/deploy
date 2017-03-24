# Create a complete deployment of the Cloud Access Manager solution including a Domain Controller

This template will deploy 5 virtual machines (along with a new VNet, Storage Account, Load Balancer, and gateway).

To administer the deployment through the Cloud Access Manager GUI, https: to the public IP of the applicationGateway1 Application Gateway.

To connect to the pre-created Agent virtual machine, point the PCoIP client to the public IP of the applicationGateway1 Application gateway and login with the administrator credentials.

To manage the Active Directory Domain, RDP to the domain controller by initiating an RDP session to the adLoadBalancer Load Balancer.


Click the button below to deploy

<a target="_blank" href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

## Resource Group Name 

The resource group that the solution is being deployed to must have a relatively short name (say, 10 characters) and can only include lower-case letters and numbers. It probably also can't start with a number. Otherwise the creation of the dns entry for the solution will fail.

## Deployment Parameters

* domainAdminUsername: The name of the administrator account to be created for the domain. Short form, not UPN. This account is also the local admin account for each created machine.
* domainAdminPassword: The password for the administrator account of the new VM's and domain.
* domainName: The FQDN of the Active Directory Domain to be created. Must have a '.' like domain.local
* AzureAdminUsername: The name of the Azure account with contributor access to the subscription. This account cannot require MFA, or be a Service Principal.
* AzureAdminPassword: The password of the Azure account with contributor access to the subscription.
* activationCode: The license activation code for the PCoIP CAS licenses. This key must be a CAS standard agent licence for the License Server. If the license expires or needs to be changed, this can be accomblished by SSH'ing to the connection manager/security gateway/licence manager machine.
* adminVMBlobSource: The location of the blobs for admin GUI machine installation. The default is fine unless you are trying a different version.
* _artifactsLocation: The location of resources, such as templates and DSC modules, that the template depends on. The default is fine unless you have customized the deployment.
* _artifactsLocationSasToken: - an auto-generated token to access _artifactsLocation. If _artifactsLocation does not need an access token then this can be blank.

        
To visualize the structure of this deployment template, click here:

<a target="_blank" href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>



Copyright 2017 Teradici Corporation. All Rights Reserved.

Some content is based off of the Azure Quickstart Templates, Copyright (c) Microsoft Azure. With the following license: https://github.com/Azure/azure-quickstart-templates/blob/master/LICENSE
