# Create a complete deployment of the Cloud Access Software Manager solution including a Domain Controller

This template will deploy 5 virtual machines (along with a new VNet, Storage Account, Load Balancer, and gateway).

To administer the deployment through the Cloud Access Software Manager GUI, https: to the public IP of the applicationGateway1 Application Gateway.

To connect to the pre-created Agent virtual machine, point the PCoIP client to the public IP of the applicationGateway1 Application gateway and login with the administrator credentials.

To manage the Active Directory Domain, RDP to the domain controller by initiating an RDP session to the adLoadBalancer Load Balancer.


Click the button below to deploy

<a target="_blank" href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>


To visualize the structure of this deployment template, click here:

<a target="_blank" href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>



Copyright 2017 Teradici Corporation. All Rights Reserved.

Some content is based off of the Azure Quickstart Templates, Copyright (c) Microsoft Azure. With the following license: https://github.com/Azure/azure-quickstart-templates/blob/master/LICENSE
