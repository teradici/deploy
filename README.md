# What is Cloud Access Manager?
Teradici Cloud Access Manager (CAM) is a one click deployment solution that provides a level of brokering on top of new Cloud Access Software (CAS) deployments. CAM will enable you to assign and revoke virtual machines to users, turn virtual machines on or off, as well as create and destroy virtual machines. 
 
The CAM solution is deployed in your Microsoft Azure subscription with an ARM template provided by Teradici. Once you have completed the template form on the Microsoft Azure Portal, you can start deployment. Information on deploying CAM, as well as additional information on the solutions architecture and deployment parameters are in the following sections.
 
The following image gives an outline of the CAM Technical Preview Architecture:

**CAM Architecture**

![Img](http://www.teradici.com/web-help/CAM/CAMPOCDiagram.png)

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

Click the **Deploy Azure** button for instructions on how to begin.

**NOTE:** In general it takes over an hour for the deployment to complete.

**NOTE:** By clicking one of the following Deploy on Azure buttons, you accept the terms of the Teradici Cloud Access Software End User License Agreement and you have read and agree to be bound by the software license for use of the third-party drivers.

<a target="_blank" href="http://www.teradici.com/web-help/CAM/site/index.html">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>


Copyright 2017 Teradici Corporation. All Rights Reserved.

Some content is based off of the Azure Quickstart Templates, Copyright (c) Microsoft Azure. With the following license: https://github.com/Azure/azure-quickstart-templates/blob/master/LICENSE
