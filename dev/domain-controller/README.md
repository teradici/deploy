# Create a new Windows VM and create a new AD Forest, Domain and DC

This template will deploy a new VM (along with a new VNet, Storage Account and Load Balancer) and will configure it as a Domain Controller and create a new forest and domain and will create a second virtual machine and join it to the domain.

based off of active-directory-new-domain and 201-vm-domain-join quickstart templates (TODO: add correct license and attribution here)

Click the button below to deploy

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fteradici%2Fdeploy%2Fmaster%2Fdev%2Fdomain-controller%2Fazuredeploy.json" target="_blank">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>
