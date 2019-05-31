<#

.SYNOPSIS
This is a CloudShell script for adding non-Cloud Access Manager provisioned machines as managed machines to the Cloud Access Manager

.DESCRIPTION
If you have manually created a machine in Azure and wish to use Teradici's CAM power management features, this script will perform the neccesary steps so that the Azure Service Principal account can perform power operations on that machine and then add it to the CAM service so that user entitlements can be added through the management interface

.EXAMPLE
./AddManagedMachine.ps1 -MachineName myMachine -ConnectorRootResourceGroup IT-Prod-CAM-RG

#>

Param(
        [String]
        $ConnectorRootResourceGroup,

        [String]
        $MachineName,

        [parameter(Mandatory = $false)]
        [String]
        $MachineResourceGroup
)

$baseHeaders = @{
    "User-Agent"="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
}

function Get-CamSecret() {
        param(
                [String]
                $secretName,
                [String]
                $VaultName
        )
        $secret = Get-AzureKeyVaultSecret `
            -VaultName $VaultName `
            -Name $secretName `
            -ErrorAction stop

        if(-not $secret) {
            throw ("Failed to fetch " +$secretName)
        }
        
        return $secret.SecretValueText
}

function Get-CamKeyVault() {
        param(
                [String]
                $ConnectorRootResourceGroup
        )
        $kv = Get-AzureRmResource -ResourceType "Microsoft.KeyVault/vaults" `
            -ResourceGroupName $ConnectorRootResourceGroup `
            | Where-Object {$_.Name -like "CAM-*"}
        
        if( -not $kv ) {
                throw ("Failed to find CAM KeyVault in " + $ConnectorRootResourceGroup)
        }
        return $kv.Name
}

function Get-CamCredentials(){
    param(
        [String]
        $VaultName
    )
    $username = Get-CamSecret -VaultName $VaultName -secretName "AzureSPClientID"
    $password = Get-CamSecret -VaultName $VaultName -secretName "AzureSPKey"
    $tenantId = Get-CamSecret -VaultName $VaultName -secretName "AzureSPTenantID"
    return @{
        username = $username
        password = $password
        tenantId = $tenantId
    }
}

function Get-CamToken() {
    param(
        $camUser,
        $camSaasBaseUri
    )
    $signInResult = ""
    try {
        $signInResult = Invoke-RestMethod -Method Post -Uri ($camSaasBaseUri + "/api/v1/auth/signin") -Body $camUser -Headers $baseHeaders
    }
    catch {
        if ($_.ErrorDetails.Message) {
            $signInResult = ConvertFrom-Json $_.ErrorDetails.Message
        }
        else {
            throw $_
        }
    }
    Write-Verbose ((ConvertTo-Json $signInResult) -replace "\.*token.*", 'Token": "Sanitized"')
    # Check if signIn succeded
    if ($signInResult.code -ne 200) {
        throw ("Signing in failed with result: " + (ConvertTo-Json $signInResult))
    }
    
    return $signInResult.data.token
}

function Add-CamManagedMachine() {
    param(
        [String]
        $MachineName,

        [String]
        $MachineResourceGroup,

        [String]
        $SubscriptionId,

        [String]
        $deploymentId,

        [String]
        $camSaasBaseUri,

        [String]
        $token
    )

    $tokenHeader = $baseHeaders + @{
        authorization = $token
    }

    $machine = @{
        machineName = $MachineName
        active = $true
        managed = $true
        deploymentId = $deploymentId
        resourceGroup = $MachineResourceGroup
        provider = "azure"
        subscriptionId = $SubscriptionId
    }

    $AddMachineResult = ""
    try {
        $AddMachineResult = Invoke-RestMethod `
            -method Post `
            -Uri ($camSaasBaseUri + "/api/v1/machines") `
            -Body $machine `
            -Headers $tokenHeader
    }
    catch {
        if ($_.ErrorDetails.Message) {
            $signInResult = ConvertFrom-Json $_.ErrorDetails.Message
        }
        else {
            throw $_
        }
    }
    # Check if signIn succeded
    if ($AddMachineResult.code -ne 201) {
        throw ("Adding machine failed with result: " + (ConvertTo-Json $signInResult))
    }
    
    return $AddMachineResult   
}

function Add-ScopeToMachine()
{
    param(
        [parameter(Mandatory = $true)] 
        $machine,
        [parameter(Mandatory = $true)] 
        $client,
        [parameter(Mandatory = $true)] 
        $subscriptionId,
        [parameter(Mandatory = $true)] 
        $camCustomRoleDefinition
    )

    if( Get-AzureRmResource `
        -Name $machine.Name `
        -ResourceType "Microsoft.Compute/virtualMachines" `
        -ResourceGroupName $machine.ResourceGroupName `
        -ErrorAction SilentlyContinue
        )
    {
        # Get-AzureRmRoleAssignment responds much more rationally if given a scope with an ID
        # than a resource group name.
        $spRoles = Get-AzureRmRoleAssignment -ServicePrincipalName $client -Scope $machine.ResourceId
    
        $vmRG = Get-AzureRmResourceGroup -Name $machine.ResourceGroupName

        # filter on an exact resource group ID match as Get-AzureRmRoleAssignment seems to do a more loose pattern match
        $spRoles = $spRoles | Where-Object `
            {   ($_.Scope -eq $vmRG.ResourceId) `
            -or ($_.Scope -eq $machine.ResourceId) `
            -or ($_.Scope -eq "/subscriptions/$subscriptionId")}
        
        # spRoles could be no object, a single object or an array. foreach works with all.
        $hasAccess = $false
        foreach($role in $spRoles) {
            $roleName = $role.RoleDefinitionName
            if (($roleName -eq "Contributor") -or ($roleName -eq "Owner") -or ($roleName -eq $camCustomRoleDefinition.Name)) {
                Write-Host "$client already has $roleName for "$machine.Name
                $hasAccess = $true
                break
            }
        }
    
        if(-not $hasAccess) {
            Write-Host "Giving $client '$($camCustomRoleDefinition.Name)' access to "$machine.Name
            New-AzureRmRoleAssignment `
                -RoleDefinitionName $camCustomRoleDefinition.Name `
                -Scope $machine.ResourceId `
                -ServicePrincipalName $client `
                -ErrorAction Stop | Out-Null
        }
    }
}

function Get-CAMRoleDefinitionName() {
    param(
        [String]$subscriptionId=""
    )
    if ( -not $subscriptionId ) {
        return "Cloud Access Manager"
    }
    return "Cloud Access Manager", $subscriptionId -Join "-"
}

# Create a custom role for CAM with necessary permissions
# Use 'Get-AzureRmProviderOperation *' to get a list of Azure Operations and their details
# See https://docs.microsoft.com/en-us/azure/active-directory/role-based-access-built-in-roles for details on Azure Built in Roles
function Get-CAMRoleDefinition() {
    param(
        [String]$subscriptionId=""
    )

    # Check for old "Cloud Access Manager" Role Deifinition
    $roleName = Get-CAMRoleDefinitionName
    $camCustomRoleDefinition = Get-AzureRmRoleDefinition $roleName
    # Check for new "Cloud Access Manager-$subsctionId" Role Definition if old is invalid
    if ( -not $camCustomRoleDefinition -or ($camCustomRoleDefinition -and -not ( `
            $camCustomRoleDefinition.AssignableScopes.Contains("/subscriptions/$subscriptionId") `
            -or $camCustomRoleDefinition.AssignableScopes.Contains("/subscriptions/*")))) {
        $roleName = Get-CAMRoleDefinitionName -subscriptionId $subscriptionId
        $camCustomRoleDefinition = Get-AzureRmRoleDefinition $roleName
    }
    
    # Create Role Defintion Based off of Contributor if it doesn't already exist
    if ( -not $camCustomRoleDefinition ) {
        Write-Host "Creating '$roleName' Role Definition"
        $camCustomRoleDefinition = Get-AzureRmRoleDefinition "Contributor"
        $camCustomRoleDefinition.Id = $null
        $camCustomRoleDefinition.IsCustom = $true
        $camCustomRoleDefinition.Name = $roleName
        $camCustomRoleDefinition.Description = "Required Permissions for $roleName"

        # Limit Assignable scopes to specified subscription
        if ($subscriptionId) {
            $camCustomRoleDefinition.AssignableScopes.Clear()
            $camCustomRoleDefinition.AssignableScopes.Add("/subscriptions/$subscriptionId")
        }

        # Clear out existing NotActions
        $camCustomRoleDefinition.NotActions.clear()

        # Actions to remove
        $requiredNotActions = @(
            # Default NotActions to disable to prevent elevation of privlege
            'Microsoft.Authorization/*/Delete'
            'Microsoft.Authorization/*/Write'
            'Microsoft.Authorization/elevateAccess/Action'
            
            # Remove ability to access snapshots
            'Microsoft.Compute/snapshots/*'
            # Remove ability to access restore points
            'Microsoft.Compute/restorePointCollections/*'
            # Remove ability to get SAS URI of VM Disk for Blob access
            'Microsoft.Compute/disks/beginGetAccess/action'
            # Remove ability to revoke SAS URI of VM Disk for Blob access
            'Microsoft.Compute/disks/endGetAccess/action'

            # Remove ability to access application gateway WAF rulesets
            'Microsoft.Network/applicationGatewayAvailableWafRuleSets/*'
            # Remove ability to access vpn connection info
            'Microsoft.Network/connections/*'
            # Remove ability to access dns zones and operation satuses
            'Microsoft.Network/dnszones/*'
            'Microsoft.Network/dnsoperationstatuses/*'
            # Remove ability to access express routes
            'Microsoft.Network/expressRouteCrossConnections/*'
            'Microsoft.Network/expressRouteCircuits/*'
            'Microsoft.Network/expressRouteServiceProviders/*'
            # Remove ability to access load balancers
            'Microsoft.Network/loadBalancers/*'
            # Remove ability to access network watchers
            'Microsoft.Network/networkWatchers/*'
            # Remove ability to access route filters and tables
            'Microsoft.Network/routeFilters/*'
            'Microsoft.Network/routeTables/*'
            # Remove ability to access secure gateways
            'Microsoft.Network/securegateways/*'
            # Remove ability to access service endpoint policies
            'Microsoft.Network/serviceEndpointPolicies/*'
            # Remove ability to access traffic management
            'Microsoft.Network/trafficManagerProfiles/*'
            'Microsoft.Network/trafficManagerUserMetricsKeys/*'
            'Microsoft.Network/trafficManagerGeographicHierarchies/*'
            # Remove ability to delete Vnets
            'Microsoft.Network/virtualNetworks/delete'
            # Remove ability to peer Vnet to other Vnets
            'Microsoft.Network/virtualNetworks/peer/action'
            # Remove ability to access Vnet peering info
            'Microsoft.Network/virtualNetworks/virtualNetworkPeerings/*'
            # Remove ability to access virtual network gateways and taps
            'Microsoft.Network/virtualNetworkGateways/*'
            'Microsoft.Network/virtualNetworkTaps/*'
            # Remove ability to access virtual wans and hubs
            'Microsoft.Network/virtualwans/*'
            'Microsoft.Network/virtualHubs/*'
            # Remove ability to access vpn gateways and sites
            'Microsoft.Network/vpnGateways/*'
            'Microsoft.Network/vpnsites/*'

            # Remove ability to access queue service in storage account
            'Microsoft.Storage/StorageAccounts/queueServices/*'
        )

        # Add Not Actions required to be disabled
        foreach ( $notAction in $requiredNotActions) {
            if ( -not $camCustomRoleDefinition.NotActions.Contains($notAction)) {
                $camCustomRoleDefinition.NotActions.Add($notAction)
            }
        }

        # Clear out existing Actions
        $camCustomRoleDefinition.Actions.Clear()

        # Actions to add
        $requiredActions = @(
            "Microsoft.Resources/*"
            "Microsoft.KeyVault/*"
            "Microsoft.Storage/*"
            "Microsoft.Network/*"
            "Microsoft.Compute/*"
        )

        # Add Actions required to be enabled
        foreach ( $Action in $requiredActions) {
            if ( -not $camCustomRoleDefinition.Actions.Contains($Action)) {
                $camCustomRoleDefinition.Actions.Add($Action)
            }
        }

        try{
            New-AzureRmRoleDefinition -Role $camCustomRoleDefinition -ErrorAction Stop | Out-Null
        }
        catch {
            $err = $_
            Write-Host-Warning "Cannot create '$roleName' Role Definition"
            throw $err
        }
        $camCustomRoleDefinition = Get-AzureRmRoleDefinition $roleName
    } else {
        Write-Host "Found existing '$roleName' Role Definition"
    }

    return $camCustomRoleDefinition
}

function Find-CamMachine () {
    param(
        [String]
        $MachineName,

        [parameter(Mandatory = $false)]
        $MachineResourceGroup
    )

    if( $MachineResourceGroup ) {
        $machine = Get-AzureRmResource -ResourceType "Microsoft.Compute/virtualMachines" `
            -ResourceGroupName $MachineResourceGroup `
            | Where-Object {$_.Name -eq $MachineName}
    } else {
        $machine = Get-AzureRmResource -ResourceType "Microsoft.Compute/virtualMachines" `
            | Where-Object {$_.Name -eq $MachineName}
    }

    if(-not $machine.Length -eq 1) {
        if($machine.Length) {
            throw ("Found multiple machines, provide Resource Group Name to make it less ambiguous")
        } else {
            throw ("Failed to find " + $MachineName)
        }
    }

    return $machine
}

if(-not $MachineName) {
    throw "Machine Name is required"
}
if(-not $ConnectorRootResourceGroup) {
    throw "Connector's Route Resource Group is required"
}

$CAMKeyVault = Get-CamKeyVault -ConnectorRootResourceGroup $ConnectorRootResourceGroup

Write-Host "Checking if machine exists..."
$machine = Find-CamMachine -MachineName $MachineName -MachineResourceGroup $MachineResourceGroup

Write-Host "Fetching CAM Credentials..."
$camUser = Get-CamCredentials -VaultName $CAMKeyVault

$CAMBaseUri = Get-CamSecret -VaultName $CAMKeyVault -secretName "CAMServiceURI"

$subscriptionId = Get-CamSecret -VaultName $CAMKeyVault -secretName "AzureSubscriptionID"

$deploymentId = Get-CamSecret -VaultName $CAMKeyVault -secretName "CAMDeploymentID"

Write-Host "Checking that CAM Azure Credentials have access to machine..."
$camCustomRoleDefinition = Get-CAMRoleDefinition -subscriptionID $subscriptionID

Add-ScopeToMachine `
    -machine $machine `
    -subscriptionId $subscriptionId `
    -client $camUser["username"] `
    -camCustomRoleDefinition $camCustomRoleDefinition

Write-Host "Signing into CAM..."
$token = Get-CamToken -camUser $camUser -camSaasBaseUri $CAMBaseUri

Write-Host "Adding Machine to CAM..."
$AddMachineResults = Add-CamManagedMachine `
    -MachineName $machine.Name `
    -MachineResourceGroup $machine.ResourceGroupName `
    -SubscriptionId $subscriptionId `
    -deploymentId $deploymentId `
    -camSaasBaseUri $CAMBaseUri `
    -token $token

Write-Host $AddMachineResults.data