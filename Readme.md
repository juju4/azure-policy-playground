# Azure policy playground

This is repository of Azure Policy both for lab and production.
As usual, adapt to your context


##  Selection
This is a starter collection that should be adapted to context.
Deploy progressively, Share schedule early, Enforce early.

* [allowed-locations](https://github.com/Azure/azure-policy/tree/master/samples/built-in-policy/allowed-locations)
* [allowed-resourcetypes](https://github.com/Azure/azure-policy/tree/master/samples/built-in-policy/allowed-resourcetypes)
* [EnvironmentTagValues_Deny](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Tags/EnvironmentTagValues_Deny.json)
* [RequireTag_Deny](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Tags/RequireTag_Deny.json)
* [ResourceGroupRequireTag_Deny](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Tags/ResourceGroupRequireTag_Deny.json)
* allowed-image-publishers
* not-allowed-vmextension
* skus-for-multiple-types
* append-date-tag-resource-group
* apply-diagnostic-setting-network-security-group

Builtin Compute
* Allowed virtual machine size SKUs
* [Managed disks should disable public network access](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Compute/AddDiskAccessToDisk_Modify.json)
* [Only approved VM extensions should be installed](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Compute/VirtualMachines_ApprovedExtensions_Audit.json). [Azure virtual machine extensions and features](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/overview)
* [VM use allowed Images](https://github.com/Azure/Community-Policy/tree/master/Policies/Compute/VM%20use%20allowed%20Images)

Builtin Key Vault
* Azure Key Vault should have firewall enabled
* Configure key vaults to enable firewall

* Key Vault keys should have an expiration date
* Key Vault secrets should have an expiration date
* Key vaults should have purge protection enabled
* Key vaults should have soft delete enabled
* Secrets should have content type set

Builtin Kubernetes
* Kubernetes cluster containers should only use allowed capabilities
* Kubernetes cluster containers should only use allowed images
* Kubernetes cluster containers should only use allowed seccomp profiles
* Kubernetes cluster containers should run with a read only root file system
* Kubernetes cluster services should listen only on allowed ports
* Kubernetes cluster should not allow privileged containers
* Kubernetes clusters should not allow container privilege escalation
* Kubernetes clusters should not grant CAP_SYS_ADMIN security capabilities
* Kubernetes resources should have required annotations

Builtin Storage
* [Preview]: Storage account public access should be disallowed
* Configure your Storage account public access to be disallowed
* Public network access should be disabled for Azure File Sync
* Storage accounts should restrict network access
* Disable Blob Public Access
* [Storage accounts should be limited by allowed SKUs](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Storage/AllowedStorageSkus_Audit.json)
* [Storage accounts should have infrastructure encryption](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Storage/StorageAccountInfrastructureEncryptionEnabled_Audit.json)


Builtin Tags
* Inherit a tag from the resource group if missing
* Require a tag on resource groups
* Require a tag on resources - environment, engcontact...
* [add-date-created-tag](https://github.com/Azure/Community-Policy/blob/master/Policies/Tags/add-date-created-tag/azurepolicy.rules.json)
* enforce-casing-on-tags
* require-tag-and-value-from-set
* Deny-resource-without-tag

* allowed-nc-for-allowed-locations-for-rgs

## Prerequisites

For powershell
```powershell
Install-Module -Repository PSGallery Az
# If interactive, end-user device
Connect-AzAccount
# If interactive, server
Connect-AzAccount -UseDeviceAuthentication
# if multiple tenant or subscriptions
Connect-AzAccount -Tenant examplecompany.onmicrosoft.com
Set-AzContext -Subscription <subscription name or id>
```

For az-cli
```shell
az login
az account show
# if multiple tenant or subscriptions
az login --tenant examplecompany.onmicrosoft.com
az account set --subscription <name or id>
```

If using Azure Cloud Shell, Storage account requirement
````powershell
$resourceGroup = "eus-azcloudshell"
$accountName = "eusazcloudshell123456vcxvcxvcxvxcvxc"
$location = "eastus"
$tags = @{
    environment="dev";
    role="Azure Cloud Shell";
    engcontact="User A";
}
New-AzResourceGroup -Name $resourceGroup -Location $location -Tags $tags
New-AzStorageAccount -ResourceGroupName $resourceGroup `
  -Name $accountName `
  -Location $location `
  -SkuName Standard_LRS `
  -Kind StorageV2 `
  -Tags $tags
````

## Deploy

Few examples

* Allowed locations

````powershell
# Get the built-in policy definition
$policyDef = Get-AzPolicyDefinition -Id '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'
# Set the scope
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
# Params
$policyparam = '{ "listOfAllowedLocations": { "value": [ "eastus", "eastus2", "westus", "westeurope" ] } }'
# Create the Policy Assignment
$assignment = New-AzPolicyAssignment -Name 'Allowed resource types' -DisplayName 'Allowed resource types' -Scope $scope -PolicyDefinition $policyDef -PolicyParameter $policyparam
````

* Allowed resource types

````powershell
# Get the built-in policy definition
$policyDef = Get-AzPolicyDefinition -Id '/providers/Microsoft.Authorization/policyDefinitions/a08ec900-254a-4555-9bf5-e42af04b5c5c'
# Set the scope
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
# Params
$policyparam = '{ "listOfResourceTypesAllowed": { "value": [ "microsoft.compute/locations/virtualmachines", "microsoft.compute/virtualmachines", "microsoft.compute/virtualmachines/extensions", "microsoft.compute/virtualmachines/runcommands", "microsoft.compute/virtualmachines/metricdefinitions", "microsoft.network/networksecuritygroups", "microsoft.keyvault/vaults", "microsoft.web/sites/functions", "microsoft.storage/storageaccounts", "microsoft.compute/disks", "microsoft.network/virtualnetworks", "microsoft.network/virtualnetworks/subnets", "microsoft.network/publicipaddresses", "microsoft.network/privateendpoints", "microsoft.network/networkinterfaces" ] } }'
# for azure function for TagWithCreator
$policyparam = '{ "listOfResourceTypesAllowed": { "value": [ "microsoft.compute/locations/virtualmachines", "microsoft.compute/virtualmachines", "microsoft.compute/virtualmachines/extensions", "microsoft.compute/virtualmachines/runcommands", "microsoft.compute/virtualmachines/metricdefinitions", "microsoft.network/networksecuritygroups", "microsoft.keyvault/vaults", "microsoft.web/sites/functions", "microsoft.storage/storageaccounts", "microsoft.compute/disks", "microsoft.network/virtualnetworks", "microsoft.network/virtualnetworks/subnets", "microsoft.network/publicipaddresses", "microsoft.network/privateendpoints", "microsoft.network/networkinterfaces", "microsoft.web/serverfarms", "microsoft.web/sites", "microsoft.insights/components", "microsoft.policyinsights/eventgridfilters", "microsoft.eventgrid/systemtopics", "microsoft.eventgrid/systemtopics/eventsubscriptions", "microsoft.eventgrid/topics", "microsoft.eventgrid/topictypes" ] } }'
# Create the Policy Assignment
$assignment = New-AzPolicyAssignment -Name 'Allowed resource types' -DisplayName 'Allowed resource types' -Scope $scope -PolicyDefinition $policyDef -PolicyParameter $policyparam
````

* [EnvironmentTagValues_Deny](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Tags/EnvironmentTagValues_Deny.json)

````powershell
$definition = New-AzPolicyDefinition -Name "EnvironmentTagValues_Deny" -DisplayName "[Deprecated]: Allow resource creation if 'environment' tag value in allowed values" -Policy 'https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policyDefinitions/Tags/EnvironmentTagValues_Deny.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$assignment = New-AzPolicyAssignment -Name 'EnvironmentTagValues_Deny' -DisplayName "[Deprecated]: Allow resource creation if 'environment' tag value in allowed values" -Scope $scope -PolicyDefinition $definition
````

* [RequireTag_Deny](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Tags/RequireTag_Deny.json)

````powershell
$definition = New-AzPolicyDefinition -Name "RequireTag_Deny" -DisplayName "Require a tag on resources" -Policy 'https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policyDefinitions/Tags/RequireTag_Deny.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "tagName": { "value": "engcontact" }}'
$assignment = New-AzPolicyAssignment -Name 'RequireTag_Deny' -DisplayName "Require a tag on resources" -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam
````

* [ResourceGroupRequireTag_Deny](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Tags/ResourceGroupRequireTag_Deny.json)

````powershell
$definition = New-AzPolicyDefinition -Name "ResourceGroupRequireTag_Deny" -DisplayName "Require a tag on resource groups" -Policy 'https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policyDefinitions/Tags/ResourceGroupRequireTag_Deny.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "tagName": { "value": "engcontact" }}'
$assignment = New-AzPolicyAssignment -Name 'ResourceGroupRequireTag_Deny' -DisplayName "Require a tag on resource groups" -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam
````
FIXME!
`New-AzPolicyDefinition: InvalidPolicyParameterUpdate : The policy contains new parameter(s) 'tagName' which are not present in the existing policy and have no default value. New parameters may be added to a policy only if they have a default value.`

* Configure key vaults to enable firewall
````powershell
$policyDef = Get-AzPolicyDefinition -Id '/providers/Microsoft.Authorization/policyDefinitions/ac673a9a-f77d-4846-b2d8-a57f8e1c01dc'
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$assignment = New-AzPolicyAssignment -Name 'AzureKeyVaultFirewallEnabled_Modify' -DisplayName 'Configure key vaults to enable firewall' -Scope $scope -PolicyDefinition $policyDef -Location 'eastus' -IdentityType "SystemAssigned"
````

* Disable Blob Public Access
````powershell
$definition = New-AzPolicyDefinition -Name "DisableBlobPublicAccess" -DisplayName "Disable Blob Public Access" -Policy 'https://raw.githubusercontent.com/HarvestingClouds/AzurePolicySamples/main/Storage/DisableBlobPublicAccess.json' -Mode Indexed
# Set the scope to a resource group; may also be a subscription or management group
#$scope = Get-AzResourceGroup -Name 'YourResourceGroup'
#$assignment = New-AzPolicyAssignment -Name 'DisableBlobPublicAccess' -DisplayName 'Disable Blob Public Access' -Scope $scope.ResourceId -PolicyDefinition $definition -Location 'eastus' -IdentityType "SystemAssigned"
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$assignment = New-AzPolicyAssignment -Name 'DisableBlobPublicAccess' -DisplayName 'Disable Blob Public Access' -Scope $scope -PolicyDefinition $definition
````

* Allowed virtual machine SKUs
````shell
policyDef=cccc23c7-8427-4f53-ad12-b6a63eb452b3
scope="/subscriptions/"`az account show --query id --output tsv`
#scope=$(az group show --name 'myrg' --output tsv --query id)
policyparam='{ "listOfAllowedSKUs": { "value": ["Standard_A1", "Standard_B4ms","Standard_D2s_v3", "Standard_D4s_v3"]}}'
az policy assignment create --name 'Allowed Virtual Machine SKUs' --display-name 'Allowed Virtual Machine SKUs' --scope $scope --policy $policyDef --params "$policyparam"
````
or
````powershell
$definition = Get-AzPolicyDefinition -Id '/providers/Microsoft.Authorization/policyDefinitions/cccc23c7-8427-4f53-ad12-b6a63eb452b3'
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "listOfAllowedSKUs": { "value": ["Standard_A1", "Standard_B4ms","Standard_D2s_v3", "Standard_D4s_v3"]}}'
$assignment = New-AzPolicyAssignment -Name 'Allowed Virtual Machine SKUs' -DisplayName 'Allowed Virtual Machine SKUs' -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam
````
or with [ARM template](https://learn.microsoft.com/en-us/azure/governance/policy/assign-policy-template) - FIXME!
````powershell
$deploymentLocation = "East US"
New-AzDeployment -Location $deploymentLocation -TemplateFile $templateFile -Verbose
New-AzDeployment -Location $deploymentLocation -TemplateFile ./azurepolicy.json -TemplateParameterFile ./azurepolicy.parameters.json -Verbose
````
```shell
az deployment group create --resource-group Testing --template-file azurepolicy.json --parameters "$(cat azurepolicy.parameters.json)" --verbose
```

* [Storage accounts should be limited by allowed SKUs](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Storage/AllowedStorageSkus_Audit.json)

````powershell
$definition = New-AzPolicyDefinition -Name "AllowedStorageSkus_Deny" -DisplayName "Storage accounts should be limited by allowed SKUs" -Policy 'https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policyDefinitions/Storage/AllowedStorageSkus_Audit.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "effect": { "value": "Deny" }, "listOfAllowedSKUs": { "value": ["Standard_LRS"] } }'
$assignment = New-AzPolicyAssignment -Name 'AllowedStorageSkus_Deny' -DisplayName "Storage accounts should be limited by allowed SKUs" -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam
````

* [Storage accounts should have infrastructure encryption](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Storage/StorageAccountInfrastructureEncryptionEnabled_Audit.json)

````powershell
$definition = New-AzPolicyDefinition -Name "StorageAccountInfrastructureEncryptionEnabled_Deny" -DisplayName "Storage accounts should have infrastructure encryption" -Policy 'https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policyDefinitions/Storage/StorageAccountInfrastructureEncryptionEnabled_Audit.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "effect": { "value": "Deny" } }'
$assignment = New-AzPolicyAssignment -Name 'StorageAccountInfrastructureEncryptionEnabled_Deny' -DisplayName "Storage accounts should have infrastructure encryption" -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam
````

* [Managed disks should disable public network access](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Compute/AddDiskAccessToDisk_Modify.json)

````powershell
$definition = New-AzPolicyDefinition -Name "AddDiskAccessToDisk_Modify" -DisplayName "Configure managed disks to disable public network access" -Policy 'https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policyDefinitions/Compute/AddDiskAccessToDisk_Modify.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "effect": { "value": "Modify" } }'
$assignment = New-AzPolicyAssignment -Name 'AddDiskAccessToDisk_Modify' -DisplayName "Configure managed disks to disable public network access" -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam -Location 'eastus' -IdentityType "SystemAssigned"
````
FIXME!
`MetadataError: A parameter with the name 'location' was defined multiple times for the command.`

* [Only approved VM extensions should be installed](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Compute/VirtualMachines_ApprovedExtensions_Audit.json). [Azure virtual machine extensions and features](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/overview)

````powershell
$definition = New-AzPolicyDefinition -Name "VirtualMachines_ApprovedExtensions_Deny" -DisplayName "Only approved VM extensions should be installed" -Policy 'https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policyDefinitions/Compute/VirtualMachines_ApprovedExtensions_Audit.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "effect": { "value": "Deny" }, "approvedExtensions": { "value": ["AzureDiskEncryption", "AzureDiskEncryptionForLinux", "WindowsAgent.AzureSecurityCenter", "ConfigurationforWindows", "DependencyAgentWindows", "AzureMonitorWindowsAgent", "ConfigurationforLinux", "LinuxDiagnostic", "DependencyAgentLinux", "AzureMonitorLinuxAgent", "MDE.Linux", "MDE.Windows", "VMSnapshot"] }}'
$assignment = New-AzPolicyAssignment -Name 'VirtualMachines_ApprovedExtensions_Deny' -DisplayName "Only approved VM extensions should be installed" -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam
````

* [add-date-created-tag](https://github.com/Azure/Community-Policy/blob/master/Policies/Tags/add-date-created-tag/azurepolicy.rules.json)

````powershell
$definition = New-AzPolicyDefinition -Name "add-date-created-tag" -DisplayName "Add DateCreated Tag to Resources" -Policy 'https://raw.githubusercontent.com/Azure/Community-Policy/master/Policies/Tags/add-date-created-tag/azurepolicy.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "tagName": { "value": "createdon" } }'
$assignment = New-AzPolicyAssignment -Name 'add-date-created-tag' -DisplayName "Add DateCreated Tag to Resources" -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam -Location 'eastus' -IdentityType "SystemAssigned"
````

* [VM use allowed Images](https://github.com/Azure/Community-Policy/tree/master/Policies/Compute/VM%20use%20allowed%20Images)

````powershell
$definition = New-AzPolicyDefinition -Name "VM use allowed Images" -DisplayName "VM use allowed Images" -Policy 'https://raw.githubusercontent.com/Azure/Community-Policy/master/Policies/Compute/VM%20use%20allowed%20Images/azurepolicy.json' -Mode Indexed
$Subscription = Get-AzSubscription -SubscriptionName 'Azure Subscription 1'
$scope = "/subscriptions/$($Subscription.Id)"
$policyparam = '{ "effect": { "value": "Deny" }, "allowedImagePublishers": { "value": ["MicrosoftWindowsServer", "Canonical", "OpenLogic"] } }'
$assignment = New-AzPolicyAssignment -Name "VM use allowed Images" -DisplayName "VM use allowed Images" -Scope $scope -PolicyDefinition $definition -PolicyParameter $policyparam
````
FIXME!
`New-AzPolicyDefinition: InvalidPolicyRule : Failed to parse policy rule: 'Could not find member 'Description' on object of type 'PolicyRuleDefinition'. Path 'Description'.'.`

## Test

With above examples, following should fail
```
az vm create -n TestPolicyVM -g Testing --image UbuntuLTS --admin-username azureuser --size Standard_B1s --generate-ssh-keys
```

Following should succeed
```
az vm create -n TestPolicyVM -g Testing --image UbuntuLTS --admin-username azureuser --size Standard_A1 --generate-ssh-keys \
  --tags 'environment=dev' 'engcontact=admin'
```
Cleaning
```
az vm delete --resource-group Testing --name TestPolicyVM --force-deletion true --yes
```
(WARNING! Not deleting attached resources...)

## Policy exemption

TODO:
tags['azpolicyExemptUntil'] and tags['engcontact'] and tags['ticket']
azpolicyExemptUntil should be an expiry date with a reasonable time.

## References

* https://learn.microsoft.com/en-us/azure/governance/policy/samples/
* https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies
* https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/manage/azure-server-management/common-policies
* https://github.com/Azure/azure-policy
* https://github.com/Azure/Community-Policy
  * https://github.com/Azure/Community-Policy/tree/master/Policies/Compute/VM%20use%20allowed%20Images
  * https://github.com/Azure/Community-Policy/tree/master/Policies/KeyVault/Enforce%20key%20vault%20firewall%20blocking%20public%20access
  * https://github.com/Azure/Community-Policy/tree/master/Policies/Storage/Enforce%20storage%20account%20public%20firewall%20blocking%20access
  * https://github.com/Azure/Community-Policy/tree/master/Policies/Storage/Storage%20account%20public%20access%20should%20be%20disallowed
  * https://github.com/Azure/Community-Policy/tree/master/Policies/Tags/add-date-created-tag
  * https://github.com/Azure/Community-Policy/tree/master/Policies/Tags/enforce-casing-on-tags
  * https://github.com/Azure/Community-Policy/tree/master/Policies/Tags/require-tag-and-value-from-set
  * https://github.com/Azure/Community-Policy/tree/master/Policies/General/Deny-resource-without-tag
  * https://github.com/Azure/Community-Policy/tree/master/Policies/General/allowed-nc-for-allowed-locations-for-rgs
  * https://github.com/Azure/Community-Policy/tree/master/Policies/General/enforce-naming-convention

Tags
* https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/tagging-azure-resources-with-a-creator/ba-p/1479819; https://github.com/anwather/TagWithCreator
 (with Azure Function)
* https://jrudlin.github.io/2019-07-18-azure-policy-createdon-date/
* https://www.stefanroth.net/2019/10/06/azure-policy-add-date-time-resource-group-tag/; https://github.com/stefanrothnet/azure-policy/blob/master/append-date-tag-resource-group/azurepolicy.json

Storage
* https://harvestingclouds.com/post/block-all-public-access-to-azure-storage-accounts-via-azure-policy-with-complete-sample/; https://github.com/HarvestingClouds/AzurePolicySamples/blob/main/Storage/DisableBlobPublicAccess.json


Management ports (RDP, SSH, Kubernetes api)
* https://markgossa.com/2018/11/azure-policy-deny-inbound-rdp-from.html
* https://guptaashish.com/2020/12/02/azure-policy-deny-creation-of-virtual-machines-without-ip-restriction-across-all-azure-subscriptions/
* https://learn.microsoft.com/en-us/azure/aks/policy-reference

VM extensions
  * https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/extensions-rmpolicy-howto-ps

* https://dev.to/cse/bypassing-policies-in-azure-29fc
* https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure

* https://stackoverflow.com/questions/73100477/enforce-tag-value-validation-in-azure-eg-format-should-a-date-2022-07-24 (No answer)

Tools
* https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux ([Support arm64 Linux builds #7368](https://github.com/Azure/azure-cli/issues/7368), user `pip install azure-cli`)
* https://learn.microsoft.com/en-us/powershell/scripting/install/install-raspbian?view=powershell-7.3

* Get policy parameters: seems only through REST API per https://stackoverflow.com/questions/56932476/how-to-get-paramaters-of-my-policy-assignment
````powershell
Get-AzPolicyAssignment -Scope $scope -Pre -PolicyDefinitionId $policyDef.PolicyDefinitionId -Verbose
````
https://learn.microsoft.com/en-us/rest/api/policy/policy-definitions/get?tabs=HTTP
```shell
curl -X POST -d 'grant_type=client_credentials&client_id=[APP_ID]&client_secret=[PASSWORD]&resource=https%3A%2F%2Fmanagement.azure.com%2F' https://login.microsoftonline.com/[TENANT_ID]/oauth2/token
subscriptionId=d458a358-255f-42d8-8f70-5efc4bfb45dd
policyDefinitionName=ac673a9a-f77d-4846-b2d8-a57f8e1c01dc
curl -X GET -H "Authorization: Bearer [TOKEN]" -H "Content-Type: application/json" "https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/policyDefinitions/${policyDefinitionName}?api-version=2021-06-01"
```


* https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/governance/policy/how-to/programmatically-create.md
* https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deployment-tutorial-local-template?tabs=azure-cli
* https://www.azurecitadel.com/policy/basics/cli/
* https://andrewmatveychuk.com/how-to-deploy-azure-policies-with-arm-templates/

* [AzPolicyAdvertizer](https://www.azadvertizer.net/azpolicyadvertizer_all.html)

* [Prevent accidental deletions at scale using Azure Policy, Dec 2022](https://techcommunity.microsoft.com/t5/azure-governance-and-management/prevent-accidental-deletions-at-scale-using-azure-policy/ba-p/3689186)
tag legal-hold, security-hold
* [Group and allocate costs using tag inheritance, Dec 2022](https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/enable-tag-inheritance)
* [Azure Policies for Automating Azure Governance - Choosing Policies, Jan 2023](https://techcommunity.microsoft.com/t5/itops-talk-blog/azure-policies-for-automating-azure-governance-choosing-policies/ba-p/3709653)
