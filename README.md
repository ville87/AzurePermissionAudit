# AzurePermissionAudit
Script to assess permissions and roles in Azure to check if there is any possible privilege escalation path.   

The script collects data about service principals:
- Assigned MS Graph API permissions
- Assigned Azure AD roles

It then checks first, if any of those are
- Dangerous MS Graph API Permissions: RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All
- Dangerous Azure AD Roles: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Partner Tier2 Support
- Potentially Dangerous Azure AD Roles: Application Administrator, Authentication Administrator, Azure AD joined device local administrator, Cloud Application Administrator, Cloud device Administrator, Exchange Administrator, Groups Administrator, Helpdesk Administrator, Hybrid Identity Administrator, Intune Administrator, Password Administrator, User Administrator, Directory Writers

> **_NOTE:_**  The difference between dangerous Azure AD roles and potentially dangerous Azure AD roles is, that the dangerous ones allow immediate control over Azure AD identities, while the potential ones could be used indirectly, to e.g. control an application in Azure which is assigned with high privileges (dangerous Azure AD roles)   

Afterwards it checks, if any user was assigned
- Azure AD Roles, which could allow the user to abuse one of those service principals: Application Administrator, Cloud Application Administrator, Hybrid Identity Administrator, Directory Synchronization Account, Partner Tier1 Support, Partner Tier2 Support
- Azure RBAC Roles, which could allow the user to abuse one of those service principals: Owner, Contributor, Automation Contributor, User Access Administrator

Those are then reported to the console output.   

The script will ask you twice to provide Azure credentials, because it uses both the Az module and the AzureAD module which have each their own connecting cmdlets.   

## Limitations (TODO)
- Currently, it is not checked if any user was provided with dangerous MS Graph API permissions which could allow to abuse one of the highly privileged service principals.
- There is some bug where the script often hangs when connecting to Azure AD. If this is the case, manually connect in PowerShell before running the script in a non-elevated PowerShell session with:   
  `Connect-AzAccount -TenantId <TenantId>`    
 
## Example Output
The following output is an example from a test environment with overprivileged service principals and abuse paths:

```
############################################################################
Report of found issues regarding MS Graph API permissions:
############################################################################
[10:49] - WARNING - Found 2 dangerous MS Graph API app role assignments:
appreg-Test-app --> AppRoleAssignment.ReadWrite.All
fn-test-kov-app1 --> RoleManagement.ReadWrite.Directory
############################################################################
Report of found issues regarding Azure AD roles:
############################################################################
[10:49] - WARNING - Found 1 dangerous Azure AD role assignments
appreg-Test-app (Id: 3a7fb636-6233-4f33-890f-97384a06b05b) --> Privileged Role Administrator
[10:49] - WARNING - Found 2 potentially dangerous Azure AD role assignments:
appreg-Test-app (Id: 3a7fb636-6233-4f33-890f-97384a06b05b) --> Application Administrator
vm-test-kov (Id: 55c85712-9a0b-4c7f-b639-f11f97c0bace) --> Authentication Administrator
[10:49] - WARNING - The following identities might be able to abuse the previously listed dangerous Azure AD role assignments for privilege escalation, since they have Azure AD roles assigned which allow them to modify the affected applications:
appreg-Test-app --> Application Administrator
############################################################################
Report of found issues regarding Azure RBAC roles:
############################################################################
[10:49] - INFO - Checking the dangerous MS Graph API AppRoleAssignment:

principalId          : 3a7fb636-6233-4f33-890f-97384a06b05b
principalDisplayName : appreg-Test-app
appRoleName          : AppRoleAssignment.ReadWrite.All

[10:49] - INFO - Subscription of the current AppRoleAssignment is:
[10:49] - INFO - No identities found which could abuse this AppRoleAssignment.
----------------------------------------------------------------------------
[10:49] - INFO - Checking the dangerous MS Graph API AppRoleAssignment:

principalId          : f11aa11e-275a-4830-be99-e1111c65623d
principalDisplayName : fn-test-kov-app1
appRoleName          : RoleManagement.ReadWrite.Directory

[10:49] - INFO - Subscription of the current AppRoleAssignment is: abc1def2-9d6c-45ff-b7bc-12abcd123d24
[10:49] - WARNING - The following identities might be able to abuse this AppRoleAssignment for Privilege Escalation:
OrgABC (ObjectId: a460121f-416d-43cf-b228-d7abeefab9ac) with role Owner on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24
GA (ObjectId: 1234abcd-1bf6-4e2d-8f8c-a8e441f91a43) with role Owner on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24
fn-test-kov-app1 (ObjectId: f11aa11e-275a-4830-be99-e1111c65623d) with role Owner on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24
DevOps Timmy (ObjectId: 1a45d8a3-5b7d-4033-ab88-8034cd7612c3) with role Contributor on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24/resourceGroups/rg-test-kov/providers/Microsoft.Web/sites/fn-test-kov-app1
bloodhoundtest (ObjectId: 6200256a-f4b2-4dd1-a980-8d0cd3ea5ccd) with role Owner on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24/resourcegroups/rg-test-kov/providers/Microsoft.Web/sites/fn-test-kov-app1
testusersub (ObjectId: 1dd16632-19c1-4c8f-a6ea-053370482d3c) with role Contributor on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24
----------------------------------------------------------------------------
############################################################################
[10:49] - INFO - Checking the dangerous Azure AD role assignments (Roles: Privileged Role Administrator,Application Administrator) of the service principal 3a7fb636-6233-4f33-890f-97384a06b05b
[10:49] - INFO - Subscription of the current service principals resource is: Unknown (Enterprise App?)
[10:49] - INFO - No identities found which could abuse this AppRoleAssignment.
############################################################################
[10:49] - INFO - Checking the dangerous Azure AD role assignments (Roles: Authentication Administrator) of the service principal 55c85712-9a0b-4c7f-b639-f11f97c0bace
[10:49] - INFO - Subscription of the current service principals resource is: abc1def2-9d6c-45ff-b7bc-12abcd123d24
[10:49] - WARNING - The following identities might be able to abuse this service principal for Privilege Escalation:
OrgABC (ObjectId: a460121f-416d-43cf-b228-d7abeefab9ac) with role Owner on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24
GA (ObjectId: 1234abcd-1bf6-4e2d-8f8c-a8e441f91a43) with role Owner on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24
fn-test-kov-app1 (ObjectId: f11aa11e-275a-4830-be99-e1111c65623d) with role Owner on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24
bloodhoundtest2 (ObjectId: 2a3132ef-0ac3-47c4-b432-bb30e6311068) with role Owner on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24/resourcegroups/rg-vmtest/providers/Microsoft.Compute/virtualMachines/vm-test-kov
bloodhoundtest (ObjectId: 6200256a-f4b2-4dd1-a980-8d0cd3ea5ccd) with role Contributor on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24/resourcegroups/rg-vmtest/providers/Microsoft.Compute/virtualMachines/vm-test-kov
testusersub (ObjectId: 1dd16632-19c1-4c8f-a6ea-053370482d3c) with role Contributor on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24
testuserrg (ObjectId: 31230ef3-6083-4226-b817-c44f82aa5726) with role Contributor on scope /subscriptions/abc1def2-9d6c-45ff-b7bc-12abcd123d24/resourceGroups/rg-vmtest
############################################################################
```
