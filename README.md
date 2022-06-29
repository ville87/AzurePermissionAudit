# AzurePermissionAudit
Script to assess permissions and roles in Azure to check if there is any possible privilege escalation path.   

The script collects data about service principals:
- Assigned MS Graph API permissions
- Assigned Azure RBAC roles
- Assigned Azure AD roles

It then checks first, if any of those are
- Dangerous MS Graph API Permissions: RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All
- Dangerous Azure AD Roles: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator
- Potentially Dangerous Azure AD Roles: Application Administrator, Authentication Administrator, Azure AD joined device local administrator, Cloud Application Administrator, Cloud device Administrator, Exchange Administrator, Groups Administrator, Helpdesk Administrator, Hybrid Identity Administrator, Intune Administrator, Password Administrator, User Administrator

Afterwards it checks, if any user was assigned
- Azure AD Roles, which could allow the user to abuse one of those service principals: Application Administrator, Cloud Application Administrator, Hybrid Identity Administrator, Directory Synchronization Account, Partner Tier1 Support, Partner Tier2 Support
- Azure RBAC Roles, which could allow the user to abuse on of those service principals: Owner, Contributor, Automation Contributor, User Access Administrator

Those are then reported to the console output.

## Limitations
- Currently, it is not checked if any user was provided with dangerous MS Graph API permissions.
- For Azure AD registered Enterprise Applications the relevant subscription could not be verified in the time of creation of the script. Therefore for the reports, the subscription is set to "Unknown" and all users with the previously mentioned RBAC roles are listed for manual verification.
 