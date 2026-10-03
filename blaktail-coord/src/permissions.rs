//! Server-side permission matrix. Console affordances mirror this table but
//! never define it: every mutating handler must call `require` (or
//! `Role::can`) against the session's organisation-scoped role.
//!
//! The table is pinned by `docs/permission-matrix.json`; the console's
//! `apps/console/src/lib/roles.ts` is tested against the same file.

use crate::{ApiError, Role, Session};

// Handlers adopt variants one by one; unused ones are the not-yet-migrated.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Permission {
    /// Read device, route, policy, DNS and resource inventory.
    ViewNetwork,
    /// Rename, tag, approve, suspend, revoke and tombstone peers.
    ManagePeers,
    /// Mint, list and revoke join keys.
    ManageJoinKeys,
    /// Network resources, routes, IPAM and connectors.
    ManageNetworks,
    /// Access policy, posture checks and SSH rules.
    ManagePolicy,
    /// Organisation DNS, nameserver groups and zones.
    ManageDns,
    /// Private service publishing.
    ManageServices,
    /// Read the administrative audit log and traffic diagnostics.
    ViewAudit,
    /// Export audit and traffic records.
    ExportAudit,
    /// Webhooks, notifications and event forwarding.
    ManageIntegrations,
    /// Automation API clients and service users. Owner-only: a client secret
    /// is a long-lived credential that outlives any one person's role.
    ManageApiClients,
    /// Organisation security settings, SSO, SCIM, sign-in policy and roles.
    ManageSecurity,
    /// Read the protected operator health view (versions, schema, relays,
    /// outbox, expiry counts, backup proof). Read-only, never key material.
    ViewOperations,
    /// Agent network: model providers, agent keys and their policies.
    ManageAgentGateway,
    /// Read agent network configuration and model usage (never prompt content).
    ViewAgentUsage,
    /// Start browser SSH/RDP sessions and request allowlisted remote jobs.
    UseRemoteSessions,
    /// Define remote job templates and approve runs. Owner-only: a job runs
    /// on devices without anyone at the keyboard.
    ManageRemoteJobs,
}

impl Role {
    pub(crate) fn can(self, permission: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Owner => true,
            Role::Admin => !matches!(
                permission,
                ManageSecurity | ManageApiClients | ViewOperations | ManageRemoteJobs
            ),
            Role::NetworkAdmin => matches!(
                permission,
                ViewNetwork
                    | ManagePeers
                    | ManageJoinKeys
                    | ManageNetworks
                    | ManagePolicy
                    | ManageDns
                    | ManageServices
                    | ViewAudit
                    | UseRemoteSessions
            ),
            Role::Auditor => matches!(
                permission,
                ViewNetwork | ViewAudit | ExportAudit | ViewOperations | ViewAgentUsage
            ),
            // Members could already read the audit log before this matrix existed.
            Role::Member => matches!(permission, ViewNetwork | ViewAudit),
        }
    }
}

pub(crate) fn require(session: &Session, permission: Permission) -> Result<(), ApiError> {
    if session.role.can(permission) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const ALL_ROLES: [Role; 5] = [
        Role::Owner,
        Role::Admin,
        Role::NetworkAdmin,
        Role::Auditor,
        Role::Member,
    ];

    pub(crate) const ALL_PERMISSIONS: [(Permission, &str); 17] = [
        (Permission::ViewNetwork, "view_network"),
        (Permission::ManagePeers, "manage_peers"),
        (Permission::ManageJoinKeys, "manage_join_keys"),
        (Permission::ManageNetworks, "manage_networks"),
        (Permission::ManagePolicy, "manage_policy"),
        (Permission::ManageDns, "manage_dns"),
        (Permission::ManageServices, "manage_services"),
        (Permission::ViewAudit, "view_audit"),
        (Permission::ExportAudit, "export_audit"),
        (Permission::ManageIntegrations, "manage_integrations"),
        (Permission::ManageApiClients, "manage_api_clients"),
        (Permission::ManageSecurity, "manage_security"),
        (Permission::ViewOperations, "view_operations"),
        (Permission::ManageAgentGateway, "manage_agent_gateway"),
        (Permission::ViewAgentUsage, "view_agent_usage"),
        (Permission::UseRemoteSessions, "use_remote_sessions"),
        (Permission::ManageRemoteJobs, "manage_remote_jobs"),
    ];

    #[test]
    fn matrix_matches_shared_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../docs/permission-matrix.json")).unwrap();
        let names: Vec<&str> = fixture["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ALL_PERMISSIONS.iter().map(|(_, n)| *n).collect::<Vec<_>>(),
            "permission list drifted from docs/permission-matrix.json"
        );
        let roles = fixture["roles"].as_object().unwrap();
        assert_eq!(roles.len(), ALL_ROLES.len());
        for role in ALL_ROLES {
            let granted: Vec<&str> = roles[role.as_str()]
                .as_array()
                .unwrap_or_else(|| panic!("fixture lacks {}", role.as_str()))
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            for (permission, name) in ALL_PERMISSIONS {
                assert_eq!(
                    role.can(permission),
                    granted.contains(&name),
                    "{} / {name} differs from docs/permission-matrix.json",
                    role.as_str()
                );
            }
        }
    }

    #[test]
    fn existing_three_roles_keep_their_access() {
        assert!(Role::Owner.can(Permission::ManageSecurity));
        assert!(Role::Owner.can(Permission::ManageApiClients));
        assert!(Role::Admin.can(Permission::ManagePolicy));
        assert!(Role::Admin.can(Permission::ManageIntegrations));
        assert!(!Role::Admin.can(Permission::ManageSecurity));
        assert!(!Role::Admin.can(Permission::ManageApiClients));
        assert!(Role::Member.can(Permission::ViewNetwork));
        assert!(!Role::Member.can(Permission::ManagePeers));
        assert!(Role::Member.can(Permission::ViewAudit));
        assert!(!Role::Member.can(Permission::ExportAudit));
    }

    #[test]
    fn new_roles_are_least_privilege() {
        for permission in [
            Permission::ManageIntegrations,
            Permission::ManageApiClients,
            Permission::ManageSecurity,
            Permission::ExportAudit,
        ] {
            assert!(!Role::NetworkAdmin.can(permission));
        }
        for (permission, _) in ALL_PERMISSIONS {
            let read_only = matches!(
                permission,
                Permission::ViewNetwork
                    | Permission::ViewAudit
                    | Permission::ExportAudit
                    | Permission::ViewOperations
                    | Permission::ViewAgentUsage
            );
            assert_eq!(Role::Auditor.can(permission), read_only);
        }
    }

    #[test]
    fn unknown_roles_fail_closed() {
        for value in [
            "",
            "Owner",
            "superuser",
            "service",
            "network-admin",
            "admin ",
        ] {
            assert!(value.parse::<Role>().is_err(), "{value:?} must not parse");
        }
        for role in ALL_ROLES {
            assert_eq!(role.as_str().parse::<Role>(), Ok(role));
        }
    }
}
