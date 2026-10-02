//! Server-side permission matrix. Console affordances mirror this table but
//! never define it: every mutating handler must call `require` (or
//! `Role::can`) against the session's organisation-scoped role.

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
    /// Automation API clients and service users.
    ManageApiClients,
    /// Organisation security settings, SSO, SCIM and roles.
    ManageSecurity,
}

impl Role {
    pub(crate) fn can(self, permission: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Owner => true,
            Role::Admin => !matches!(permission, ManageSecurity),
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
mod tests {
    use super::*;

    #[test]
    fn existing_three_roles_keep_their_access() {
        assert!(Role::Owner.can(Permission::ManageSecurity));
        assert!(Role::Admin.can(Permission::ManagePolicy));
        assert!(!Role::Admin.can(Permission::ManageSecurity));
        assert!(Role::Member.can(Permission::ViewNetwork));
        assert!(!Role::Member.can(Permission::ManagePeers));
        assert!(Role::Member.can(Permission::ViewAudit));
        assert!(!Role::Member.can(Permission::ExportAudit));
    }
}
