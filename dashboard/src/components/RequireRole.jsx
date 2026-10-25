import React, { useContext } from 'react';
import { WorkspaceContext } from '../App';

// Earlier role names are still issued by older registries; treat them as the
// current names. Mirrors LEGACY_ROLE_ALIASES in hermes/workspaces.py.
const LEGACY_ROLE_ALIASES = {
    msp_admin: 'org_admin',
    msp_tech: 'operator',
    client_readonly: 'viewer',
};

export const canonicalRole = (role) => LEGACY_ROLE_ALIASES[role] || role;

export const RequireRole = ({ allowedRoles, children }) => {
    const { workspace } = useContext(WorkspaceContext);
    const allowed = allowedRoles.map(canonicalRole);
    if (!workspace || !allowed.includes(canonicalRole(workspace.role))) {
        return null;
    }
    return children;
};
