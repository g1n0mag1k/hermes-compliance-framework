import React, { useContext } from 'react';
import { WorkspaceContext } from '../App';

export const RequireRole = ({ allowedRoles, children }) => {
    const { workspace } = useContext(WorkspaceContext);
    if (!workspace || !allowedRoles.includes(workspace.role)) {
        return null;
    }
    return children;
};
