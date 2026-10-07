package com.authsystem.sso.contracts;

import com.authsystem.sso.contracts.dto.DirectoryAccountSyncPage;
import com.authsystem.sso.contracts.dto.DirectoryAccountSyncRequest;

/** Versioned internal contract implemented by the authoritative corporate directory adapter. */
public interface DirectoryAccountSyncService {
    DirectoryAccountSyncPage fetchChanges(DirectoryAccountSyncRequest request);
}
