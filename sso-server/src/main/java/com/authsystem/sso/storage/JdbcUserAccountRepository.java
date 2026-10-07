package com.authsystem.sso.storage;

import com.authsystem.sso.domain.UserAccount;
import java.util.List;
import java.util.Optional;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class JdbcUserAccountRepository implements UserAccountRepository {
    private final JdbcTemplate jdbc;
    private final boolean directoryMode;
    private final long directoryMaxStalenessSeconds;
    public JdbcUserAccountRepository(JdbcTemplate jdbc,
            @Value("${sso.identity.credential-mode:database}") String credentialMode,
            @Value("${sso.identity.directory-sync-max-staleness-seconds:120}") long directoryMaxStalenessSeconds) {
        this.jdbc = jdbc;
        this.directoryMode = "directory".equals(credentialMode);
        this.directoryMaxStalenessSeconds = directoryMaxStalenessSeconds;
    }
    @Override public Optional<UserAccount> findByUsername(String username) {
        List<UserAccount> rows = jdbc.query("select id, subject_id, password_hash, enabled from sso_user where username_normalized = ? limit 1",
                (rs, row) -> new UserAccount(rs.getLong("id"), rs.getString("subject_id"), rs.getString("password_hash"), rs.getBoolean("enabled")), username);
        return rows.stream().findFirst();
    }

    @Override public boolean isEnabledBySubject(String subject) {
        if (directoryMode) {
            List<AccountSyncState> rows = jdbc.query("select u.enabled, d.last_success_at from sso_user u "
                            + "left join sso_directory_sync_state d on d.sync_id = 'directory' where u.subject_id = ? limit 1",
                    (rs, row) -> new AccountSyncState(rs.getBoolean(1), rs.getTimestamp(2)), subject);
            if (rows.isEmpty()) return false;
            if (directoryMaxStalenessSeconds < 1 || rows.get(0).lastSuccessfulSync() == null
                    || !rows.get(0).lastSuccessfulSync().toInstant()
                            .isAfter(Instant.now().minusSeconds(directoryMaxStalenessSeconds))) {
                throw new DirectorySyncUnavailableException();
            }
            return rows.get(0).enabled();
        }
        List<Boolean> rows = jdbc.query("select enabled from sso_user where subject_id = ? limit 1",
                (rs, row) -> rs.getBoolean(1), subject);
        return !rows.isEmpty() && rows.get(0);
    }

    private record AccountSyncState(boolean enabled, java.sql.Timestamp lastSuccessfulSync) { }
}
