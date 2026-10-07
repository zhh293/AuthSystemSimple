package com.authsystem.sso.service;

import com.authsystem.sso.contracts.DirectoryAccountSyncService;
import com.authsystem.sso.contracts.dto.DirectoryAccountRecord;
import com.authsystem.sso.contracts.dto.DirectoryAccountSyncPage;
import com.authsystem.sso.contracts.dto.DirectoryAccountSyncRequest;
import com.authsystem.sso.observability.SsoMetrics;
import com.authsystem.sso.storage.AuditRepository;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.apache.dubbo.config.annotation.DubboReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Pulls directory account changes and commits each page together with its opaque cursor. */
@Component
@ConditionalOnProperty(prefix = "sso.identity", name = "credential-mode", havingValue = "directory")
public class DirectoryAccountSyncConsumer {
    private static final Logger LOGGER = LoggerFactory.getLogger(DirectoryAccountSyncConsumer.class);
    private static final int PAGE_SIZE = 500;
    private static final int MAX_PAGES_PER_RUN = 10;
    private static final Pattern USERNAME = Pattern.compile("[a-z0-9._@+-]{1,128}");
    private static final Pattern EMAIL = Pattern.compile("[^\\s@]+@[^\\s@]+\\.[^\\s@]+");

    @DubboReference(interfaceClass = DirectoryAccountSyncService.class, version = "1.0.0",
            check = false, timeout = 5000, retries = 0)
    private DirectoryAccountSyncService directory;

    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final AuditRepository audit;
    private final SsoMetrics metrics;

    public DirectoryAccountSyncConsumer(JdbcTemplate jdbc, PlatformTransactionManager transactionManager,
            AuditRepository audit, SsoMetrics metrics) {
        this.jdbc = jdbc;
        this.transaction = new TransactionTemplate(transactionManager);
        this.audit = audit;
        this.metrics = metrics;
    }

    @Scheduled(fixedDelayString = "${sso.identity.directory-sync-interval-ms:30000}")
    public void synchronizeDirectoryChanges() {
        for (int pageNumber = 0; pageNumber < MAX_PAGES_PER_RUN; pageNumber++) {
            try {
                if (!synchronizeOnePage()) return;
            } catch (SyncConflictException e) {
                metrics.directorySync(SsoMetrics.DirectorySyncOutcome.CONFLICT);
                LOGGER.warn("Directory account sync page rejected due to validation or cursor conflict");
                return;
            } catch (RuntimeException e) {
                metrics.directorySync(SsoMetrics.DirectorySyncOutcome.FAILURE);
                LOGGER.warn("Directory account sync page failed; causeType={}", e.getClass().getSimpleName());
                return;
            }
        }
    }

    private boolean synchronizeOnePage() {
        String cursor = readCursor();
        DirectoryAccountSyncPage page = directory.fetchChanges(new DirectoryAccountSyncRequest(cursor, PAGE_SIZE));
        validatePage(cursor, page);
        List<DirectoryAccountRecord> accounts = page.getAccounts().stream()
                .sorted(java.util.Comparator.comparing(DirectoryAccountRecord::getSubject)).toList();
        transaction.executeWithoutResult(status -> applyPage(cursor, page.getNextCursor(), accounts));
        metrics.directorySync(SsoMetrics.DirectorySyncOutcome.PAGE_APPLIED);
        return page.isHasMore();
    }

    private String readCursor() {
        List<String> cursors = jdbc.query("select cursor_value from sso_directory_sync_state where sync_id = 'directory'",
                (rs, row) -> rs.getString(1));
        if (cursors.isEmpty()) throw new IllegalStateException("Directory synchronization state is not initialized");
        return cursors.get(0);
    }

    private void validatePage(String cursor, DirectoryAccountSyncPage page) {
        if (cursor != null && cursor.length() > 1024) throw new SyncConflictException();
        if (page == null || page.getAccounts() == null || page.getAccounts().size() > PAGE_SIZE
                || page.getNextCursor() == null || page.getNextCursor().isBlank() || page.getNextCursor().length() > 1024
                || page.getNextCursor().chars().anyMatch(Character::isISOControl)
                || (page.isHasMore() && page.getNextCursor().equals(cursor))
                || (!page.getAccounts().isEmpty() && page.getNextCursor().equals(cursor))) throw new SyncConflictException();

        Set<String> subjects = new HashSet<>();
        Set<String> usernames = new HashSet<>();
        for (DirectoryAccountRecord account : page.getAccounts()) {
            if (account == null || account.getSubject() == null || account.getSubject().isBlank()
                    || account.getSubject().length() > 128 || !account.getSubject().equals(account.getSubject().trim())
                    || account.getSubject().chars().anyMatch(Character::isISOControl)
                    || account.getUsernameNormalized() == null || !USERNAME.matcher(account.getUsernameNormalized()).matches()
                    || account.getDisplayName() != null && (account.getDisplayName().length() > 200
                            || account.getDisplayName().chars().anyMatch(Character::isISOControl))
                    || account.getEmail() != null && (account.getEmail().length() > 320 || !EMAIL.matcher(account.getEmail()).matches())
                    || account.isEmailVerified() && (account.getEmail() == null || account.getEmail().isBlank())
                    || !subjects.add(account.getSubject()) || !usernames.add(account.getUsernameNormalized())) {
                throw new SyncConflictException();
            }
        }
    }

    private void applyPage(String expectedCursor, String nextCursor, List<DirectoryAccountRecord> accounts) {
        List<String> currentCursors = jdbc.query("select cursor_value from sso_directory_sync_state where sync_id = 'directory' for update",
                (rs, row) -> rs.getString(1));
        if (currentCursors.isEmpty() || !java.util.Objects.equals(currentCursors.get(0), expectedCursor)) {
            throw new SyncConflictException();
        }
        for (DirectoryAccountRecord account : accounts) synchronizeAccount(account);
        int updated = jdbc.update("update sso_directory_sync_state set cursor_value = ?, last_success_at = ? "
                        + "where sync_id = 'directory' and cursor_value <=> ?",
                nextCursor, Timestamp.from(Instant.now()), expectedCursor);
        if (updated != 1) throw new SyncConflictException();
        audit.record("DIRECTORY_SYNC_PAGE", "SUCCESS", null, null, UUID.randomUUID().toString());
    }

    private void synchronizeAccount(DirectoryAccountRecord account) {
        List<AccountMapping> bySubject = jdbc.query("select id, subject_id, username_normalized from sso_user where subject_id = ? for update",
                (rs, row) -> new AccountMapping(rs.getLong(1), rs.getString(2), rs.getString(3)), account.getSubject());
        List<AccountMapping> byUsername = jdbc.query("select id, subject_id, username_normalized from sso_user where username_normalized = ? for update",
                (rs, row) -> new AccountMapping(rs.getLong(1), rs.getString(2), rs.getString(3)), account.getUsernameNormalized());

        if (!bySubject.isEmpty()) {
            AccountMapping existing = bySubject.get(0);
            if (!existing.username().equals(account.getUsernameNormalized())
                    || !byUsername.isEmpty() && byUsername.get(0).id() != existing.id()) throw new SyncConflictException();
            jdbc.update("update sso_user set password_hash = null, enabled = ?, display_name = ?, email = ?, email_verified = ? where id = ?",
                    account.isEnabled(), account.getDisplayName(), account.getEmail(), account.isEmailVerified(), existing.id());
            revokeDisabledAccountFamilies(account);
            return;
        }
        if (!byUsername.isEmpty()) throw new SyncConflictException();
        jdbc.update("insert into sso_user (subject_id, username_normalized, password_hash, enabled, display_name, email, email_verified) "
                        + "values (?, ?, null, ?, ?, ?, ?)",
                account.getSubject(), account.getUsernameNormalized(), account.isEnabled(), account.getDisplayName(),
                account.getEmail(), account.isEmailVerified());
        revokeDisabledAccountFamilies(account);
    }

    private void revokeDisabledAccountFamilies(DirectoryAccountRecord account) {
        if (!account.isEnabled()) {
            jdbc.update("update oauth_refresh_token_family set revoked = true where subject_id = ? and revoked = false",
                    account.getSubject());
        }
    }

    private record AccountMapping(long id, String subject, String username) { }

    private static final class SyncConflictException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
