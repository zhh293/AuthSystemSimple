package com.authsystem.sso.storage;

import com.authsystem.sso.config.SsoProperties;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@EnableScheduling
public class RefreshTokenFamilyCleanup {
    private static final int BATCH_SIZE = 500;
    private final JdbcTemplate jdbc;
    private final SsoProperties properties;

    public RefreshTokenFamilyCleanup(JdbcTemplate jdbc, SsoProperties properties) {
        this.jdbc = jdbc;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${sso.refresh-family-cleanup-delay-ms:3600000}")
    public void removeExpiredAuthorizationStateAndHistory() {
        Instant cutoff = Instant.now().minusSeconds(properties.getRefreshFamilyHistoryRetentionSeconds());
        Timestamp cutoffTimestamp = Timestamp.from(cutoff);
        List<String> familyIds = jdbc.query(
                "select family_id from oauth_refresh_token_family where expires_at < ? order by expires_at limit " + BATCH_SIZE,
                (rs, row) -> rs.getString(1), cutoffTimestamp);
        for (String familyId : familyIds) {
            jdbc.update("delete from oauth_refresh_token_family where family_id = ? and expires_at < ?",
                    familyId, cutoffTimestamp);
        }
        List<String> authorizationIds = jdbc.query(
                "select id from oauth2_authorization "
                        + "where (authorization_code_expires_at is null or authorization_code_expires_at < ?) "
                        + "and (access_token_expires_at is null or access_token_expires_at < ?) "
                        + "and (oidc_id_token_expires_at is null or oidc_id_token_expires_at < ?) "
                        + "and (refresh_token_expires_at is null or refresh_token_expires_at < ?) "
                        + "and (user_code_expires_at is null or user_code_expires_at < ?) "
                        + "and (device_code_expires_at is null or device_code_expires_at < ?) "
                        + "order by id limit " + BATCH_SIZE,
                (rs, row) -> rs.getString(1), cutoffTimestamp, cutoffTimestamp, cutoffTimestamp,
                cutoffTimestamp, cutoffTimestamp, cutoffTimestamp);
        for (String authorizationId : authorizationIds) {
            jdbc.update("delete from oauth2_authorization where id = ?", authorizationId);
        }
    }
}
