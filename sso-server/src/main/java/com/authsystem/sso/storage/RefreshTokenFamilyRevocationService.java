package com.authsystem.sso.storage;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenFamilyRevocationService {
    private final JdbcTemplate jdbc;

    public RefreshTokenFamilyRevocationService(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public void revokeAllForSubject(String subject) {
        if (subject == null || subject.isBlank()) return;
        jdbc.update("update oauth_refresh_token_family set revoked = true where subject_id = ? and revoked = false", subject);
    }
}
