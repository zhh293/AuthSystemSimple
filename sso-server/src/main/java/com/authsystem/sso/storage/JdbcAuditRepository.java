package com.authsystem.sso.storage;

import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class JdbcAuditRepository implements AuditRepository {
    private final JdbcTemplate jdbc;
    public JdbcAuditRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    @Override public void record(String eventType, String outcome, String subject, String clientAddress, String correlationId) {
        jdbc.update("insert into sso_audit_event(event_type, outcome, subject_id, remote_address, correlation_id, occurred_at) values (?, ?, ?, ?, ?, ?)",
                eventType, outcome, subject, clientAddress, correlationId, Timestamp.from(Instant.now()));
    }
}
