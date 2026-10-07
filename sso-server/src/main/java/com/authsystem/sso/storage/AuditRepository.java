package com.authsystem.sso.storage;

public interface AuditRepository {
    void record(String eventType, String outcome, String subject, String clientAddress, String correlationId);
}
