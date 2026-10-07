ALTER TABLE sso_audit_event
    ADD COLUMN actor_id VARCHAR(128) NULL,
    ADD COLUMN resource_type VARCHAR(32) NULL,
    ADD COLUMN resource_id VARCHAR(128) NULL,
    ADD KEY ix_audit_actor_occurred (actor_id, occurred_at),
    ADD KEY ix_audit_resource (resource_type, resource_id);
