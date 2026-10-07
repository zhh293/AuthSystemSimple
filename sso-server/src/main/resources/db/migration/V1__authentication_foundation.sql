CREATE TABLE sso_user (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    subject_id VARCHAR(128) NOT NULL,
    username_normalized VARCHAR(128) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_sso_user_subject (subject_id),
    UNIQUE KEY uq_sso_user_username (username_normalized)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE oauth_client (
    client_id VARCHAR(128) NOT NULL PRIMARY KEY,
    display_name VARCHAR(200) NOT NULL,
    client_type VARCHAR(32) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE oauth_client_redirect_uri (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(128) NOT NULL,
    redirect_uri VARCHAR(2048) NOT NULL,
    CONSTRAINT fk_redirect_client FOREIGN KEY (client_id) REFERENCES oauth_client(client_id) ON DELETE CASCADE,
    UNIQUE KEY uq_client_redirect (client_id, redirect_uri)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE oauth_client_scope (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(128) NOT NULL,
    scope_name VARCHAR(64) NOT NULL,
    CONSTRAINT fk_scope_client FOREIGN KEY (client_id) REFERENCES oauth_client(client_id) ON DELETE CASCADE,
    UNIQUE KEY uq_client_scope (client_id, scope_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sso_audit_event (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    subject_id VARCHAR(128) NULL,
    remote_address VARCHAR(64) NULL,
    correlation_id VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMP(6) NOT NULL,
    KEY ix_audit_occurred_at (occurred_at),
    KEY ix_audit_correlation (correlation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
