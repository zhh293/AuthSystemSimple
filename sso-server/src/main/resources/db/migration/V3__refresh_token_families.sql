CREATE TABLE oauth_refresh_token_family (
    family_id VARCHAR(100) NOT NULL PRIMARY KEY,
    client_id VARCHAR(128) NOT NULL,
    subject_id VARCHAR(128) NOT NULL,
    current_token_digest VARCHAR(128) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_refresh_family_current_token (current_token_digest),
    KEY ix_refresh_family_subject_client (subject_id, client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE oauth_refresh_token_history (
    token_digest VARCHAR(128) NOT NULL PRIMARY KEY,
    family_id VARCHAR(100) NOT NULL,
    token_status VARCHAR(16) NOT NULL,
    issued_at TIMESTAMP(6) NOT NULL,
    consumed_at TIMESTAMP(6) NULL,
    CONSTRAINT fk_refresh_history_family FOREIGN KEY (family_id)
        REFERENCES oauth_refresh_token_family(family_id) ON DELETE CASCADE,
    KEY ix_refresh_history_family_status (family_id, token_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
