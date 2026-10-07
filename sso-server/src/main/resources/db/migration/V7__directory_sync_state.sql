CREATE TABLE sso_directory_sync_state (
    sync_id VARCHAR(32) NOT NULL PRIMARY KEY,
    cursor_value VARCHAR(1024) NULL,
    last_success_at TIMESTAMP(6) NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO sso_directory_sync_state (sync_id, cursor_value, last_success_at)
VALUES ('directory', NULL, NULL);
