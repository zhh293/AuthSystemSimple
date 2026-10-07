ALTER TABLE sso_user
    MODIFY COLUMN password_hash VARCHAR(255) NULL;
