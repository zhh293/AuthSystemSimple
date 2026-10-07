package com.authsystem.sso.domain;

public record StoredSession(String subject, long expiresAtEpochSecond) { }
