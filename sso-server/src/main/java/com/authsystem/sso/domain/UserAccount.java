package com.authsystem.sso.domain;

public record UserAccount(long id, String subject, String passwordHash, boolean enabled) { }
