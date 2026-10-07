package com.authsystem.sso.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sso")
public class SsoProperties {
    private String issuer = "http://localhost:8080";
    private String sessionCookie = "TGC";
    private String cookiePath = "/";
    private boolean cookieSecure = true;
    private String sessionHmacKey;
    private String rateLimitHmacKey;
    private String oauthStateHmacKey;
    private String tokenStorageHmacKey;
    private java.util.List<String> tokenStorageHmacPreviousKeys = new java.util.ArrayList<>();
    private long sessionTtlSeconds = 28800;
    private int loginMaxAttempts = 10;
    private long loginWindowSeconds = 300;
    private long authorizationCodeTtlSeconds = 90;
    private long pendingAuthorizationTtlSeconds = 600;
    private long accessTokenTtlSeconds = 600;
    private long idTokenTtlSeconds = 600;
    private long refreshTokenTtlSeconds = 2592000;
    private boolean authorizationStorageEncrypted;
    private long refreshFamilyHistoryRetentionSeconds = 2592000;
    private String oidcKeystorePath;
    private String oidcKeystorePassword;
    private String oidcKeyAlias = "sso-signing";
    private java.util.List<String> oidcPreviousKeyAliases = new java.util.ArrayList<>();
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getSessionCookie() { return sessionCookie; }
    public void setSessionCookie(String sessionCookie) { this.sessionCookie = sessionCookie; }
    public String getCookiePath() { return cookiePath; }
    public void setCookiePath(String cookiePath) { this.cookiePath = cookiePath; }
    public boolean isCookieSecure() { return cookieSecure; }
    public void setCookieSecure(boolean cookieSecure) { this.cookieSecure = cookieSecure; }
    public String getSessionHmacKey() { return sessionHmacKey; }
    public void setSessionHmacKey(String sessionHmacKey) { this.sessionHmacKey = sessionHmacKey; }
    public String getRateLimitHmacKey() { return rateLimitHmacKey; }
    public void setRateLimitHmacKey(String rateLimitHmacKey) { this.rateLimitHmacKey = rateLimitHmacKey; }
    public String getOauthStateHmacKey() { return oauthStateHmacKey; }
    public void setOauthStateHmacKey(String oauthStateHmacKey) { this.oauthStateHmacKey = oauthStateHmacKey; }
    public String getTokenStorageHmacKey() { return tokenStorageHmacKey; }
    public void setTokenStorageHmacKey(String tokenStorageHmacKey) { this.tokenStorageHmacKey = tokenStorageHmacKey; }
    public java.util.List<String> getTokenStorageHmacPreviousKeys() { return tokenStorageHmacPreviousKeys; }
    public void setTokenStorageHmacPreviousKeys(java.util.List<String> value) {
        tokenStorageHmacPreviousKeys = value == null ? new java.util.ArrayList<>() : new java.util.ArrayList<>(value);
    }
    public long getSessionTtlSeconds() { return sessionTtlSeconds; }
    public void setSessionTtlSeconds(long sessionTtlSeconds) { this.sessionTtlSeconds = sessionTtlSeconds; }
    public int getLoginMaxAttempts() { return loginMaxAttempts; }
    public void setLoginMaxAttempts(int loginMaxAttempts) { this.loginMaxAttempts = loginMaxAttempts; }
    public long getLoginWindowSeconds() { return loginWindowSeconds; }
    public void setLoginWindowSeconds(long loginWindowSeconds) { this.loginWindowSeconds = loginWindowSeconds; }
    public long getAuthorizationCodeTtlSeconds() { return authorizationCodeTtlSeconds; }
    public void setAuthorizationCodeTtlSeconds(long value) { authorizationCodeTtlSeconds = value; }
    public long getPendingAuthorizationTtlSeconds() { return pendingAuthorizationTtlSeconds; }
    public void setPendingAuthorizationTtlSeconds(long value) { pendingAuthorizationTtlSeconds = value; }
    public long getAccessTokenTtlSeconds() { return accessTokenTtlSeconds; }
    public void setAccessTokenTtlSeconds(long value) { accessTokenTtlSeconds = value; }
    public long getIdTokenTtlSeconds() { return idTokenTtlSeconds; }
    public void setIdTokenTtlSeconds(long value) { idTokenTtlSeconds = value; }
    public long getRefreshTokenTtlSeconds() { return refreshTokenTtlSeconds; }
    public void setRefreshTokenTtlSeconds(long value) { refreshTokenTtlSeconds = value; }
    public boolean isAuthorizationStorageEncrypted() { return authorizationStorageEncrypted; }
    public void setAuthorizationStorageEncrypted(boolean value) { authorizationStorageEncrypted = value; }
    public long getRefreshFamilyHistoryRetentionSeconds() { return refreshFamilyHistoryRetentionSeconds; }
    public void setRefreshFamilyHistoryRetentionSeconds(long value) { refreshFamilyHistoryRetentionSeconds = value; }
    public String getOidcKeystorePath() { return oidcKeystorePath; }
    public void setOidcKeystorePath(String value) { oidcKeystorePath = value; }
    public String getOidcKeystorePassword() { return oidcKeystorePassword; }
    public void setOidcKeystorePassword(String value) { oidcKeystorePassword = value; }
    public String getOidcKeyAlias() { return oidcKeyAlias; }
    public void setOidcKeyAlias(String value) { oidcKeyAlias = value; }
    public java.util.List<String> getOidcPreviousKeyAliases() { return oidcPreviousKeyAliases; }
    public void setOidcPreviousKeyAliases(java.util.List<String> value) {
        oidcPreviousKeyAliases = value == null ? new java.util.ArrayList<>() : new java.util.ArrayList<>(value);
    }
}
