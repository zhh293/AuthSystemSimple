package com.authsystem.sso.client.starter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(value = "sso.client", ignoreUnknownFields = false)
public class SsoClientSettings {
    private boolean enabled;
    private String issuer, clientId, clientSecret, redirectUri;
    private String cookieName, cookiePath = "/", cookieSameSite = "Lax";
    private String lookupHmacKey, refreshEncryptionKey;
    private String redisKeyPrefix = "sso:rp";
    private boolean secureCookie = true, localStore = false, apiUnauthorizedAsJson = true, statusEnabled = false;
    private Duration transactionTtl = Duration.ofMinutes(5), connectTimeout = Duration.ofSeconds(2), responseTimeout = Duration.ofSeconds(4);
    private Duration refreshSkew = Duration.ofSeconds(30), familyLifetime = Duration.ofDays(30), metadataCacheTtl = Duration.ofMinutes(15);
    private Duration userMappingCacheTtl = Duration.ZERO;
    private Duration jwksRefreshInterval = Duration.ofMinutes(5), jwksStaleIfError = Duration.ofHours(1);
    private List<String> protectedPaths = new ArrayList<>(List.of("/**"));
    private List<String> publicPaths = new ArrayList<>(List.of("/sso/login", "/sso/callback", "/sso/logout"));
    private List<String> scopes = new ArrayList<>(List.of("openid", "profile"));
    private String loginPath = "/sso/login";
    private String callbackPath = "/sso/callback";
    private String logoutPath = "/sso/logout";
    private String statusPath = "/sso/status";
    private String returnToParameter = "returnTo";

    public boolean isEnabled() {
        return enabled;
    }
    public void setEnabled(boolean value) {
        enabled = value;
    }

    public String getIssuer() {
        return issuer;
    }
    public void setIssuer(String value) {
        issuer = value;
    }

    public String getClientId() {
        return clientId;
    }
    public void setClientId(String value) {
        clientId = value;
    }

    public String getClientSecret() {
        return clientSecret;
    }
    public void setClientSecret(String value) {
        clientSecret = value;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
    public void setRedirectUri(String value) {
        redirectUri = value;
    }

    public String getCookieName() {
        return cookieName;
    }
    public void setCookieName(String value) {
        cookieName = value;
    }

    public String getCookiePath() {
        return cookiePath;
    }
    public void setCookiePath(String value) {
        cookiePath = value;
    }

    public String getCookieSameSite() {
        return cookieSameSite;
    }
    public void setCookieSameSite(String value) {
        cookieSameSite = value;
    }

    public String getLookupHmacKey() {
        return lookupHmacKey;
    }
    public void setLookupHmacKey(String value) {
        lookupHmacKey = value;
    }

    public String getRefreshEncryptionKey() {
        return refreshEncryptionKey;
    }
    public void setRefreshEncryptionKey(String value) {
        refreshEncryptionKey = value;
    }

    public String getRedisKeyPrefix() {
        return redisKeyPrefix;
    }
    public void setRedisKeyPrefix(String value) {
        redisKeyPrefix = value;
    }

    public boolean isSecureCookie() {
        return secureCookie;
    }
    public void setSecureCookie(boolean value) {
        secureCookie = value;
    }

    public boolean isLocalStore() {
        return localStore;
    }
    public void setLocalStore(boolean value) {
        localStore = value;
    }

    public boolean isApiUnauthorizedAsJson() {
        return apiUnauthorizedAsJson;
    }
    public void setApiUnauthorizedAsJson(boolean value) {
        apiUnauthorizedAsJson = value;
    }

    public boolean isStatusEnabled() {
        return statusEnabled;
    }
    public void setStatusEnabled(boolean value) {
        statusEnabled = value;
    }

    public Duration getTransactionTtl() {
        return transactionTtl;
    }
    public void setTransactionTtl(Duration value) {
        transactionTtl = value;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }
    public void setConnectTimeout(Duration value) {
        connectTimeout = value;
    }

    public Duration getResponseTimeout() {
        return responseTimeout;
    }
    public void setResponseTimeout(Duration value) {
        responseTimeout = value;
    }

    public Duration getRefreshSkew() {
        return refreshSkew;
    }
    public void setRefreshSkew(Duration value) {
        refreshSkew = value;
    }

    public Duration getFamilyLifetime() {
        return familyLifetime;
    }
    public void setFamilyLifetime(Duration value) {
        familyLifetime = value;
    }

    public Duration getUserMappingCacheTtl() {
        return userMappingCacheTtl;
    }
    public void setUserMappingCacheTtl(Duration value) {
        userMappingCacheTtl = value;
    }

    public Duration getMetadataCacheTtl() {
        return metadataCacheTtl;
    }
    public void setMetadataCacheTtl(Duration value) {
        metadataCacheTtl = value;
    }

    public Duration getJwksRefreshInterval() {
        return jwksRefreshInterval;
    }
    public void setJwksRefreshInterval(Duration value) {
        jwksRefreshInterval = value;
    }

    public Duration getJwksStaleIfError() {
        return jwksStaleIfError;
    }
    public void setJwksStaleIfError(Duration value) {
        jwksStaleIfError = value;
    }

    public List<String> getProtectedPaths() {
        return protectedPaths;
    }
    public void setProtectedPaths(List<String> value) {
        protectedPaths = value;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }
    public void setPublicPaths(List<String> value) {
        publicPaths = value;
    }

    public List<String> getScopes() {
        return scopes;
    }
    public void setScopes(List<String> value) {
        scopes = value;
    }

    public String getLoginPath() {
        return loginPath;
    }
    public void setLoginPath(String value) {
        loginPath = value;
    }

    public String getCallbackPath() {
        return callbackPath;
    }
    public void setCallbackPath(String value) {
        callbackPath = value;
    }

    public String getLogoutPath() {
        return logoutPath;
    }
    public void setLogoutPath(String value) {
        logoutPath = value;
    }

    public String getStatusPath() {
        return statusPath;
    }
    public void setStatusPath(String value) {
        statusPath = value;
    }

    public String getReturnToParameter() {
        return returnToParameter;
    }
    public void setReturnToParameter(String value) {
        returnToParameter = value;
    }
}
