package com.authsystem.sso.client.starter;

import java.net.ProxySelector;

/** Allows enterprise proxy selection while the SDK retains TLS verification, redirect, timeout and response-size rules. */
@FunctionalInterface
public interface SsoHttpClientCustomizer {
    ProxySelector proxySelector();
}
