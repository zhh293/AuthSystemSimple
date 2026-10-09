package com.authsystem.sso.client.starter;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/** Composes SDK authentication into the application's existing SecurityFilterChain. */
public final class SsoHttpSecurityConfigurer extends AbstractHttpConfigurer<SsoHttpSecurityConfigurer, HttpSecurity> {
    private final SsoAuthenticationFilter filter;
    SsoHttpSecurityConfigurer(SsoAuthenticationFilter filter) {
        this.filter = filter;
    }
    @Override public void init(HttpSecurity http) throws Exception { }
    @Override public void configure(HttpSecurity http) {
        http.addFilterBefore(filter, AnonymousAuthenticationFilter.class);
    }
}
