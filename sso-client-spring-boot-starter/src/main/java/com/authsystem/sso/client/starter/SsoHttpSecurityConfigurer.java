package com.authsystem.sso.client.starter;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.http.HttpMethod;

/** Composes SDK authentication into the application's existing SecurityFilterChain. */
public final class SsoHttpSecurityConfigurer extends AbstractHttpConfigurer<SsoHttpSecurityConfigurer, HttpSecurity> {
    private final SsoAuthenticationFilter filter;
    private final SsoClientSettings settings;
    SsoHttpSecurityConfigurer(SsoAuthenticationFilter filter, SsoClientSettings settings) {
        this.filter = filter;
        this.settings = settings;
    }
    @Override public void init(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.requestMatchers(HttpMethod.GET, settings.getLoginPath(),
                settings.getCallbackPath()).permitAll()
            .requestMatchers(HttpMethod.POST, settings.getLogoutPath()).permitAll());
    }
    @Override public void configure(HttpSecurity http) {
        http.addFilterBefore(filter, AnonymousAuthenticationFilter.class);
    }
}
