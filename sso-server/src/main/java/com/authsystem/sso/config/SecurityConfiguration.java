package com.authsystem.sso.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import com.authsystem.sso.security.OpaqueUserInfoFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.core.annotation.Order;
import com.authsystem.sso.security.TgcAuthenticationFilter;
import com.authsystem.sso.security.LoginCryptoFilter;
import java.util.List;

@Configuration
public class SecurityConfiguration {
    @Bean
    FilterRegistrationBean<TgcAuthenticationFilter> tgcFilterServletRegistration(TgcAuthenticationFilter filter) {
        FilterRegistrationBean<TgcAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<OpaqueUserInfoFilter> userInfoFilterServletRegistration(OpaqueUserInfoFilter filter) {
        FilterRegistrationBean<OpaqueUserInfoFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<LoginCryptoFilter> loginCryptoFilterServletRegistration(LoginCryptoFilter filter) {
        FilterRegistrationBean<LoginCryptoFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    PasswordEncoder clientSecretPasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    SecurityContextRepository securityContextRepository() { return new HttpSessionSecurityContextRepository(); }

    @Bean
    CsrfTokenRepository csrfTokenRepository() { return new HttpSessionCsrfTokenRepository(); }

    @Bean
    SessionAuthenticationStrategy loginSessionAuthenticationStrategy(CsrfTokenRepository csrfTokenRepository) {
        return new CompositeSessionAuthenticationStrategy(List.of(
                new ChangeSessionIdAuthenticationStrategy(), new CsrfAuthenticationStrategy(csrfTokenRepository)));
    }

    @Bean
    @Order(2)
    SecurityFilterChain webSecurity(HttpSecurity http, TgcAuthenticationFilter tgcFilter, LoginCryptoFilter loginCryptoFilter,
            SecurityContextRepository securityContextRepository, CsrfTokenRepository csrfTokenRepository) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.requestMatchers("/actuator/health", "/actuator/health/**").permitAll().anyRequest().permitAll())
                .securityContext(context -> context.securityContextRepository(securityContextRepository))
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"))
                        .referrerPolicy(referrer -> referrer.policy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)))
                .addFilterBefore(tgcFilter, AnonymousAuthenticationFilter.class)
                .addFilterBefore(loginCryptoFilter, AnonymousAuthenticationFilter.class)
                .build();
    }
}
