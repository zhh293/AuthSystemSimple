package com.authsystem.sso.example;

import com.authsystem.sso.client.starter.SsoHttpSecurityConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Profile("sso-sdk")
public class SsoSdkSecurityConfiguration {
    @Bean
    SecurityFilterChain sdkRelyingParty(HttpSecurity http,SsoHttpSecurityConfigurer sso) throws Exception {
        http.with(sso,Customizer.withDefaults())
                .authorizeHttpRequests(auth->auth.requestMatchers("/","/error").permitAll().anyRequest().authenticated());
        return http.build();
    }
}
