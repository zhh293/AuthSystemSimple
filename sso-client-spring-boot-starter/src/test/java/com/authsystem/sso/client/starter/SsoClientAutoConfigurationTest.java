package com.authsystem.sso.client.starter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.security.web.SecurityFilterChain;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import static org.assertj.core.api.Assertions.assertThat;

class SsoClientAutoConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(SsoClientAutoConfiguration.class));
    @Test void disabledSdkDoesNotContributeSsoBeans() {
        runner.run(context -> {
                assertThat(context).doesNotHaveBean(SsoClientController.class);
                assertThat(context).doesNotHaveBean(SsoAuthenticationFilter.class);
            });
    }
    @Test void healthIntegrationIsAbsentWhenTheHostDoesNotIncludeActuator() {
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(SsoClientHealthAutoConfiguration.class))
        .withClassLoader(new FilteredClassLoader("org.springframework.boot.actuate.health"))
        .withPropertyValues("sso.client.enabled=true")
        .run(context -> assertThat(context).doesNotHaveBean("ssoClientHealthIndicator"));
    }
    @Test void enabledSdkComposesBeansWithoutDeclaringAnApplicationSecurityChain() throws Exception {
        HttpServer discoveryServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        String issuer = "http://localhost:" + discoveryServer.getAddress().getPort();
        String metadata = "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + issuer
            + "/authorize\",\"token_endpoint\":\"" + issuer + "/token\",\"jwks_uri\":\"" + issuer
            + "/jwks\"}";
        discoveryServer.createContext("/.well-known/openid-configuration", exchange -> {
            byte[] body = metadata.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        discoveryServer.start();
        try {
        runner.withConfiguration(AutoConfigurations.of(SsoClientAutoConfiguration.class, JacksonAutoConfiguration.class))
        .withPropertyValues("sso.client.enabled=true", "sso.client.issuer=" + issuer,
            "sso.client.client-id=portal", "sso.client.client-secret=local-secret",
            "sso.client.redirect-uri=http://localhost:8082/sso/callback",
            "sso.client.local-store=true", "sso.client.secure-cookie=false")
        .run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context).hasSingleBean(SsoClientController.class);
                assertThat(context).hasSingleBean(SsoAuthenticationFilter.class);
                assertThat(context.getBean(com.authsystem.sso.client.config.SsoClientProperties.class).familyLifetime())
                .isEqualTo(java.time.Duration.ofDays(30));
                assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
            });
        } finally {
            discoveryServer.stop(0);
        }
    }
}
