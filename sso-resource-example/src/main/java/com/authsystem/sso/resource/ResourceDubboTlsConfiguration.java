package com.authsystem.sso.resource;

import org.apache.dubbo.config.SslConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile({"prod", "production"})
public class ResourceDubboTlsConfiguration {
    @Bean
    SslConfig dubboSslConfig(@Value("${SSO_DUBBO_CLIENT_CERT}") String clientCertificate,
            @Value("${SSO_DUBBO_CLIENT_KEY}") String clientPrivateKey,
            @Value("${SSO_DUBBO_SERVER_CA}") String trustedServerCertificates) {
        SslConfig ssl = new SslConfig();
        ssl.setClientKeyCertChainPath(clientCertificate);
        ssl.setClientPrivateKeyPath(clientPrivateKey);
        ssl.setClientTrustCertCollectionPath(trustedServerCertificates);
        return ssl;
    }
}
