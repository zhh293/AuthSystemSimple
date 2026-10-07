package com.authsystem.sso.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import com.nimbusds.jose.JWSAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class SigningJwkConfiguration {
    @Bean
    JWKSource<SecurityContext> jwkSource(SsoProperties properties, Environment environment) throws Exception {
        String[] activeProfiles = environment.getActiveProfiles();
        ProductionProfiles.validate(activeProfiles, environment.getDefaultProfiles());
        boolean production = ProductionProfiles.isProduction(activeProfiles);
        List<JWK> keys = production
                ? loadProductionKeys(properties)
                : List.<JWK>of(generateDevelopmentKey());
        JWKSet jwkSet = new JWKSet(keys);
        return (selector, context) -> selector.select(jwkSet);
    }

    private static List<JWK> loadProductionKeys(SsoProperties properties) throws Exception {
        if (properties.getOidcKeystorePath() == null || properties.getOidcKeystorePassword() == null) {
            throw new IllegalStateException("OIDC signing keystore path and password are required in production");
        }
        String activeAlias = requireAlias(properties.getOidcKeyAlias());
        Set<String> aliases = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        aliases.add(activeAlias);
        for (String alias : properties.getOidcPreviousKeyAliases()) {
            String previousAlias = requireAlias(alias);
            if (!aliases.add(previousAlias)) throw new IllegalStateException("OIDC signing aliases must be unique");
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(Path.of(properties.getOidcKeystorePath()))) {
            keyStore.load(input, properties.getOidcKeystorePassword().toCharArray());
        }
        List<JWK> keys = new ArrayList<>();
        keys.add(loadActiveSigningKey(keyStore, properties, activeAlias));
        for (String alias : properties.getOidcPreviousKeyAliases()) keys.add(loadPreviousPublicKey(keyStore, alias));
        return List.copyOf(keys);
    }

    private static RSAKey loadActiveSigningKey(KeyStore keyStore, SsoProperties properties, String alias) throws Exception {
        var privateKey = keyStore.getKey(alias, properties.getOidcKeystorePassword().toCharArray());
        var certificate = keyStore.getCertificate(alias);
        if (!(privateKey instanceof RSAPrivateKey rsaPrivateKey) || certificate == null
                || !(certificate.getPublicKey() instanceof RSAPublicKey rsaPublicKey)) {
            throw new IllegalStateException("Active OIDC key alias must contain an RSA private key and certificate");
        }
        if (rsaPublicKey.getModulus().bitLength() < 2048 || rsaPrivateKey.getModulus().bitLength() < 2048) {
            throw new IllegalStateException("OIDC RSA signing keys must be at least 2048 bits");
        }
        verifyKeyPair(rsaPrivateKey, rsaPublicKey);
        return new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).keyID(alias)
                .keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
    }

    private static RSAKey loadPreviousPublicKey(KeyStore keyStore, String alias) throws Exception {
        var certificate = keyStore.getCertificate(alias);
        if (certificate == null || !(certificate.getPublicKey() instanceof RSAPublicKey rsaPublicKey)) {
            throw new IllegalStateException("Previous OIDC key alias must contain an RSA certificate");
        }
        if (rsaPublicKey.getModulus().bitLength() < 2048) {
            throw new IllegalStateException("Previous OIDC RSA keys must be at least 2048 bits");
        }
        return new RSAKey.Builder(rsaPublicKey).keyID(alias).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
    }

    private static String requireAlias(String alias) {
        if (alias == null || alias.isBlank()) throw new IllegalStateException("OIDC key aliases must not be blank");
        return alias;
    }

    private static void verifyKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey) throws Exception {
        byte[] challenge = new byte[32];
        byte[] signature = null;
        new java.security.SecureRandom().nextBytes(challenge);
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(challenge);
            signature = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            if (!verifier.verify(signature)) throw new IllegalStateException("Active OIDC private key does not match its certificate");
        } finally {
            java.util.Arrays.fill(challenge, (byte) 0);
            if (signature != null) java.util.Arrays.fill(signature, (byte) 0);
        }
    }

    private static RSAKey generateDevelopmentKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate()).keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
    }
}
