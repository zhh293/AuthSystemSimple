package com.authsystem.sso.admin;

import java.net.URI;
import java.nio.CharBuffer;
import java.io.Console;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

/** Standalone, operator-run user/client provisioning tool. */
public final class SsoAdminApplication {
    private static final Set<String> SUPPORTED_SCOPES = Set.of("openid", "profile", "email", "resource.read");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Argon2PasswordEncoder USER_PASSWORD_ENCODER = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    private static final PasswordEncoder CLIENT_SECRET_ENCODER = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    private SsoAdminApplication() { }

    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                usage();
                System.exit(2);
                return;
            }
            JdbcTemplate jdbc = connect();
            TransactionTemplate transaction = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
            if ("user".equals(args[0]) && "create".equals(args[1])) createUser(jdbc, transaction, parseOptions(args, 2));
            else if ("user".equals(args[0]) && "link-directory".equals(args[1])) linkDirectoryUser(jdbc, transaction, parseOptions(args, 2));
            else if ("client".equals(args[0]) && "create".equals(args[1])) createClient(jdbc, transaction, parseOptions(args, 2));
            else {
                usage();
                System.exit(2);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid provisioning request: " + e.getMessage());
            usage();
            System.exit(2);
        } catch (Exception e) {
            // Never print exception details: JDBC drivers may include bound values in diagnostics.
            System.err.println("Provisioning failed. Check database availability and operator input.");
            System.exit(1);
        }
    }

    private static JdbcTemplate connect() {
        String url = requiredEnv("SSO_DB_URL");
        if (!url.startsWith("jdbc:mysql:")) throw new IllegalArgumentException("SSO_DB_URL must use jdbc:mysql");
        DriverManagerDataSource source = new DriverManagerDataSource(url, requiredEnv("SSO_DB_USERNAME"), requiredEnv("SSO_DB_PASSWORD"));
        source.setDriverClassName("com.mysql.cj.jdbc.Driver");
        return new JdbcTemplate(source);
    }

    private static void createUser(JdbcTemplate jdbc, TransactionTemplate transaction, Options options) {
        options.rejectUnknown(Set.of("username", "subject", "display-name", "email"));
        String username = required(options.one("username"), "username").trim().toLowerCase(Locale.ROOT);
        String subject = required(options.one("subject"), "subject");
        String displayName = options.optional("display-name");
        String email = options.optional("email");
        String actor = requiredAdminActor();
        if (!username.matches("[a-z0-9._@+-]{1,128}")) throw new IllegalArgumentException("username format is invalid");
        if (subject.length() > 128 || subject.isBlank()) throw new IllegalArgumentException("subject must contain 1 to 128 characters");
        if (displayName != null && displayName.length() > 200) throw new IllegalArgumentException("display-name exceeds 200 characters");
        if (email != null && email.length() > 320) throw new IllegalArgumentException("email exceeds 320 characters");
        Console console = requireConsole();
        char[] password = console.readPassword("Password (12-1024 characters): ");
        char[] confirmation = console.readPassword("Confirm password: ");
        try {
            if (password == null || password.length < 12 || password.length > 1024) throw new IllegalArgumentException("password must contain 12 to 1024 characters");
            if (!Arrays.equals(password, confirmation)) throw new IllegalArgumentException("password confirmation does not match");
            String passwordHash = USER_PASSWORD_ENCODER.encode(CharBuffer.wrap(password));
            transaction.executeWithoutResult(status -> {
                jdbc.update("insert into sso_user (subject_id, username_normalized, password_hash, enabled, display_name, email, email_verified) values (?, ?, ?, true, ?, ?, false)",
                        subject, username, passwordHash, displayName, email);
                recordProvisioningAudit(jdbc, actor, "USER", subject);
            });
            console.printf("User provisioned: %s%n", username);
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (confirmation != null) Arrays.fill(confirmation, '\0');
        }
    }

    private static void linkDirectoryUser(JdbcTemplate jdbc, TransactionTemplate transaction, Options options) {
        options.rejectUnknown(Set.of("username", "subject", "display-name", "email"));
        String username = required(options.one("username"), "username").trim().toLowerCase(Locale.ROOT);
        String subject = required(options.one("subject"), "subject");
        String displayName = options.optional("display-name");
        String email = options.optional("email");
        String actor = requiredAdminActor();
        if (!username.matches("[a-z0-9._@+-]{1,128}")) throw new IllegalArgumentException("username format is invalid");
        if (subject.length() > 128 || subject.isBlank()) throw new IllegalArgumentException("subject must contain 1 to 128 characters");
        if (displayName != null && displayName.length() > 200) throw new IllegalArgumentException("display-name exceeds 200 characters");
        if (email != null && email.length() > 320) throw new IllegalArgumentException("email exceeds 320 characters");
        transaction.executeWithoutResult(status -> {
            jdbc.update("insert into sso_user (subject_id, username_normalized, password_hash, enabled, display_name, email, email_verified) values (?, ?, null, true, ?, ?, false)",
                    subject, username, displayName, email);
            recordProvisioningAudit(jdbc, actor, "DIRECTORY_USER_MAPPING", subject);
        });
        System.out.printf("Directory user mapping created: %s%n", username);
    }

    private static void createClient(JdbcTemplate jdbc, TransactionTemplate transaction, Options options) {
        options.rejectUnknown(Set.of("id", "name", "type", "redirect-uri", "scope"));
        String clientId = required(options.one("id"), "id");
        String name = required(options.one("name"), "name");
        String type = required(options.one("type"), "type").toUpperCase(Locale.ROOT);
        String actor = requiredAdminActor();
        List<String> redirects = options.many("redirect-uri");
        List<String> requestedScopes = options.many("scope");
        if (!clientId.matches("[A-Za-z0-9._-]{1,128}")) throw new IllegalArgumentException("client id format is invalid");
        if (name.isBlank() || name.length() > 200) throw new IllegalArgumentException("name must contain 1 to 200 characters");
        if (!"PUBLIC".equals(type) && !"CONFIDENTIAL".equals(type)) throw new IllegalArgumentException("type must be PUBLIC or CONFIDENTIAL");
        if (redirects.isEmpty() || redirects.size() > 20) throw new IllegalArgumentException("provide 1 to 20 redirect-uri values");
        if (requestedScopes.isEmpty()) throw new IllegalArgumentException("at least one scope is required");
        Set<String> scopes = new LinkedHashSet<>(requestedScopes);
        if (scopes.size() != requestedScopes.size()) throw new IllegalArgumentException("duplicate scopes are not allowed");
        if (!scopes.contains("openid") || !SUPPORTED_SCOPES.containsAll(scopes)) throw new IllegalArgumentException("scopes must include openid and use only openid, profile, email, resource.read");
        if (new LinkedHashSet<>(redirects).size() != redirects.size()) throw new IllegalArgumentException("duplicate redirect URIs are not allowed");
        redirects.forEach(SsoAdminApplication::validateRedirectUri);

        Console secretConsole = "CONFIDENTIAL".equals(type) ? requireConsole() : null;
        String rawSecret = "CONFIDENTIAL".equals(type) ? randomClientSecret() : null;
        String encodedSecret = rawSecret == null ? null : CLIENT_SECRET_ENCODER.encode(rawSecret);
        transaction.executeWithoutResult(status -> {
            jdbc.update("insert into oauth_client (client_id, display_name, client_type, enabled, client_secret_hash) values (?, ?, ?, true, ?)",
                    clientId, name, type, encodedSecret);
            for (String redirect : redirects) jdbc.update(
                    "insert into oauth_client_redirect_uri (client_id, redirect_uri) values (?, ?)", clientId, redirect);
            for (String scope : scopes) jdbc.update(
                    "insert into oauth_client_scope (client_id, scope_name) values (?, ?)", clientId, scope);
            recordProvisioningAudit(jdbc, actor, "OAUTH_CLIENT", clientId);
        });
        if (rawSecret == null) System.out.printf("Public client provisioned: %s%n", clientId);
        else secretConsole.printf("Confidential client provisioned: %s%nClient secret (displayed once): %s%n", clientId, rawSecret);
    }

    private static String randomClientSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        try { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
        finally { Arrays.fill(bytes, (byte) 0); }
    }

    private static void recordProvisioningAudit(JdbcTemplate jdbc, String actor, String resourceType, String resourceId) {
        jdbc.update("insert into sso_audit_event (event_type, outcome, subject_id, remote_address, correlation_id, occurred_at, actor_id, resource_type, resource_id) values (?, 'SUCCESS', NULL, NULL, ?, ?, ?, ?, ?)",
                "ADMIN_PROVISIONED", UUID.randomUUID().toString(), java.sql.Timestamp.from(java.time.Instant.now()), actor, resourceType, resourceId);
    }

    private static void validateRedirectUri(String value) {
        if (value.length() > 2048 || value.contains("*")) throw new IllegalArgumentException("redirect URI is too long or contains a wildcard");
        try {
            URI uri = new URI(value);
            if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null) throw new IllegalArgumentException("redirect URI must have a host and no user info or fragment");
            if ("https".equalsIgnoreCase(uri.getScheme())) return;
            String host = uri.getHost();
            if ("http".equalsIgnoreCase(uri.getScheme()) && ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host))) return;
            throw new IllegalArgumentException("redirect URI must use HTTPS (HTTP is allowed only for localhost)");
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException("redirect URI is invalid");
        }
    }

    private static Options parseOptions(String[] args, int start) {
        var values = new java.util.LinkedHashMap<String, List<String>>();
        for (int i = start; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--") || i + 1 >= args.length || args[i + 1].startsWith("--")) throw new IllegalArgumentException("options must use --name value form");
            values.computeIfAbsent(arg.substring(2), ignored -> new ArrayList<>()).add(args[++i]);
        }
        return new Options(values);
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value;
    }

    private static String requiredEnv(String name) { return required(System.getenv(name), name + " environment variable"); }

    private static String requiredAdminActor() {
        String actor = requiredEnv("SSO_ADMIN_ACTOR");
        if (actor.length() > 128) throw new IllegalArgumentException("SSO_ADMIN_ACTOR must be at most 128 characters");
        return actor;
    }

    private static Console requireConsole() {
        Console console = System.console();
        if (console == null) throw new IllegalArgumentException("an interactive terminal is required for password input");
        return console;
    }

    private static void usage() {
        System.err.println("Usage:\n  sso-admin user create --username USER --subject SUBJECT [--display-name NAME] [--email EMAIL]\n"
                + "  sso-admin user link-directory --username USER --subject SUBJECT [--display-name NAME] [--email EMAIL]\n"
                + "  sso-admin client create --id ID --name NAME --type PUBLIC|CONFIDENTIAL --redirect-uri URI... --scope openid [--scope profile|email|resource.read]");
    }

    private record Options(java.util.Map<String, List<String>> values) {
        String one(String key) {
            List<String> entries = values.get(key);
            if (entries == null) return null;
            if (entries.size() != 1) throw new IllegalArgumentException("--" + key + " may appear only once");
            return entries.get(0);
        }
        String optional(String key) { return one(key); }
        List<String> many(String key) { return values.getOrDefault(key, List.of()); }
        void rejectUnknown(Set<String> allowed) {
            for (String key : values.keySet()) if (!allowed.contains(key)) throw new IllegalArgumentException("unknown option --" + key);
        }
    }
}
