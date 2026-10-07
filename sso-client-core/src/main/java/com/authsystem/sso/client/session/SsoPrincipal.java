package com.authsystem.sso.client.session;

import java.util.Map;

public record SsoPrincipal(String subject, String name, String email, Map<String, Object> attributes) {
    public SsoPrincipal {
        attributes = Map.copyOf(attributes);
    }
}
