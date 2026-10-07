package com.authsystem.sso.client.observability;

import io.micrometer.core.instrument.MeterRegistry;

/** SDK metrics have a closed outcome vocabulary and never use user or token values as tags. */
public final class SsoClientMetrics {
    private final MeterRegistry registry;
    public SsoClientMetrics(MeterRegistry registry) {
        this.registry = registry;
    }
    public void login(String outcome) {
        increment("sso.client.login", outcome, "started", "succeeded", "failed");
    }
    public void callback(String outcome) {
        increment("sso.client.callback", outcome, "succeeded", "failed");
    }
    public void refresh(String outcome) {
        increment("sso.client.refresh", outcome, "attempted", "succeeded", "failed");
    }
    public void revoke(String outcome) {
        increment("sso.client.revoke", outcome, "succeeded", "failed");
    }
    private void increment(String name, String outcome, String... allowed) {
        for (String value:allowed)
            if (value.equals(outcome)) {
            registry.counter(name, "outcome", value).increment();
            return;
        }
        throw new IllegalArgumentException("Unsupported bounded metric outcome");
    }
}
