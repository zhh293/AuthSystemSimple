package com.authsystem.sso.observability;

import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.Locale;
import org.springframework.stereotype.Component;

/** Emits bounded-cardinality authentication lifecycle counters without user or credential labels. */
@Component
public final class SsoMetrics {
    public enum AuthenticationOutcome { SUCCESS, FAILURE, THROTTLED, DEPENDENCY_ERROR }
    public enum SessionOutcome { ACTIVE, INACTIVE, ACCOUNT_DISABLED, DEPENDENCY_ERROR }
    public enum RefreshOutcome { FAMILY_CREATED, ROTATED, REPLAY_REJECTED, INVALID_REJECTED }
    public enum TokenOutcome { ACTIVE, INACTIVE, DEPENDENCY_ERROR }
    public enum DirectorySyncOutcome { PAGE_APPLIED, FAILURE, CONFLICT }

    private final MeterRegistry registry;

    public SsoMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    public void authentication(AuthenticationOutcome outcome) {
        registry.counter("sso.authentication.attempts", "outcome", outcome.name().toLowerCase(Locale.ROOT)).increment();
    }

    public void session(SessionOutcome outcome) {
        registry.counter("sso.tgc.validation", "outcome", outcome.name().toLowerCase(Locale.ROOT)).increment();
    }

    public void logout() {
        registry.counter("sso.logout.requests").increment();
    }

    public void logoutDependencyFailure() {
        registry.counter("sso.logout.dependency_failures").increment();
    }

    public void tokenValidation(TokenOutcome outcome) {
        registry.counter("sso.resource_token.validation", "outcome", outcome.name().toLowerCase(Locale.ROOT)).increment();
    }

    public void httpRequest(String endpoint, String statusClass, Duration elapsed) {
        registry.counter("sso.http.endpoint.requests", "endpoint", endpoint, "status", statusClass).increment();
        registry.timer("sso.http.endpoint.duration", "endpoint", endpoint, "status", statusClass).record(elapsed);
    }

    public void refresh(RefreshOutcome outcome) {
        registry.counter("sso.refresh.family.events", "event", outcome.name().toLowerCase(Locale.ROOT)).increment();
    }

    public void directorySync(DirectorySyncOutcome outcome) {
        registry.counter("sso.directory.sync.events", "outcome", outcome.name().toLowerCase(Locale.ROOT)).increment();
    }
}
