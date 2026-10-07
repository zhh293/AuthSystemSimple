package com.authsystem.sso.client.starter;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

final class DefaultSsoFailureHandler implements SsoFailureHandler {
    @Override
    public void handle(Failure failure, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("application/json");

        if (failure == Failure.DEPENDENCY_UNAVAILABLE) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.getWriter().write("{\"error\":\"sso_temporarily_unavailable\"}");
            return;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(
            "{\"error\":\"sso_authentication_failed\",\"requestId\":\""
            + UUID.randomUUID()
            + "\"}");
    }
}
