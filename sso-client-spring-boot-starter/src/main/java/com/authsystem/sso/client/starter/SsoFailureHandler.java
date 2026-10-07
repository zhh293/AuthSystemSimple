package com.authsystem.sso.client.starter;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Receives only a fixed failure category, never OAuth parameters or credential values. */
@FunctionalInterface
public interface SsoFailureHandler {
    void handle(Failure failure, HttpServletResponse response) throws IOException;
    enum Failure {
        AUTHENTICATION_REJECTED, DEPENDENCY_UNAVAILABLE
    }
}
