package com.authsystem.sso.example;

import com.authsystem.sso.client.session.SsoCurrentUser;
import com.authsystem.sso.client.session.SsoPrincipal;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.context.annotation.Profile;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RestController
@Profile("sso-sdk")
public class SsoSdkExampleController {
    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> home(CsrfToken csrf) throws IOException {
        String html;
        try (var input = new ClassPathResource("static/index.html").getInputStream()) {
            html = StreamUtils.copyToString(input, StandardCharsets.UTF_8);
        }
        html = html.replace("__CSRF_TOKEN__", escape(csrf.getToken()))
                .replace("__CSRF_HEADER__", escape(csrf.getHeaderName()));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("Content-Security-Policy",
                        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
                .header("Referrer-Policy", "no-referrer")
                .body(html);
    }

    @GetMapping("/profile")
    public ResponseEntity<SsoPrincipal> profile() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(SsoCurrentUser.get().orElseThrow());
    }
    @GetMapping(value = "/logout-form", produces = MediaType.TEXT_HTML_VALUE)
    public String logoutForm(HttpServletRequest request) {
        CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrf == null) csrf = (CsrfToken) request.getAttribute("_csrf");
        if (csrf == null) throw new IllegalStateException("CSRF token unavailable");
        return "<!doctype html><html><body><form method=\"post\" action=\"/sso/logout\">"
                + "<input type=\"hidden\" name=\"" + escape(csrf.getParameterName()) + "\" value=\""
                + escape(csrf.getToken()) + "\"><button type=\"submit\">Log out</button></form></body></html>";
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
