package com.authsystem.sso.example;

import com.authsystem.sso.client.session.SsoCurrentUser;
import com.authsystem.sso.client.session.SsoPrincipal;
import org.springframework.http.MediaType;
import org.springframework.context.annotation.Profile;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@Profile("sso-sdk")
public class SsoSdkExampleController {
    @GetMapping("/") public Map<String,Object> home(){return Map.of("example","sso-client-sdk","authenticated",SsoCurrentUser.get().isPresent());}
    @GetMapping("/profile") public SsoPrincipal profile(){return SsoCurrentUser.get().orElseThrow();}
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
