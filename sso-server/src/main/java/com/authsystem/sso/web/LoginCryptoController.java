package com.authsystem.sso.web;

import com.authsystem.sso.crypto.LoginCryptoService;
import com.authsystem.sso.crypto.LoginCryptoSessionResponse;
import com.authsystem.sso.crypto.LoginCryptoRateLimitException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.http.ResponseEntity;

@RestController
public class LoginCryptoController {
    private final LoginCryptoService crypto;
    public LoginCryptoController(LoginCryptoService crypto) { this.crypto = crypto; }
    @GetMapping("/login/crypto/session")
    public LoginCryptoSessionResponse session(HttpServletRequest request) {
        return crypto.createSession(request.getRemoteAddr());
    }
    @ExceptionHandler(LoginCryptoRateLimitException.class)
    public ResponseEntity<Void> rateLimited() { return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build(); }
}
