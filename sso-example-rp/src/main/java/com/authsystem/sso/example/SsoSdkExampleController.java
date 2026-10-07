package com.authsystem.sso.example;

import com.authsystem.sso.client.session.SsoCurrentUser;
import com.authsystem.sso.client.session.SsoPrincipal;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@Profile("sso-sdk")
public class SsoSdkExampleController {
    @GetMapping("/") public Map<String,Object> home(){return Map.of("example","sso-client-sdk","authenticated",SsoCurrentUser.get().isPresent());}
    @GetMapping("/profile") public SsoPrincipal profile(){return SsoCurrentUser.get().orElseThrow();}
}
