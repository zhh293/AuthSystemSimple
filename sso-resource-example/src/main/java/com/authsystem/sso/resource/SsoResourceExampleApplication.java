package com.authsystem.sso.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.ApplicationContextInitializer;

@SpringBootApplication
public class SsoResourceExampleApplication {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(SsoResourceExampleApplication.class);
        application.addInitializers((ApplicationContextInitializer<ConfigurableApplicationContext>) new ResourceProfileGuard());
        application.run(args);
    }
}
