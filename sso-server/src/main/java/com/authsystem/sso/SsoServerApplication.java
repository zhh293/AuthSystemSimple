package com.authsystem.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.ApplicationContextInitializer;
import com.authsystem.sso.config.ProductionProfiles;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SsoServerApplication {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(SsoServerApplication.class);
        application.addInitializers((ApplicationContextInitializer<ConfigurableApplicationContext>) context ->
                ProductionProfiles.validateEnvironment(context.getEnvironment()));
        application.run(args);
    }
}
