package com.authsystem.sso.client.starter;

import org.springframework.web.client.RestClient;

/** Internal SDK transports; the starter does not add generic RestClient beans to the host context. */
record SsoHttpClients(RestClient protocol, RestClient jwks) {
}
