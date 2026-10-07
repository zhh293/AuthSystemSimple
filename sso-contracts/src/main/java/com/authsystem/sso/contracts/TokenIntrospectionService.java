package com.authsystem.sso.contracts;

import com.authsystem.sso.contracts.dto.TokenIntrospectionRequest;
import com.authsystem.sso.contracts.dto.TokenIntrospectionResult;

/** Internal, mTLS-protected validation contract for opaque Access Tokens. */
public interface TokenIntrospectionService {
    TokenIntrospectionResult introspect(TokenIntrospectionRequest request);
}
