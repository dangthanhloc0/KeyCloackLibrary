package org.ldang.keycloack.dto.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenInfoDTO {

    // ===== Standard claims =====
    private String userId;          // sub
    private String issuer;           // iss
    private String tokenType;        // typ
    private Instant issuedAt;        // iat
    private Instant expiresAt;       // exp
    private String jti;              // jti
    private String sid;              // session id
    private String azp;              // authorized party
    private String acr;              // auth context
    private String scope;

    // ===== User info =====
    private String username;
    private String email;
    private Boolean emailVerified;
    private String name;
    private String givenName;
    private String familyName;

    // ===== Roles =====
    private Map<String, List<String>> clientRoles;
    // ===== Raw claims =====
    private Map<String, Object> claims;
}

