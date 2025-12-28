package org.ldang.keycloack.utils;

import lombok.RequiredArgsConstructor;
import org.ldang.keycloack.dto.token.TokenInfoDTO;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class TokenDecoder {

    private final JwtDecoder jwtDecoder;

    public TokenInfoDTO decode(String accessToken) {
        Jwt jwt = jwtDecoder.decode(accessToken);

        return TokenInfoDTO.builder()
                .userId(jwt.getSubject())
                .issuer(jwt.getIssuer().toString())
                .tokenType(jwt.getClaimAsString("typ"))
                .issuedAt(jwt.getIssuedAt())
                .expiresAt(jwt.getExpiresAt())
                .jti(jwt.getClaimAsString("jti"))
                .sid(jwt.getClaimAsString("sid"))
                .azp(jwt.getClaimAsString("azp"))
                .acr(jwt.getClaimAsString("acr"))
                .scope(jwt.getClaimAsString("scope"))

                .username(jwt.getClaimAsString("preferred_username"))
                .email(jwt.getClaimAsString("email"))
                .emailVerified(jwt.getClaimAsBoolean("email_verified"))
                .name(jwt.getClaimAsString("name"))
                .givenName(jwt.getClaimAsString("given_name"))
                .familyName(jwt.getClaimAsString("family_name"))

                .clientRoles(extractClientRoles(jwt))
                .claims(jwt.getClaims())
                .build();
    }

    private Map<String, List<String>> extractClientRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess == null) return Map.of();

        Map<String, List<String>> result = new HashMap<>();
        resourceAccess.forEach((client, value) -> {
            Map<String, Object> clientData = (Map<String, Object>) value;
            result.put(
                    client,
                    (List<String>) clientData.get("roles")
            );
        });
        return result;
    }
}
