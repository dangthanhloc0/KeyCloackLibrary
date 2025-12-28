package org.ldang.keycloack.dto.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class TokenIntrospectionResponse {

    @JsonProperty("active")
    private Boolean active;

    @JsonProperty("client_id")
    private String clientIdentifier;

    @JsonProperty("username")
    private String username;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("exp")
    private Long expirationTime;

    @JsonProperty("iat")
    private Long issuedAt;

    @JsonProperty("sub")
    private String subjectUserId;

    @JsonProperty("aud")
    private String audience;

    @JsonProperty("iss")
    private String issuer;

    @JsonProperty("jti")
    private String tokenId;

    @JsonProperty("realm_access")
    private RealmAccess realmAccess;

    @Data
    public static class RealmAccess {
        private List<String> roles;
    }
}


