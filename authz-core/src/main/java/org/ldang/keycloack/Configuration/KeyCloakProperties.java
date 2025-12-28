package org.ldang.keycloack.Configuration;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "keycloak")
@Data
public class KeyCloakProperties {
    private String domainUrl;
    private String realmName;
    private String clientSecret;
    private String clientId;
    private String adminUsername;
    private String adminPassword;
}

