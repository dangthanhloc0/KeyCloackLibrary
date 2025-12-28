package org.ldang.keycloack.dto.user;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInformation {
    // information
    @JsonProperty("id")
    private String id;
    @JsonProperty("username")
    private String userName;
    @JsonProperty("email")
    private String email;
    @JsonProperty("enabled")
    private Boolean enabled;
    @JsonProperty("firstName")
    private String firstName;
    @JsonProperty("lastName")
    private String lastName;
    @JsonProperty("emailVerified")
    private Boolean emailVerified;

    // Roles
    private List<String> realmRoles;
    private Map<String, List<String>> clientRoles;

    private Map<String, List<String>> attributes;

    // Metadata
    @JsonProperty("createdTimestamp")
    private Long createdTimestamp;
    private String federationLink;
    private Boolean totp;
    private List<String> disableableCredentialTypes;
    private List<String> requiredActions;

}
