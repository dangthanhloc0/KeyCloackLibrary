package org.ldang.keycloack.dto.role;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class RealmRoleResponse {

    private String id;

    private String name;

    private String description;

    private Boolean composite;

    @JsonProperty("clientRole")
    private boolean clientRole;

    @JsonProperty("containerId")
    private String containerId;
}
