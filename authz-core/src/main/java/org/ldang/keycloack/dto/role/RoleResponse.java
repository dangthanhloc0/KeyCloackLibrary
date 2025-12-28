package org.ldang.keycloack.dto.role;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class RoleResponse {
    List<String> realmRoles;
    Map<String, List<String>> clientRoles;
}
