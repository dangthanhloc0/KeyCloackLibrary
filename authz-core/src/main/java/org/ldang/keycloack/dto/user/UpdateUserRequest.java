package org.ldang.keycloack.dto.user;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.Email;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UpdateUserRequest {
    private String email;
    private String firstName;
    private String lastName;
    private Boolean enabled;
}
