package org.ldang.keycloack.constans;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum AuthzErrorCode {
    USER_NOT_FOUND("AUTHZ-001", "User not found. User name or id", HttpStatus.NOT_FOUND),
    ROLE_NOT_FOUND("AUTHZ-002", "Role not found. Role name", HttpStatus.NOT_FOUND),
    CLIENT_ROLE_NOT_FOUND("AUTHZ-003", "Client role not found", HttpStatus.NOT_FOUND),
    TOKEN_INVALID("AUTHZ-004", "Token invalid", HttpStatus.UNAUTHORIZED),
    API_ERROR("AUTHZ-005", "API error. See message for details", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_ADMIN_CREDENTIALS("AUTHZ-006", "Invalid admin credentials for Keycloak", HttpStatus.UNAUTHORIZED),
    REALM_NOT_FOUND("AUTHZ-007", "Realm not found", HttpStatus.NOT_FOUND),
    ADMIN_NO_REALM_ACCESS("AUTHZ-008", "Admin user has no access to the realm", HttpStatus.FORBIDDEN),
    NOT_FOUND_REALM_ROLE("AUTHZ-009", "Realm role not found. Realm role name", HttpStatus.NOT_FOUND),
    CLIENT_NOT_FOUND("AUTHZ-010", "Client not found", HttpStatus.NOT_FOUND),
    NOT_FOUND_CLIENT_SECRET("AUTHZ-011", "Client secret not found", HttpStatus.NOT_FOUND),
    INVALID_OLD_PASSWORD("AUTHZ-012","Invalid old password", HttpStatus.BAD_REQUEST),
    KEYCLOAK_SERVER_ERROR("AUTHZ-013","Server error", HttpStatus.INTERNAL_SERVER_ERROR),
    KEYCLOAK_CONNECTION_ERROR("AUTHZ-014","Invalid connect", HttpStatus.SERVICE_UNAVAILABLE),
    UNKNOWN_ERROR("AUTHZ-015","Unknown error", HttpStatus.INTERNAL_SERVER_ERROR),
    FORBIDDEN("AUTHZ-016", "Forbidden: You do not have permission to access this resource", HttpStatus.FORBIDDEN),
    UNAUTHORIZED("AUTHZ-017", "Unauthorized", HttpStatus.UNAUTHORIZED),
    VALIDATION_ERROR("AUTHZ-018", "Validation error", HttpStatus.BAD_REQUEST),
    INVALID_USER_NAME_OR_PASSWORD("AUTHZ-019", "Invalid username or password", HttpStatus.BAD_REQUEST),
    DUPLICATE("AUTHZ-020", "Duplicate", HttpStatus.CONFLICT);;

    private final String code;
    private final String defaultMessage;
    private final HttpStatus httpStatus;

    AuthzErrorCode(String code, String defaultMessage, HttpStatus httpStatus) {
        this.code = code;
        this.defaultMessage = defaultMessage;
        this.httpStatus = httpStatus;
    }
}
