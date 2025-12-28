package org.ldang.keycloack.exception;

import lombok.RequiredArgsConstructor;
import org.ldang.keycloack.constans.AuthzErrorCode;
import org.ldang.keycloack.utils.KCResponse;

import java.util.Collections;
import java.util.List;

import static org.ldang.keycloack.utils.KCResponse.error;

@RequiredArgsConstructor
public class GlobalExceptionCustom {
    public static <T> KCResponse<T> handleKeycloakValidation(AuthzErrorCode errorCode, List<String> message) {
        switch (errorCode) {
            case VALIDATION_ERROR -> {
                return error(
                        errorCode,
                        message
                );
            }
        };
        return null;
    }

    public static <T> KCResponse<T> handleKeyCloakException(AuthzErrorCode errorCode,String message) {
        switch (errorCode) {
            case USER_NOT_FOUND, API_ERROR, NOT_FOUND_REALM_ROLE, REALM_NOT_FOUND, ADMIN_NO_REALM_ACCESS,
                 CLIENT_ROLE_NOT_FOUND, INVALID_OLD_PASSWORD,VALIDATION_ERROR,TOKEN_INVALID,INVALID_USER_NAME_OR_PASSWORD,
                 DUPLICATE, ROLE_NOT_FOUND-> {
                return error(
                        errorCode,
                        Collections.singletonList(message)
                );
            }
            case FORBIDDEN, UNKNOWN_ERROR, KEYCLOAK_CONNECTION_ERROR, KEYCLOAK_SERVER_ERROR, INVALID_ADMIN_CREDENTIALS,
                 NOT_FOUND_CLIENT_SECRET-> throw message != null
                    ? new AuthzException(errorCode, message)
                    : new AuthzException(errorCode);
        };
        return null;
    }
}
