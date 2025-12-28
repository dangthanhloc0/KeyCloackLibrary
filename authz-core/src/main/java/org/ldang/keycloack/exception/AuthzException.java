package org.ldang.keycloack.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.ldang.keycloack.constans.AuthzErrorCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class AuthzException extends RuntimeException {

    public AuthzException(AuthzErrorCode errorCode) {
        super(errorCode.getCode() + ": " + errorCode.getDefaultMessage());
    }

    public AuthzException(AuthzErrorCode errorCode, String message) {
        super(errorCode.getCode() + ": " + errorCode.getDefaultMessage() + ": " + message);
    }

}

