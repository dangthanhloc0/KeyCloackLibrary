package org.ldang.keycloack.exception;

import org.ldang.keycloack.constans.AuthzErrorCode;
import org.ldang.keycloack.utils.KCResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.ldang.keycloack.exception.GlobalExceptionCustom.handleKeycloakValidation;


@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public KCResponse<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex) {
        List<String> errors = new java.util.ArrayList<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(err -> errors.add(err.getDefaultMessage()));
        return handleKeycloakValidation(AuthzErrorCode.VALIDATION_ERROR, errors);
    }

//    @ExceptionHandler(HttpClientErrorException.class)
//    public KCResponse<?> handleUnexpected(HttpClientErrorException ex) {
//        String errorMsg = "";
//        try {
//            String body = ex.getResponseBodyAsString();
//            if (body == null || body.isBlank()) {
//                return handleKeycloakException(AuthzErrorCode.API_ERROR, ex.getMessage());
//            }
//            Map<String, Object> errorBody = new ObjectMapper().readValue(body, Map.class);
//            if(errorMsg == null) {
//                errorMsg = errorBody.get("errorMessage").toString();
//            }
//        } catch (Exception e) {
//            errorMsg = e.getMessage();
//        }
//        return handleKeycloakException(AuthzErrorCode.API_ERROR, errorMsg);
//    }
}