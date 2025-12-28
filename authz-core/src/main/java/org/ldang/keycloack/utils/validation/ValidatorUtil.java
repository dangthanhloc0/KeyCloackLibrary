package org.ldang.keycloack.utils.validation;

import jakarta.validation.*;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.ArrayList;
import java.util.List;


@Component
public class ValidatorUtil {

    private static final ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
    private static final Validator validator = factory.getValidator();

    public static <T> List<String> validateFields(T dto) {
        List<String> errors = new ArrayList<>();
        if (dto == null) {
            errors.add("DTO to validate cannot be null");
            return errors;
        }

        if (dto instanceof ConstraintViolationException e) {
            for (ConstraintViolation<?> v : e.getConstraintViolations()) {
                errors.add(v.getMessage());
            }
        }

        if (dto instanceof MethodArgumentNotValidException e) {
            e.getBindingResult()
                    .getFieldErrors()
                    .forEach(err -> errors.add(err.getDefaultMessage()));
        }

        return errors;
    }
}
