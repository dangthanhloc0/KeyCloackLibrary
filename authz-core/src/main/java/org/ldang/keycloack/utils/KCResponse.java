package org.ldang.keycloack.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.common.util.StringUtils;
import lombok.Data;
import org.ldang.keycloack.constans.AuthzErrorCode;
import org.ldang.keycloack.helper.KCError;

import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class KCResponse<T> {

    private boolean success;
    private T data;
    private KCError<T> error;

    public static <T> KCResponse<T> success(T data) {
        KCResponse<T> resp  = new KCResponse<>();
        resp.success = true;
        resp.data = data;
        return resp;
    }

    public static <T> KCResponse<T> error(AuthzErrorCode authzErrorCode, List<String> extraInformation) {
        T message = (T) "";
        if (extraInformation.isEmpty() || extraInformation.size() == 1 && StringUtils.isBlank(extraInformation.get(0))
        ) {
            message = (T) authzErrorCode.getDefaultMessage();
        } else if(extraInformation.size() == 1 && StringUtils.isNotBlank(extraInformation.get(0))) {
            message = (T) (authzErrorCode.getDefaultMessage() + (": "+ extraInformation.get(0).trim()));
        } else if (extraInformation.size() > 1){
            ObjectMapper mapper = new ObjectMapper();
            JsonNode node = mapper.valueToTree(extraInformation);
            message = (T) node;
        } else {
            message = (T) "Unknow error. Please review your input: some required fields are empty or incorrectly formatted.";
        }
        KCError<T> error = new KCError<T>(authzErrorCode.getCode(), message,authzErrorCode.getHttpStatus().value());
        KCResponse<T> resp = new KCResponse<>();
        resp.success = false;
        resp.error = error;
        return resp;
    }

}

