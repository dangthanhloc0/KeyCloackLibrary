package org.ldang.keycloack.helper;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class KCError<T> {
    private String code;
    private T message;
    private int httpStatus;
}
