package org.ldang.keycloack.helper;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

public class CommonHelpers {
    public static HttpHeaders createAdminHeaders(String adminToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    public static HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

}
