package org.ldang.keycloack.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.ldang.keycloack.Configuration.KeyCloakProperties;
import org.ldang.keycloack.constans.AuthzConstans;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.web.client.RestTemplate;

@Configuration
public class BeanConfig {

    private final KeyCloakProperties props;

    public BeanConfig(KeyCloakProperties props) {
        this.props = props;
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
    @Bean
    public JwtDecoder jwtDecoder(org.springframework.core.env.Environment env) {
        String url = props.getDomainUrl() + AuthzConstans.REALM + props.getRealmName();
        return JwtDecoders.fromOidcIssuerLocation(url);
    }

}

