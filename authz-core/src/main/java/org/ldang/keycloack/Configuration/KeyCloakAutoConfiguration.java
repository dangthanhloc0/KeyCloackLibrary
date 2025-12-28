package org.ldang.keycloack.Configuration;

import org.ldang.keycloack.service.KeyCloakService;
import org.ldang.keycloack.service.KeyCloakServiceImpl;
import org.ldang.keycloack.utils.TokenDecoder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableConfigurationProperties(KeyCloakProperties.class)
public class KeyCloakAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public KeyCloakService keyCloakService(RestTemplate restTemplate, TokenDecoder tokenDecoder, KeyCloakProperties props) {
        return new KeyCloakServiceImpl(
                props,
                restTemplate,
                tokenDecoder
        );
    }
}
