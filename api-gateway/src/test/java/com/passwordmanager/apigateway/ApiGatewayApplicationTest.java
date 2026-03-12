package com.passwordmanager.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.core.annotation.AnnotationUtils;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ApiGatewayApplicationTest {

    @Test
    void applicationIsMarkedAsDiscoveryClient() {
        assertNotNull(AnnotationUtils.findAnnotation(ApiGatewayApplication.class, EnableDiscoveryClient.class));
    }
}
