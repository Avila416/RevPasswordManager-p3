package com.passwordmanager.discoveryserver;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;
import org.springframework.core.annotation.AnnotationUtils;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class DiscoveryServerApplicationTest {

    @Test
    void applicationIsMarkedAsEurekaServer() {
        assertNotNull(AnnotationUtils.findAnnotation(DiscoveryServerApplication.class, EnableEurekaServer.class));
    }
}
