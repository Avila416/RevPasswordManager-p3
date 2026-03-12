package com.passwordmanager.configserver;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.config.server.EnableConfigServer;
import org.springframework.core.annotation.AnnotationUtils;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ConfigServerApplicationTest {

    @Test
    void applicationIsMarkedAsConfigServer() {
        assertNotNull(AnnotationUtils.findAnnotation(ConfigServerApplication.class, EnableConfigServer.class));
    }
}
