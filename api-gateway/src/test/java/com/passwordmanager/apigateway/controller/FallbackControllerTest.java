package com.passwordmanager.apigateway.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.reactive.server.WebTestClient;

class FallbackControllerTest {

    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() {
        webTestClient = WebTestClient.bindToController(new FallbackController()).build();
    }

    @Test
    void backupFallbackReturnsUnavailablePayload() {
        webTestClient.get()
                .uri("/fallback/backup")
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody()
                .jsonPath("$.success").isEqualTo(false)
                .jsonPath("$.service").isEqualTo("Backup Service")
                .jsonPath("$.message").isEqualTo("Backup service is currently unavailable");
    }

    @Test
    void authFallbackReturnsUnavailablePayload() {
        webTestClient.get()
                .uri("/fallback/auth")
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody()
                .jsonPath("$.success").isEqualTo(false)
                .jsonPath("$.service").isEqualTo("Auth Service")
                .jsonPath("$.message").isEqualTo("Authentication service is currently unavailable")
                .jsonPath("$.timestamp").exists();
    }

    @Test
    void vaultFallbackReturnsUnavailablePayload() {
        webTestClient.get()
                .uri("/fallback/vault")
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody()
                .jsonPath("$.service").isEqualTo("Vault Service")
                .jsonPath("$.message").isEqualTo("Vault service is currently unavailable");
    }
}
