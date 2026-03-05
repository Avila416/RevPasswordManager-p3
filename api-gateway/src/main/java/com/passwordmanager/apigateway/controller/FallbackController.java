package com.passwordmanager.apigateway.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/fallback")
public class FallbackController {

    @GetMapping("/auth")
    public ResponseEntity<Map<String, Object>> authServiceFallback() {
        return createFallbackResponse("Auth Service", "Authentication service is currently unavailable");
    }

    @GetMapping("/vault")
    public ResponseEntity<Map<String, Object>> vaultServiceFallback() {
        return createFallbackResponse("Vault Service", "Vault service is currently unavailable");
    }

    @GetMapping("/security")
    public ResponseEntity<Map<String, Object>> securityServiceFallback() {
        return createFallbackResponse("Security Service", "Security service is currently unavailable");
    }

    @GetMapping("/backup")
    public ResponseEntity<Map<String, Object>> backupServiceFallback() {
        return createFallbackResponse("Backup Service", "Backup service is currently unavailable");
    }

    private ResponseEntity<Map<String, Object>> createFallbackResponse(String service, String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("service", service);
        response.put("message", message);
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
}
