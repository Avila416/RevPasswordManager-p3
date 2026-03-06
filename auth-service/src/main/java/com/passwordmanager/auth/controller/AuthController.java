package com.passwordmanager.auth.controller;

import com.passwordmanager.auth.dto.*;
import com.passwordmanager.auth.entity.User;
import com.passwordmanager.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout() {
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @GetMapping("/account")
    public ResponseEntity<User> getAccount(Authentication authentication) {
        User user = authService.getCurrentUser(authentication.getName());
        user.setPassword(null);
        user.setMasterPassword(null);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/master-password/setup")
    public ResponseEntity<Map<String, String>> setupMasterPassword(
            Authentication authentication,
            @Valid @RequestBody MasterPasswordRequest request) {
        authService.setupMasterPassword(authentication.getName(), request);
        return ResponseEntity.ok(Map.of("message", "Master password set successfully"));
    }

    @PutMapping("/master-password/change")
    public ResponseEntity<Map<String, String>> changeMasterPassword(
            Authentication authentication,
            @Valid @RequestBody MasterPasswordRequest request) {
        authService.changeMasterPassword(authentication.getName(), request);
        return ResponseEntity.ok(Map.of("message", "Master password changed successfully"));
    }

    @PostMapping("/master-password/verify")
    public ResponseEntity<Map<String, Boolean>> verifyMasterPassword(
            Authentication authentication,
            @RequestBody Map<String, String> request) {
        boolean valid = authService.verifyMasterPassword(authentication.getName(), request.get("masterPassword"));
        return ResponseEntity.ok(Map.of("valid", valid));
    }

    @PostMapping("/2fa/request")
    public ResponseEntity<Map<String, String>> requestTwoFactorCode(@RequestBody TwoFactorRequest request) {
        authService.requestTwoFactorCode(request.getEmail());
        return ResponseEntity.ok(Map.of("message", "Verification code sent"));
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<AuthResponse> verifyTwoFactorCode(@Valid @RequestBody TwoFactorRequest request) {
        return ResponseEntity.ok(authService.verifyTwoFactorCode(request));
    }

    @PutMapping("/2fa/status")
    public ResponseEntity<Map<String, String>> updateTwoFactorStatus(
            Authentication authentication,
            @RequestBody Map<String, Boolean> request) {
        authService.updateTwoFactorStatus(authentication.getName(), request.get("enabled"));
        return ResponseEntity.ok(Map.of("message", "Two-factor authentication status updated"));
    }
}
