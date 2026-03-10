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
        String username = requireUsername(authentication);
        User user = authService.getCurrentUser(username);
        user.setPassword(null);
        user.setMasterPassword(null);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/master-password/setup")
    public ResponseEntity<Map<String, String>> setupMasterPassword(
            Authentication authentication,
            @Valid @RequestBody MasterPasswordRequest request) {
        authService.setupMasterPassword(requireUsername(authentication), request);
        return ResponseEntity.ok(Map.of("message", "Master password set successfully"));
    }

    @PutMapping("/master-password/change")
    public ResponseEntity<Map<String, String>> changeMasterPassword(
            Authentication authentication,
            @Valid @RequestBody MasterPasswordRequest request) {
        authService.changeMasterPassword(requireUsername(authentication), request);
        return ResponseEntity.ok(Map.of("message", "Master password changed successfully"));
    }

    @PostMapping("/master-password/verify")
    public ResponseEntity<Map<String, Boolean>> verifyMasterPassword(
            Authentication authentication,
            @RequestBody Map<String, String> request) {
        boolean valid = authService.verifyMasterPassword(requireUsername(authentication), request.get("masterPassword"));
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

    @PostMapping("/password/forgot/request")
    public ResponseEntity<Map<String, String>> requestForgotPasswordCode(@RequestBody Map<String, String> request) {
        authService.requestPasswordResetCode(request.get("email"));
        return ResponseEntity.ok(Map.of("message", "Password reset code sent"));
    }

    @PostMapping("/password/forgot/reset")
    public ResponseEntity<Map<String, String>> resetForgotPassword(@RequestBody Map<String, String> request) {
        authService.resetForgotPassword(
                request.get("email"),
                request.get("verificationCode"),
                request.get("newPassword"),
                request.get("confirmPassword"));
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    @PostMapping("/master-password/forgot/request")
    public ResponseEntity<Map<String, String>> requestForgotMasterPasswordCode(@RequestBody Map<String, String> request) {
        authService.requestMasterPasswordResetCode(request.get("email"));
        return ResponseEntity.ok(Map.of("message", "Master password reset code sent"));
    }

    @PostMapping("/master-password/forgot/reset")
    public ResponseEntity<Map<String, String>> resetForgotMasterPassword(@RequestBody Map<String, String> request) {
        authService.resetForgotMasterPassword(
                request.get("email"),
                request.get("verificationCode"),
                request.get("newMasterPassword"),
                request.get("confirmMasterPassword"));
        return ResponseEntity.ok(Map.of("message", "Master password reset successful"));
    }

    @PutMapping("/2fa/status")
    public ResponseEntity<Map<String, String>> updateTwoFactorStatus(
            Authentication authentication,
            @RequestBody Map<String, Boolean> request) {
        authService.updateTwoFactorStatus(requireUsername(authentication), request.get("enabled"));
        return ResponseEntity.ok(Map.of("message", "Two-factor authentication status updated"));
    }

    private String requireUsername(Authentication authentication) {
        if (authentication == null || authentication.getName() == null || authentication.getName().isBlank()) {
            throw new com.passwordmanager.auth.exception.UnauthorizedException("Authentication required");
        }
        return authentication.getName();
    }
}
