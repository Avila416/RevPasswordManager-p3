package com.passwordmanager.auth.controller;

import com.passwordmanager.auth.dto.UserDto;
import com.passwordmanager.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AuthService authService;

    public UserController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(authService.getUserById(id));
    }

    @GetMapping("/exists/{id}")
    public ResponseEntity<Boolean> userExists(@PathVariable Long id) {
        return ResponseEntity.ok(authService.userExists(id));
    }

    @PostMapping("/{id}/master-password/verify")
    public ResponseEntity<Map<String, Boolean>> verifyMasterPassword(
            @PathVariable Long id,
            @RequestBody Map<String, String> request) {
        boolean valid = authService.verifyMasterPasswordByUserId(id, request.get("masterPassword"));
        return ResponseEntity.ok(Map.of("valid", valid));
    }
}
