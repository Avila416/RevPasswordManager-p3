package com.passwordmanager.security.service;

import org.springframework.stereotype.Service;

@Service
public class PasswordStrengthService {

    public String checkStrength(String password) {
        if (password == null || password.isBlank()) {
            return "WEAK";
        }

        int score = 0;

        if (password.length() >= 8) {
            score++;
        }
        if (password.length() >= 12) {
            score++;
        }
        if (password.matches(".*[A-Z].*")) {
            score++;
        }
        if (password.matches(".*[a-z].*")) {
            score++;
        }
        if (password.matches(".*[0-9].*")) {
            score++;
        }
        if (password.matches(".*[^A-Za-z0-9].*")) {
            score++;
        }

        if (score <= 2) {
            return "WEAK";
        }
        if (score <= 4) {
            return "MEDIUM";
        }
        if (score == 5) {
            return "STRONG";
        }
        return "VERY_STRONG";
    }
}
