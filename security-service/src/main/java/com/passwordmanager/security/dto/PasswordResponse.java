package com.passwordmanager.security.dto;

public class PasswordResponse {

    private String password;
    private String strength; // WEAK/MEDIUM/STRONG/VERY_STRONG

    public PasswordResponse() {
    }

    public PasswordResponse(String password, String strength) {
        this.password = password;
        this.strength = strength;
    }

    public static PasswordResponseBuilder builder() {
        return new PasswordResponseBuilder();
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getStrength() {
        return strength;
    }

    public void setStrength(String strength) {
        this.strength = strength;
    }

    public static class PasswordResponseBuilder {
        private String password;
        private String strength;

        PasswordResponseBuilder() {
        }

        public PasswordResponseBuilder password(String password) {
            this.password = password;
            return this;
        }

        public PasswordResponseBuilder strength(String strength) {
            this.strength = strength;
            return this;
        }

        public PasswordResponse build() {
            return new PasswordResponse(password, strength);
        }
    }
}
