package com.passwordmanager.auth.dto;

import jakarta.validation.constraints.NotBlank;

public class TwoFactorRequest {

    @NotBlank(message = "Email is required")
    private String email;

    private String code;

    public TwoFactorRequest() {
    }

    public TwoFactorRequest(String email, String code) {
        this.email = email;
        this.code = code;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public static TwoFactorRequestBuilder builder() {
        return new TwoFactorRequestBuilder();
    }

    public static class TwoFactorRequestBuilder {
        private String email;
        private String code;

        public TwoFactorRequestBuilder email(String email) {
            this.email = email;
            return this;
        }

        public TwoFactorRequestBuilder code(String code) {
            this.code = code;
            return this;
        }

        public TwoFactorRequest build() {
            return new TwoFactorRequest(email, code);
        }
    }
}
