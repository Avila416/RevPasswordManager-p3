package com.passwordmanager.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class MasterPasswordRequest {

    @NotBlank(message = "Master password is required")
    @Size(min = 8, message = "Master password must be at least 8 characters")
    private String masterPassword;

    private String currentMasterPassword;

    public MasterPasswordRequest() {
    }

    public MasterPasswordRequest(String masterPassword, String currentMasterPassword) {
        this.masterPassword = masterPassword;
        this.currentMasterPassword = currentMasterPassword;
    }

    public String getMasterPassword() {
        return masterPassword;
    }

    public void setMasterPassword(String masterPassword) {
        this.masterPassword = masterPassword;
    }

    public String getCurrentMasterPassword() {
        return currentMasterPassword;
    }

    public void setCurrentMasterPassword(String currentMasterPassword) {
        this.currentMasterPassword = currentMasterPassword;
    }

    public static MasterPasswordRequestBuilder builder() {
        return new MasterPasswordRequestBuilder();
    }

    public static class MasterPasswordRequestBuilder {
        private String masterPassword;
        private String currentMasterPassword;

        public MasterPasswordRequestBuilder masterPassword(String masterPassword) {
            this.masterPassword = masterPassword;
            return this;
        }

        public MasterPasswordRequestBuilder currentMasterPassword(String currentMasterPassword) {
            this.currentMasterPassword = currentMasterPassword;
            return this;
        }

        public MasterPasswordRequest build() {
            return new MasterPasswordRequest(masterPassword, currentMasterPassword);
        }
    }
}
