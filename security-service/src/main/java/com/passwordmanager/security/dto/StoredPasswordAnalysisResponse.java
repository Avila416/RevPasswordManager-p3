package com.passwordmanager.security.dto;

import java.time.LocalDateTime;

public class StoredPasswordAnalysisResponse {

    private Long entryId;
    private String username;
    private String website;
    private String strength;
    private boolean weak;
    private boolean reused;
    private boolean old;
    private LocalDateTime createdAt;

    public StoredPasswordAnalysisResponse() {
    }

    public StoredPasswordAnalysisResponse(Long entryId, String username, String website, String strength,
                                          boolean weak, boolean reused, boolean old, LocalDateTime createdAt) {
        this.entryId = entryId;
        this.username = username;
        this.website = website;
        this.strength = strength;
        this.weak = weak;
        this.reused = reused;
        this.old = old;
        this.createdAt = createdAt;
    }

    public static StoredPasswordAnalysisResponseBuilder builder() {
        return new StoredPasswordAnalysisResponseBuilder();
    }

    public Long getEntryId() {
        return entryId;
    }

    public void setEntryId(Long entryId) {
        this.entryId = entryId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getWebsite() {
        return website;
    }

    public void setWebsite(String website) {
        this.website = website;
    }

    public String getStrength() {
        return strength;
    }

    public void setStrength(String strength) {
        this.strength = strength;
    }

    public boolean isWeak() {
        return weak;
    }

    public void setWeak(boolean weak) {
        this.weak = weak;
    }

    public boolean isReused() {
        return reused;
    }

    public void setReused(boolean reused) {
        this.reused = reused;
    }

    public boolean isOld() {
        return old;
    }

    public void setOld(boolean old) {
        this.old = old;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public static class StoredPasswordAnalysisResponseBuilder {
        private Long entryId;
        private String username;
        private String website;
        private String strength;
        private boolean weak;
        private boolean reused;
        private boolean old;
        private LocalDateTime createdAt;

        StoredPasswordAnalysisResponseBuilder() {
        }

        public StoredPasswordAnalysisResponseBuilder entryId(Long entryId) {
            this.entryId = entryId;
            return this;
        }

        public StoredPasswordAnalysisResponseBuilder username(String username) {
            this.username = username;
            return this;
        }

        public StoredPasswordAnalysisResponseBuilder website(String website) {
            this.website = website;
            return this;
        }

        public StoredPasswordAnalysisResponseBuilder strength(String strength) {
            this.strength = strength;
            return this;
        }

        public StoredPasswordAnalysisResponseBuilder weak(boolean weak) {
            this.weak = weak;
            return this;
        }

        public StoredPasswordAnalysisResponseBuilder reused(boolean reused) {
            this.reused = reused;
            return this;
        }

        public StoredPasswordAnalysisResponseBuilder old(boolean old) {
            this.old = old;
            return this;
        }

        public StoredPasswordAnalysisResponseBuilder createdAt(LocalDateTime createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public StoredPasswordAnalysisResponse build() {
            return new StoredPasswordAnalysisResponse(entryId, username, website, strength, weak, reused, old, createdAt);
        }
    }
}
