package com.passwordmanager.vault.dto;

import java.time.LocalDateTime;

public class PasswordEntryResponse {

    private Long id;
    private String title;
    private String username;
    private String password;
    private String website;
    private String category;
    private String notes;
    private boolean favorite;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public PasswordEntryResponse() {
    }

    public PasswordEntryResponse(Long id, String title, String username, String password, String website,
                                String category, String notes, boolean favorite,
                                LocalDateTime createdAt, LocalDateTime updatedAt) {
        this.id = id;
        this.title = title;
        this.username = username;
        this.password = password;
        this.website = website;
        this.category = category;
        this.notes = notes;
        this.favorite = favorite;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getWebsite() { return website; }
    public void setWebsite(String website) { this.website = website; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }
    public boolean isFavorite() { return favorite; }
    public void setFavorite(boolean favorite) { this.favorite = favorite; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    public static PasswordEntryResponseBuilder builder() {
        return new PasswordEntryResponseBuilder();
    }

    public static class PasswordEntryResponseBuilder {
        private Long id;
        private String title;
        private String username;
        private String password;
        private String website;
        private String category;
        private String notes;
        private boolean favorite;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        public PasswordEntryResponseBuilder id(Long id) { this.id = id; return this; }
        public PasswordEntryResponseBuilder title(String title) { this.title = title; return this; }
        public PasswordEntryResponseBuilder username(String username) { this.username = username; return this; }
        public PasswordEntryResponseBuilder password(String password) { this.password = password; return this; }
        public PasswordEntryResponseBuilder website(String website) { this.website = website; return this; }
        public PasswordEntryResponseBuilder category(String category) { this.category = category; return this; }
        public PasswordEntryResponseBuilder notes(String notes) { this.notes = notes; return this; }
        public PasswordEntryResponseBuilder favorite(boolean favorite) { this.favorite = favorite; return this; }
        public PasswordEntryResponseBuilder createdAt(LocalDateTime createdAt) { this.createdAt = createdAt; return this; }
        public PasswordEntryResponseBuilder updatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; return this; }

        public PasswordEntryResponse build() {
            return new PasswordEntryResponse(id, title, username, password, website, category, notes, favorite, createdAt, updatedAt);
        }
    }
}
