package com.passwordmanager.vault.dto;

import jakarta.validation.constraints.NotBlank;

public class PasswordEntryRequest {

    @NotBlank(message = "Title is required")
    private String title;

    private String username;

    @NotBlank(message = "Password is required")
    private String password;

    private String website;

    private String category;

    private String notes;

    private boolean favorite;

    public PasswordEntryRequest() {
    }

    public PasswordEntryRequest(String title, String username, String password, String website,
                               String category, String notes, boolean favorite) {
        this.title = title;
        this.username = username;
        this.password = password;
        this.website = website;
        this.category = category;
        this.notes = notes;
        this.favorite = favorite;
    }

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

    public static PasswordEntryRequestBuilder builder() {
        return new PasswordEntryRequestBuilder();
    }

    public static class PasswordEntryRequestBuilder {
        private String title;
        private String username;
        private String password;
        private String website;
        private String category;
        private String notes;
        private boolean favorite;

        public PasswordEntryRequestBuilder title(String title) { this.title = title; return this; }
        public PasswordEntryRequestBuilder username(String username) { this.username = username; return this; }
        public PasswordEntryRequestBuilder password(String password) { this.password = password; return this; }
        public PasswordEntryRequestBuilder website(String website) { this.website = website; return this; }
        public PasswordEntryRequestBuilder category(String category) { this.category = category; return this; }
        public PasswordEntryRequestBuilder notes(String notes) { this.notes = notes; return this; }
        public PasswordEntryRequestBuilder favorite(boolean favorite) { this.favorite = favorite; return this; }

        public PasswordEntryRequest build() {
            return new PasswordEntryRequest(title, username, password, website, category, notes, favorite);
        }
    }
}
