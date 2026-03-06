package com.passwordmanager.vault.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "password_entries")
public class PasswordEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false)
    private String title;

    private String username;

    @Column(columnDefinition = "TEXT")
    private String encryptedPassword;

    private String website;

    private String category;

    private String notes;

    private boolean favorite = false;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    public PasswordEntry() {
    }

    public PasswordEntry(Long id, Long userId, String title, String username, String encryptedPassword,
                        String website, String category, String notes, boolean favorite,
                        LocalDateTime createdAt, LocalDateTime updatedAt) {
        this.id = id;
        this.userId = userId;
        this.title = title;
        this.username = username;
        this.encryptedPassword = encryptedPassword;
        this.website = website;
        this.category = category;
        this.notes = notes;
        this.favorite = favorite;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEncryptedPassword() { return encryptedPassword; }
    public void setEncryptedPassword(String encryptedPassword) { this.encryptedPassword = encryptedPassword; }
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

    public static PasswordEntryBuilder builder() {
        return new PasswordEntryBuilder();
    }

    public static class PasswordEntryBuilder {
        private Long id;
        private Long userId;
        private String title;
        private String username;
        private String encryptedPassword;
        private String website;
        private String category;
        private String notes;
        private boolean favorite = false;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        public PasswordEntryBuilder id(Long id) { this.id = id; return this; }
        public PasswordEntryBuilder userId(Long userId) { this.userId = userId; return this; }
        public PasswordEntryBuilder title(String title) { this.title = title; return this; }
        public PasswordEntryBuilder username(String username) { this.username = username; return this; }
        public PasswordEntryBuilder encryptedPassword(String encryptedPassword) { this.encryptedPassword = encryptedPassword; return this; }
        public PasswordEntryBuilder website(String website) { this.website = website; return this; }
        public PasswordEntryBuilder category(String category) { this.category = category; return this; }
        public PasswordEntryBuilder notes(String notes) { this.notes = notes; return this; }
        public PasswordEntryBuilder favorite(boolean favorite) { this.favorite = favorite; return this; }
        public PasswordEntryBuilder createdAt(LocalDateTime createdAt) { this.createdAt = createdAt; return this; }
        public PasswordEntryBuilder updatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; return this; }

        public PasswordEntry build() {
            return new PasswordEntry(id, userId, title, username, encryptedPassword, website, category, notes, favorite, createdAt, updatedAt);
        }
    }
}
