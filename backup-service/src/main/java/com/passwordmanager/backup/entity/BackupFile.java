package com.passwordmanager.backup.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class BackupFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String fileName;

    @Lob
    @Column(nullable = false, columnDefinition = "CLOB")
    private String encryptedContent;

    @Column(nullable = false)
    private String checksum;

    private Long userId;

    private LocalDateTime createdAt;

    public BackupFile() {
    }

    public BackupFile(Long id, String fileName, String encryptedContent, String checksum, Long userId, LocalDateTime createdAt) {
        this.id = id;
        this.fileName = fileName;
        this.encryptedContent = encryptedContent;
        this.checksum = checksum;
        this.userId = userId;
        this.createdAt = createdAt;
    }

    public static BackupFileBuilder builder() {
        return new BackupFileBuilder();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getEncryptedContent() {
        return encryptedContent;
    }

    public void setEncryptedContent(String encryptedContent) {
        this.encryptedContent = encryptedContent;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public static class BackupFileBuilder {
        private Long id;
        private String fileName;
        private String encryptedContent;
        private String checksum;
        private Long userId;
        private LocalDateTime createdAt;

        BackupFileBuilder() {
        }

        public BackupFileBuilder id(Long id) {
            this.id = id;
            return this;
        }

        public BackupFileBuilder fileName(String fileName) {
            this.fileName = fileName;
            return this;
        }

        public BackupFileBuilder encryptedContent(String encryptedContent) {
            this.encryptedContent = encryptedContent;
            return this;
        }

        public BackupFileBuilder checksum(String checksum) {
            this.checksum = checksum;
            return this;
        }

        public BackupFileBuilder userId(Long userId) {
            this.userId = userId;
            return this;
        }

        public BackupFileBuilder createdAt(LocalDateTime createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public BackupFile build() {
            return new BackupFile(id, fileName, encryptedContent, checksum, userId, createdAt);
        }

        public String toString() {
            return "BackupFile.BackupFileBuilder(id=" + this.id + ", fileName=" + this.fileName + ", encryptedContent=" + this.encryptedContent + ", checksum=" + this.checksum + ", userId=" + this.userId + ", createdAt=" + this.createdAt + ")";
        }
    }
}
