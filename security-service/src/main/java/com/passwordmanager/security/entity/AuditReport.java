package com.passwordmanager.security.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class AuditReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private int totalPasswords;
    private int weakPasswords;
    private int reusedPasswords;
    private int oldPasswords;

    private LocalDateTime generatedAt;

    public AuditReport() {
    }

    public AuditReport(Long id, int totalPasswords, int weakPasswords, int reusedPasswords, int oldPasswords, LocalDateTime generatedAt) {
        this.id = id;
        this.totalPasswords = totalPasswords;
        this.weakPasswords = weakPasswords;
        this.reusedPasswords = reusedPasswords;
        this.oldPasswords = oldPasswords;
        this.generatedAt = generatedAt;
    }

    public static AuditReportBuilder builder() {
        return new AuditReportBuilder();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public int getTotalPasswords() {
        return totalPasswords;
    }

    public void setTotalPasswords(int totalPasswords) {
        this.totalPasswords = totalPasswords;
    }

    public int getWeakPasswords() {
        return weakPasswords;
    }

    public void setWeakPasswords(int weakPasswords) {
        this.weakPasswords = weakPasswords;
    }

    public int getReusedPasswords() {
        return reusedPasswords;
    }

    public void setReusedPasswords(int reusedPasswords) {
        this.reusedPasswords = reusedPasswords;
    }

    public int getOldPasswords() {
        return oldPasswords;
    }

    public void setOldPasswords(int oldPasswords) {
        this.oldPasswords = oldPasswords;
    }

    public LocalDateTime getGeneratedAt() {
        return generatedAt;
    }

    public void setGeneratedAt(LocalDateTime generatedAt) {
        this.generatedAt = generatedAt;
    }

    public static class AuditReportBuilder {
        private Long id;
        private int totalPasswords;
        private int weakPasswords;
        private int reusedPasswords;
        private int oldPasswords;
        private LocalDateTime generatedAt;

        AuditReportBuilder() {
        }

        public AuditReportBuilder id(Long id) {
            this.id = id;
            return this;
        }

        public AuditReportBuilder totalPasswords(int totalPasswords) {
            this.totalPasswords = totalPasswords;
            return this;
        }

        public AuditReportBuilder weakPasswords(int weakPasswords) {
            this.weakPasswords = weakPasswords;
            return this;
        }

        public AuditReportBuilder reusedPasswords(int reusedPasswords) {
            this.reusedPasswords = reusedPasswords;
            return this;
        }

        public AuditReportBuilder oldPasswords(int oldPasswords) {
            this.oldPasswords = oldPasswords;
            return this;
        }

        public AuditReportBuilder generatedAt(LocalDateTime generatedAt) {
            this.generatedAt = generatedAt;
            return this;
        }

        public AuditReport build() {
            return new AuditReport(id, totalPasswords, weakPasswords, reusedPasswords, oldPasswords, generatedAt);
        }
    }
}
