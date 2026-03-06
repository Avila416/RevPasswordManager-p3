package com.passwordmanager.backup.util;

public final class AuditActions {

    private AuditActions() {
    }

    public static final String LOGIN_ATTEMPT = "LOGIN_ATTEMPT";
    public static final String FAILED_LOGIN_ATTEMPT = "FAILED_LOGIN_ATTEMPT";
    public static final String MASTER_PASSWORD_CHANGE = "MASTER_PASSWORD_CHANGE";
    public static final String PASSWORD_VIEW = "PASSWORD_VIEW";
    public static final String DELETE_ENTRY = "DELETE_ENTRY";
    public static final String BACKUP_EXPORT = "BACKUP_EXPORT";
    public static final String BACKUP_RESTORE = "BACKUP_RESTORE";
    public static final String BACKUP_UPDATE = "BACKUP_UPDATE";
    public static final String BACKUP_VALIDATE = "BACKUP_VALIDATE";
    public static final String BACKUP_DELETE = "BACKUP_DELETE";
}
