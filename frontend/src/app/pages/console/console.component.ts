import { HttpClient, HttpErrorResponse, HttpHeaders, HttpParams } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { VaultEntry } from '../../models/vault.models';
import { VaultApiService } from '../../services/vault-api.service';
import { NotificationService } from '../../core/services/notification.service';

interface DashboardResponse {
  totalPasswords: number;
  weakPasswords: number;
  recentPasswords: number;
  actionStats?: Record<string, number>;
}

interface AuditLog {
  action: string;
  ip: string;
  status: string;
  time: string;
}

interface LatestBackupInfo {
  exists: boolean;
  fileName: string;
  filePath: string;
  createdAt: string;
}

interface BackupValidateResponse {
  message: string;
  checksum: string;
  encryptedLength: number;
  payloadLength: number;
  validatedAt: string;
}

interface BackupUpdateResponse {
  message: string;
  fileName: string;
  filePath: string;
  checksum: string;
  payloadLength: number;
  updatedAt: string;
}

interface BackupRestoreResponse {
  message: string;
  restoredEntries: number;
  restoredAt: string;
}

@Component({
  selector: 'app-console',
  templateUrl: './console.component.html',
  styleUrls: ['./console.component.css']
})
export class ConsoleComponent implements OnInit {
  private readonly apiBaseUrl = '/api';

  dashboard: DashboardResponse | null = null;
  entries: VaultEntry[] = [];
  auditLogs: AuditLog[] = [];
  revealedPasswords: Record<number, string> = {};
  selectedEntry: VaultEntry | null = null;
  masterPasswordInput = '';
  masterAction: 'view' | 'delete' | null = null;
  processingMasterAction = false;

  auditFilter = {
    action: '',
    status: '',
    ip: ''
  };

  backupContent = '';
  backupExport = '';
  showBackupContent = false;
  showTechnicalDetails = false;
  backupMasterPassword = '';
  backupValidationResult: BackupValidateResponse | null = null;
  backupUpdateResult: BackupUpdateResponse | null = null;
  latestBackupInfo: LatestBackupInfo | null = null;

  loading = false;
  message = '';
  error = '';
  lastRefreshedAt = '';

  constructor(
    private readonly http: HttpClient,
    private readonly vaultApi: VaultApiService,
    private readonly notifications: NotificationService
  ) {}

  ngOnInit(): void {
    this.refreshAll();
  }

  refreshAll(): void {
    this.auditFilter = { action: '', status: '', ip: '' };
    this.lastRefreshedAt = new Date().toLocaleTimeString();
    this.message = `Data refreshed at ${this.lastRefreshedAt}`;
    this.error = '';
    this.fetchDashboard();
    this.fetchEntries();
    this.fetchAuditLogs();
    this.fetchLatestBackupInfo();
    this.showSuccess(`Data refreshed at ${this.lastRefreshedAt}`);
  }

  fetchDashboard(): void {
    const masterPassword = this.backupMasterPassword.trim();
    const options = masterPassword
      ? { headers: new HttpHeaders({ 'X-Master-Password': masterPassword }) }
      : {};
    this.http.get<DashboardResponse>(`${this.apiBaseUrl}/dashboard`, options).subscribe({
      next: (data) => {
        this.dashboard = data;
        this.error = '';
      },
      error: () => {
        this.showError('Failed to load dashboard.');
      }
    });
  }

  fetchEntries(): void {
    this.vaultApi.getAllEntries().subscribe({
      next: (data) => {
        this.entries = data;
        this.error = '';
        const validIds = new Set(data.map((entry) => entry.id));
        Object.keys(this.revealedPasswords).forEach((id) => {
          if (!validIds.has(Number(id))) {
            delete this.revealedPasswords[Number(id)];
          }
        });
      },
      error: () => {
        this.showError('Failed to load vault entries.');
      }
    });
  }

  viewEntry(entry: VaultEntry): void {
    if (this.revealedPasswords[entry.id]) {
      delete this.revealedPasswords[entry.id];
      return;
    }
    this.openMasterPasswordModal(entry, 'view');
  }

  deleteEntry(entryId: number): void {
    const target = this.entries.find((entry) => entry.id === entryId);
    if (!target) {
      this.showWarning('Vault entry not found.');
      return;
    }
    this.openMasterPasswordModal(target, 'delete');
  }

  fetchAuditLogs(): void {
    const action = this.auditFilter.action.trim();
    const status = this.auditFilter.status.trim();
    const ip = this.auditFilter.ip.trim();

    let params = new HttpParams();
    if (action) {
      params = params.set('action', action);
    }
    if (status) {
      params = params.set('status', status);
    }
    if (ip) {
      params = params.set('ip', ip);
    }

    this.http.get<AuditLog[]>(`${this.apiBaseUrl}/audit`, { params }).subscribe({
      next: (data) => {
        this.auditLogs = data;
        this.error = '';
      },
      error: () => {
        this.showError('Failed to load audit logs.');
      }
    });
  }

  clearAuditFilters(): void {
    this.auditFilter = { action: '', status: '', ip: '' };
    this.fetchAuditLogs();
  }

  toggleBackupContent(): void {
    this.showBackupContent = !this.showBackupContent;
  }

  toggleTechnicalDetails(): void {
    this.showTechnicalDetails = !this.showTechnicalDetails;
  }

  exportBackup(): void {
    const masterPassword = this.backupMasterPassword.trim();
    if (!masterPassword) {
      this.showWarning('Master password is required to export a backup.');
      return;
    }
    this.loading = true;
    const headers = new HttpHeaders({ 'X-Master-Password': masterPassword });
    this.http.get(`${this.apiBaseUrl}/backup/export`, { responseType: 'text', headers }).subscribe({
      next: (data) => {
        this.backupExport = data;
        this.backupContent = data;
        this.loading = false;
        this.showSuccess('Backup exported.');
        this.fetchAuditLogs();
        this.fetchDashboard();
        this.fetchLatestBackupInfo();
      },
      error: (err: HttpErrorResponse) => {
        this.loading = false;
        this.showError(this.extractErrorMessage(err, 'Failed to export backup.'));
      }
    });
  }

  validateBackup(): void {
    const normalizedContent = this.normalizeBackupContent('validate');
    if (!normalizedContent) {
      return;
    }
    this.http.patch<BackupValidateResponse & { restoredEntries?: number }>(`${this.apiBaseUrl}/backup/validate`, { fileContent: normalizedContent }).subscribe({
      next: (res) => {
        this.backupValidationResult = res;
        this.backupUpdateResult = null;
        const restoredMsg = res.restoredEntries !== undefined ? ` Restored ${res.restoredEntries} entries.` : '';
        this.showSuccess(`Backup validated and restored.${restoredMsg}`);
        this.revealedPasswords = {};
        this.fetchEntries();
        this.fetchAuditLogs();
        this.fetchDashboard();
      },
      error: (err: HttpErrorResponse) => {
        this.showError(this.extractErrorMessage(err, 'Backup validation failed.'));
      }
    });
  }

  restoreBackup(): void {
    const normalizedContent = this.normalizeBackupContent('restore');
    if (!normalizedContent) {
      return;
    }
    this.http.post(`${this.apiBaseUrl}/backup/restore`, { fileContent: normalizedContent }, { responseType: 'text' }).subscribe({
      next: (res) => {
        const parsed = this.parseRestoreResponse(res);
        const restoreMessage = parsed.restoredEntries > -1
          ? `${parsed.message}. Restored entries: ${parsed.restoredEntries}.`
          : parsed.message;
        this.showSuccess(restoreMessage);
        this.revealedPasswords = {};
        this.refreshAll();
      },
      error: (err: HttpErrorResponse) => {
        this.showError(this.extractErrorMessage(err, 'Failed to restore backup.'));
      }
    });
  }

  updateBackup(): void {
    const normalizedContent = this.normalizeBackupContent('update');
    if (!normalizedContent) {
      return;
    }
    this.http.put<BackupUpdateResponse & { restoredEntries?: number }>(`${this.apiBaseUrl}/backup/update`, { fileContent: normalizedContent }).subscribe({
      next: (res) => {
        this.backupUpdateResult = res;
        this.backupValidationResult = null;
        const restoredMsg = res.restoredEntries !== undefined ? ` Restored ${res.restoredEntries} entries.` : '';
        this.showSuccess(`Backup updated and restored.${restoredMsg}`);
        this.revealedPasswords = {};
        this.fetchEntries();
        this.fetchLatestBackupInfo();
        this.fetchAuditLogs();
        this.fetchDashboard();
      },
      error: (err: HttpErrorResponse) => {
        this.showError(this.extractErrorMessage(err, 'Failed to update backup.'));
      }
    });
  }

  deleteBackup(): void {
    this.http.delete(`${this.apiBaseUrl}/backup/delete`, { responseType: 'text' }).subscribe({
      next: (res) => {
        this.showSuccess(res);
        this.backupUpdateResult = null;
        this.fetchLatestBackupInfo();
        this.fetchAuditLogs();
        this.fetchDashboard();
      },
      error: (err: HttpErrorResponse) => {
        this.showError(this.extractErrorMessage(err, 'Failed to delete backup.'));
      }
    });
  }

  fetchLatestBackupInfo(): void {
    this.http.get<LatestBackupInfo>(`${this.apiBaseUrl}/backup/latest`).subscribe({
      next: (data) => {
        this.latestBackupInfo = data;
      },
      error: () => {
        this.latestBackupInfo = null;
      }
    });
  }

  openMasterPasswordModal(entry: VaultEntry, action: 'view' | 'delete'): void {
    this.selectedEntry = entry;
    this.masterAction = action;
    this.masterPasswordInput = '';
    this.processingMasterAction = false;
    this.error = '';
  }

  closeMasterPasswordModal(): void {
    this.selectedEntry = null;
    this.masterAction = null;
    this.masterPasswordInput = '';
    this.processingMasterAction = false;
  }

  submitMasterPasswordAction(): void {
    if (!this.selectedEntry || !this.masterAction) {
      return;
    }

    const masterPassword = this.masterPasswordInput.trim();
    if (!masterPassword) {
      this.showWarning('Master password is required.');
      return;
    }

    this.processingMasterAction = true;
    if (this.masterAction === 'view') {
      this.vaultApi.verifyAndGet(this.selectedEntry.id, masterPassword).subscribe({
        next: (viewedEntry) => {
          this.revealedPasswords[viewedEntry.id] = viewedEntry.password;
          this.closeMasterPasswordModal();
          this.showSuccess('Password revealed successfully.');
          this.fetchAuditLogs();
          this.fetchDashboard();
        },
        error: () => {
          this.processingMasterAction = false;
          this.showError('Failed to view vault entry. Check master password.');
        }
      });
      return;
    }

    this.vaultApi.deleteEntry(this.selectedEntry.id, masterPassword).subscribe({
      next: () => {
        delete this.revealedPasswords[this.selectedEntry!.id];
        this.showSuccess('Vault entry deleted.');
        this.closeMasterPasswordModal();
        this.fetchEntries();
        this.fetchAuditLogs();
        this.fetchDashboard();
      },
      error: () => {
        this.processingMasterAction = false;
        this.showError('Failed to delete vault entry. Check master password.');
      }
    });
  }

  private normalizeBackupContent(action: string): string | null {
    const normalized = this.backupContent.replace(/\s+/g, '').trim();
    if (normalized) {
      this.backupContent = normalized;
      return normalized;
    }
    this.showWarning(`Paste backup content in the textarea before ${action}.`);
    return null;
  }

  private extractErrorMessage(error: HttpErrorResponse, fallback: string): string {
    if (!error) {
      return fallback;
    }

    if (typeof error.error === 'string' && error.error.trim()) {
      return error.error;
    }

    if (error.error && typeof error.error === 'object' && 'message' in error.error) {
      const message = (error.error as { message?: unknown }).message;
      if (typeof message === 'string' && message.trim()) {
        return message;
      }
    }

    if (typeof error.message === 'string' && error.message.trim()) {
      return error.message;
    }

    return fallback;
  }

  private parseRestoreResponse(raw: string): BackupRestoreResponse {
    const text = (raw ?? '').trim();
    if (!text) {
      return { message: 'Backup restored successfully', restoredEntries: -1, restoredAt: '' };
    }

    try {
      const payload = JSON.parse(text) as Partial<BackupRestoreResponse>;
      return {
        message: typeof payload.message === 'string' && payload.message.trim() ? payload.message : 'Backup restored successfully',
        restoredEntries: typeof payload.restoredEntries === 'number' ? payload.restoredEntries : -1,
        restoredAt: typeof payload.restoredAt === 'string' ? payload.restoredAt : ''
      };
    } catch {
      return {
        message: text,
        restoredEntries: -1,
        restoredAt: ''
      };
    }
  }

  private showSuccess(text: string): void {
    this.message = text;
    this.error = '';
    this.notifications.show({ type: 'success', text });
  }

  private showError(text: string): void {
    this.error = text;
    this.notifications.show({ type: 'error', text });
  }

  private showWarning(text: string): void {
    this.error = text;
    this.notifications.show({ type: 'warning', text });
  }
}
