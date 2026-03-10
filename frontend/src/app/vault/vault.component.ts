import { Component, OnInit } from '@angular/core';
import { FormBuilder, Validators } from '@angular/forms';
import { HttpErrorResponse } from '@angular/common/http';
import { Category, SearchPayload, VaultEntry, VaultEntryPayload } from '../models/vault.models';
import { VaultApiService } from '../services/vault-api.service';
import { NotificationService } from '../core/services/notification.service';

@Component({
  selector: 'app-vault',
  templateUrl: './vault.component.html',
  styleUrls: ['./vault.component.css']
})
export class VaultComponent implements OnInit {
  categories: Category[] = ['SOCIAL', 'BANKING', 'WORK', 'SHOPPING', 'OTHER'];
  entries: VaultEntry[] = [];
  favorites: VaultEntry[] = [];

  viewMode: 'grid' | 'list' = 'grid';
  activeTab: 'all' | 'favorites' = 'all';
  loading = false;
  error = '';
  success = '';

  editingId: number | null = null;
  editingEntry: VaultEntry | null = null;
  showEditModal = false;
  selectedEntry: VaultEntry | null = null;
  deleteEntryTarget: VaultEntry | null = null;
  verifyMasterPassword = '';
  revealedPassword = '';
  deleteMasterPassword = '';

  entryForm = this.fb.group({
    title: [''],
    username: ['', Validators.required],
    password: [''],
    website: [''],
    category: ['OTHER']
  });

  editForm = this.fb.group({
    title: [''],
    username: ['', Validators.required],
    password: [''],
    website: [''],
    category: ['OTHER']
  });

  searchForm = this.fb.group({
    keyword: [''],
    category: [''],
    sortBy: ['title'],
    direction: ['asc']
  });

  constructor(
    private fb: FormBuilder,
    private api: VaultApiService,
    private notifications: NotificationService
  ) {}

  ngOnInit(): void {
    this.loadAllEntries();
    this.loadFavorites();
  }

  loadAllEntries(): void {
    this.loading = true;
    this.api.getAllEntries().subscribe({
      next: (data) => {
        this.entries = data;
        this.loading = false;
      },
      error: (err) => {
        this.showError(this.extractErrorMessage(err, 'Failed to load entries'));
        this.loading = false;
      }
    });
  }

  loadFavorites(): void {
    this.api.getFavorites().subscribe({
      next: (data) => (this.favorites = data),
      error: (err) => this.showError(this.extractErrorMessage(err, 'Failed to load favorites'))
    });
  }

  saveEntry(): void {
    this.error = '';
    this.success = '';

    if (this.entryForm.invalid) {
      this.entryForm.markAllAsTouched();
      this.showWarning('Fill required fields before saving');
      return;
    }

    const payload: VaultEntryPayload = {
      title: this.entryForm.value.title || '',
      username: this.entryForm.value.username || '',
      website: this.entryForm.value.website || '',
      category: (this.entryForm.value.category as Category) || 'OTHER'
    };

    const rawPassword = this.entryForm.value.password || '';
    if (rawPassword) {
      payload.password = rawPassword;
    }

    if (!rawPassword) {
      this.showWarning('Password is required for new entry');
      return;
    }

    this.api.addEntry(payload).subscribe({
      next: () => {
        this.showSuccess('Entry added');
        this.resetForm();
        this.loadAllEntries();
        this.loadFavorites();
      },
      error: (err) => {
        this.showError(this.extractErrorMessage(err, 'Failed to save entry'));
      }
    });
  }

  editEntry(entry: VaultEntry): void {
    this.editingId = entry.id;
    this.editingEntry = entry;
    this.editForm.patchValue({
      title: entry.title,
      username: entry.username,
      website: entry.website,
      category: entry.category,
      password: ''
    });
    this.success = '';
    this.error = '';
    this.showEditModal = true;
  }

  resetForm(): void {
    this.entryForm.reset({ category: 'OTHER' });
  }

  closeEditModal(): void {
    this.showEditModal = false;
    this.editingId = null;
    this.editingEntry = null;
    this.editForm.reset({ category: 'OTHER' });
  }

  saveEditEntry(): void {
    if (!this.editingEntry || this.editingId === null) {
      return;
    }

    this.error = '';
    this.success = '';

    if (this.editForm.invalid) {
      this.editForm.markAllAsTouched();
      this.showWarning('Fill required fields before updating');
      return;
    }

    const payload: VaultEntryPayload = {
      title: this.editForm.value.title || '',
      username: this.editForm.value.username || '',
      website: this.editForm.value.website || '',
      category: (this.editForm.value.category as Category) || 'OTHER'
    };

    const rawPassword = this.editForm.value.password || '';
    if (rawPassword) {
      payload.password = rawPassword;
    }

    this.api.updateEntry(this.editingId, payload).subscribe({
      next: () => {
        this.showSuccess('Entry updated');
        this.closeEditModal();
        this.loadAllEntries();
        this.loadFavorites();
      },
      error: (err) => {
        this.showError(this.extractErrorMessage(err, 'Failed to update entry'));
      }
    });
  }

  markFavorite(entry: VaultEntry): void {
    if (entry.favorite) {
      this.showWarning('Entry is already in favorites');
      return;
    }

    this.api.markFavorite(entry.id).subscribe({
      next: () => {
        this.showSuccess('Entry added to favorites');
        this.loadAllEntries();
        this.loadFavorites();
      },
      error: (err) => this.showError(this.extractErrorMessage(err, 'Failed to mark favorite'))
    });
  }

  openDeleteModal(entry: VaultEntry): void {
    this.deleteEntryTarget = entry;
    this.deleteMasterPassword = '';
  }

  closeDeleteModal(): void {
    this.deleteEntryTarget = null;
    this.deleteMasterPassword = '';
  }

  authorizeDelete(): void {
    if (!this.deleteEntryTarget) {
      return;
    }

    const masterPassword = this.deleteMasterPassword.trim();
    if (!masterPassword) {
      this.showWarning('Enter master password');
      return;
    }

    this.api.deleteEntry(this.deleteEntryTarget.id, masterPassword).subscribe({
      next: () => {
        this.showSuccess('Entry deleted');
        this.closeDeleteModal();
        this.loadAllEntries();
        this.loadFavorites();
      },
      error: (err) => {
        this.showError(this.extractErrorMessage(err, 'Failed to delete entry'));
      }
    });
  }

  search(): void {
    const payload: SearchPayload = {
      keyword: this.searchForm.value.keyword || undefined,
      category: (this.searchForm.value.category as Category) || undefined,
      sortBy: this.searchForm.value.sortBy || undefined
    };

    const direction = this.searchForm.value.direction || 'asc';

    this.api.searchEntries(payload, payload.sortBy, direction).subscribe({
      next: (data) => {
        this.entries = data;
        this.activeTab = 'all';
        this.showSuccess('Search applied');
      },
      error: (err) => this.showError(this.extractErrorMessage(err, 'Search failed'))
    });
  }

  clearSearch(): void {
    this.searchForm.reset({ sortBy: 'title', direction: 'asc' });
    this.loadAllEntries();
    this.showSuccess('Search reset');
  }

  openVerify(entry: VaultEntry): void {
    this.selectedEntry = entry;
    this.verifyMasterPassword = '';
    this.revealedPassword = '';
  }

  closeVerify(): void {
    this.selectedEntry = null;
    this.verifyMasterPassword = '';
    this.revealedPassword = '';
  }

  verifyAndReveal(): void {
    const masterPassword = this.verifyMasterPassword.trim();
    if (!this.selectedEntry || !masterPassword) {
      this.showWarning('Enter master password');
      return;
    }

    this.error = '';
    this.api.verifyAndGet(this.selectedEntry.id, masterPassword).subscribe({
      next: (entry) => {
        this.revealedPassword = entry.password;
        this.showSuccess('Password verified and revealed');
      },
      error: (err) => {
        this.showError(this.extractErrorMessage(err, 'Verification failed'));
      }
    });
  }

  maskPassword(password: string): string {
    if (!password) {
      return '';
    }
    return '*'.repeat(Math.max(8, password.length));
  }

  private extractErrorMessage(error: unknown, fallback: string): string {
    const err = error as HttpErrorResponse | undefined;
    if (!err) {
      return fallback;
    }

    if (err.status === 0) {
      return 'Cannot connect to backend. Start the API Gateway on localhost:8080.';
    }

    if (typeof err.error === 'string' && err.error.trim()) {
      return err.error;
    }

    if (err.error && typeof err.error === 'object' && 'message' in err.error) {
      const message = (err.error as { message?: unknown }).message;
      if (typeof message === 'string' && message.trim()) {
        return message;
      }
    }

    if (err.status === 401 || err.status === 403) {
      return 'Unauthorized request. Please login again.';
    }

    if (typeof err.message === 'string' && err.message.trim()) {
      return err.message;
    }

    return fallback;
  }

  private showSuccess(message: string): void {
    this.success = message;
    this.error = '';
    this.notifications.show({ type: 'success', text: message });
  }

  private showError(message: string): void {
    this.error = message;
    this.success = '';
    this.notifications.show({ type: 'error', text: message });
  }

  private showWarning(message: string): void {
    this.error = message;
    this.success = '';
    this.notifications.show({ type: 'warning', text: message });
  }
}
