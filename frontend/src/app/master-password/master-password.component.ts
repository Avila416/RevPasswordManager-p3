import { Component, OnInit } from '@angular/core';
import { AuthService, UserProfile } from '../services/auth.service';

@Component({
  selector: 'app-master-password',
  templateUrl: './master-password.component.html',
  styleUrls: ['./master-password.component.css']
})
export class MasterPasswordComponent implements OnInit {
  private readonly maxEmailLength = 255;
  private readonly minPasswordLength = 8;
  private readonly maxPasswordLength = 128;
  private readonly maxVerificationCodeLength = 20;

  profile: UserProfile | null = null;
  accountError = '';
  setupMessage = '';
  setupError = '';
  changeMessage = '';
  changeError = '';
  twoFaMessage = '';
  twoFaError = '';
  forgotMessage = '';
  forgotError = '';
  showChangeConfirmModal = false;
  isChangingMasterPassword = false;
  pendingMasterPasswordChange: { oldMasterPassword: string; newMasterPassword: string } | null = null;

  setupForm = {
    masterPassword: '',
    confirmMasterPassword: ''
  };

  changeForm = {
    oldMasterPassword: '',
    newMasterPassword: '',
    confirmNewMasterPassword: ''
  };

  forgotForm = {
    email: '',
    verificationCode: '',
    newMasterPassword: '',
    confirmMasterPassword: ''
  };

  constructor(private authService: AuthService) {}

  ngOnInit(): void {
    this.loadAccount();
  }

  loadAccount() {
    this.authService.getAccount().subscribe({
      next: (resp) => {
        this.profile = resp;
        this.accountError = '';
      },
      error: (err) => {
        this.accountError = this.extractError(err, 'Failed to load account');
      }
    });
  }

  displayName(): string {
    if (!this.profile) {
      return '';
    }
    const first = this.profile.firstName?.trim() ?? '';
    const last = this.profile.lastName?.trim() ?? '';
    const full = `${first} ${last}`.trim();
    return full || this.profile.username;
  }

  setupMasterPassword() {
    this.setupError = '';
    this.setupMessage = '';

    const masterPassword = this.setupForm.masterPassword.trim();
    const confirmMasterPassword = this.setupForm.confirmMasterPassword.trim();

    if (!masterPassword || !confirmMasterPassword) {
      this.setupError = 'Master password and confirm password are required';
      return;
    }

    if (masterPassword.length < this.minPasswordLength) {
      this.setupError = `Master password must be at least ${this.minPasswordLength} characters`;
      return;
    }

    if (masterPassword.length > this.maxPasswordLength || confirmMasterPassword.length > this.maxPasswordLength) {
      this.setupError = `Master password cannot exceed ${this.maxPasswordLength} characters`;
      return;
    }

    if (masterPassword !== confirmMasterPassword) {
      this.setupError = 'Master password and confirm password must match';
      return;
    }

    this.authService.setupMasterPassword(
      masterPassword,
      confirmMasterPassword
    ).subscribe({
      next: (resp) => {
        this.setupMessage = resp.message;
      },
      error: (err) => {
        this.setupError = this.extractError(err, 'Failed to set master password');
      }
    });
  }

  changeMasterPassword() {
    this.changeError = '';
    this.changeMessage = '';
    const oldMasterPassword = this.changeForm.oldMasterPassword.trim();
    const newMasterPassword = this.changeForm.newMasterPassword.trim();
    const confirmNewMasterPassword = this.changeForm.confirmNewMasterPassword.trim();

    if (!oldMasterPassword || !newMasterPassword || !confirmNewMasterPassword) {
      this.changeError = 'All fields are required';
      return;
    }

    if (newMasterPassword.length < this.minPasswordLength) {
      this.changeError = `New master password must be at least ${this.minPasswordLength} characters`;
      return;
    }

    if (
      oldMasterPassword.length > this.maxPasswordLength ||
      newMasterPassword.length > this.maxPasswordLength ||
      confirmNewMasterPassword.length > this.maxPasswordLength
    ) {
      this.changeError = `Master password cannot exceed ${this.maxPasswordLength} characters`;
      return;
    }

    if (newMasterPassword !== confirmNewMasterPassword) {
      this.changeError = 'New master password and confirm password must match';
      return;
    }

    this.pendingMasterPasswordChange = { oldMasterPassword, newMasterPassword };
    this.showChangeConfirmModal = true;
  }

  cancelChangeMasterPassword(): void {
    this.showChangeConfirmModal = false;
    this.pendingMasterPasswordChange = null;
  }

  confirmChangeMasterPassword(): void {
    if (!this.pendingMasterPasswordChange || this.isChangingMasterPassword) {
      return;
    }

    this.isChangingMasterPassword = true;
    this.authService.changeMasterPassword(
      this.pendingMasterPasswordChange.oldMasterPassword,
      this.pendingMasterPasswordChange.newMasterPassword
    ).subscribe({
      next: (resp) => {
        this.changeMessage = resp.message;
        this.changeForm = {
          oldMasterPassword: '',
          newMasterPassword: '',
          confirmNewMasterPassword: ''
        };
        this.cancelChangeMasterPassword();
        this.isChangingMasterPassword = false;
      },
      error: (err) => {
        this.changeError = this.extractError(err, 'Failed to change master password');
        this.cancelChangeMasterPassword();
        this.isChangingMasterPassword = false;
      }
    });
  }

  set2fa(enabled: boolean) {
    this.twoFaError = '';
    this.twoFaMessage = '';
    this.authService.update2fa(enabled).subscribe({
      next: () => {
        this.twoFaMessage = `2FA ${enabled ? 'enabled' : 'disabled'}`;
        this.loadAccount();
      },
      error: (err) => {
        this.twoFaError = this.extractError(err, 'Failed to update 2FA');
      }
    });
  }

  requestForgotMasterPasswordCode() {
    this.forgotError = '';
    this.forgotMessage = '';
    const email = this.forgotForm.email.trim();

    if (!email) {
      this.forgotError = 'Email is required';
      return;
    }

    if (!this.isValidEmail(email)) {
      this.forgotError = 'Enter a valid email address';
      return;
    }

    if (email.length > this.maxEmailLength) {
      this.forgotError = `Email cannot exceed ${this.maxEmailLength} characters`;
      return;
    }

    this.authService.requestForgotMasterPasswordCode(email).subscribe({
      next: (resp) => {
        this.forgotMessage = resp.message;
      },
      error: (err) => {
        this.forgotError = this.extractError(err, 'Failed to send verification code');
      }
    });
  }

  resetForgotMasterPassword() {
    this.forgotError = '';
    this.forgotMessage = '';
    const email = this.forgotForm.email.trim();
    const verificationCode = this.forgotForm.verificationCode.trim();
    const newMasterPassword = this.forgotForm.newMasterPassword.trim();
    const confirmMasterPassword = this.forgotForm.confirmMasterPassword.trim();

    if (!email || !verificationCode || !newMasterPassword || !confirmMasterPassword) {
      this.forgotError = 'All fields are required';
      return;
    }

    if (!this.isValidEmail(email)) {
      this.forgotError = 'Enter a valid email address';
      return;
    }

    if (email.length > this.maxEmailLength) {
      this.forgotError = `Email cannot exceed ${this.maxEmailLength} characters`;
      return;
    }

    if (verificationCode.length > this.maxVerificationCodeLength) {
      this.forgotError = `Verification code cannot exceed ${this.maxVerificationCodeLength} characters`;
      return;
    }

    if (newMasterPassword.length < this.minPasswordLength) {
      this.forgotError = `New master password must be at least ${this.minPasswordLength} characters`;
      return;
    }

    if (
      newMasterPassword.length > this.maxPasswordLength ||
      confirmMasterPassword.length > this.maxPasswordLength
    ) {
      this.forgotError = `Master password cannot exceed ${this.maxPasswordLength} characters`;
      return;
    }

    if (newMasterPassword !== confirmMasterPassword) {
      this.forgotError = 'New master password and confirm master password must match';
      return;
    }

    this.authService.resetForgotMasterPassword({
      email,
      verificationCode,
      newMasterPassword,
      confirmMasterPassword
    }).subscribe({
      next: (resp) => {
        this.forgotMessage = resp.message;
        this.forgotForm = {
          email: '',
          verificationCode: '',
          newMasterPassword: '',
          confirmMasterPassword: ''
        };
      },
      error: (err) => {
        this.forgotError = this.extractError(err, 'Failed to reset master password');
      }
    });
  }

  private extractError(err: any, fallback: string): string {
    const backendMessage = err?.error?.message;
    if (backendMessage === 'Invalid authentication principal' || backendMessage === 'Authentication required') {
      return 'Session expired. Please login again.';
    }
    return backendMessage ?? fallback;
  }

  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }
}
