import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-forgot-password',
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.css']
})
export class ForgotPasswordComponent {
  private readonly maxEmailLength = 255;
  private readonly minPasswordLength = 6;
  private readonly maxPasswordLength = 128;
  private readonly maxVerificationCodeLength = 20;

  form = {
    email: '',
    verificationCode: '',
    newPassword: '',
    confirmPassword: ''
  };

  message = '';
  error = '';

  constructor(private authService: AuthService, private router: Router) {}

  requestCode() {
    this.error = '';
    this.message = '';
    const email = this.form.email.trim();
    if (!email) {
      this.error = 'Email is required';
      return;
    }
    if (!this.isValidEmail(email)) {
      this.error = 'Enter a valid email address';
      return;
    }
    if (email.length > this.maxEmailLength) {
      this.error = `Email cannot exceed ${this.maxEmailLength} characters`;
      return;
    }

    this.authService.requestForgotPasswordCode(email).subscribe({
      next: (resp) => (this.message = resp.message),
      error: (err) => (this.error = err?.error?.message ?? 'Failed to request code')
    });
  }

  resetPassword() {
    this.error = '';
    this.message = '';

    const email = this.form.email.trim();
    const verificationCode = this.form.verificationCode.trim();
    const newPassword = this.form.newPassword.trim();
    const confirmPassword = this.form.confirmPassword.trim();

    if (!email) {
      this.error = 'Email is required';
      return;
    }

    if (!this.isValidEmail(email)) {
      this.error = 'Enter a valid email address';
      return;
    }

    if (email.length > this.maxEmailLength) {
      this.error = `Email cannot exceed ${this.maxEmailLength} characters`;
      return;
    }

    if (!verificationCode) {
      this.error = 'Verification code is required';
      return;
    }

    if (verificationCode.length > this.maxVerificationCodeLength) {
      this.error = `Verification code cannot exceed ${this.maxVerificationCodeLength} characters`;
      return;
    }

    if (!newPassword || !confirmPassword) {
      this.error = 'New password and confirm password are required';
      return;
    }

    if (newPassword.length < this.minPasswordLength) {
      this.error = `New password must be at least ${this.minPasswordLength} characters`;
      return;
    }

    if (newPassword.length > this.maxPasswordLength || confirmPassword.length > this.maxPasswordLength) {
      this.error = `Password cannot exceed ${this.maxPasswordLength} characters`;
      return;
    }

    if (newPassword !== confirmPassword) {
      this.error = 'New password and confirm password must match';
      return;
    }

    this.form = { email, verificationCode, newPassword, confirmPassword };

    this.authService.resetForgotPassword(this.form).subscribe({
      next: (resp) => {
        this.message = `${resp.message}. You can login now.`;
        this.router.navigate(['/login']);
      },
      error: (err) => (this.error = err?.error?.message ?? 'Failed to reset password')
    });
  }

  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }
}
