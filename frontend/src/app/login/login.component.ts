import { Component } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  private readonly maxEmailLength = 255;
  private readonly minPasswordLength = 6;
  private readonly maxPasswordLength = 128;
  private readonly otpLength = 6;

  form = {
    email: '',
    password: '',
    otp: ''
  };

  message = '';
  error = '';

  constructor(
    private authService: AuthService,
    private router: Router,
    private route: ActivatedRoute
  ) {}

  login() {
    this.error = '';
    this.message = '';

    const email = this.form.email.trim();
    const password = this.form.password.trim();
    const otp = this.form.otp.trim();

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

    if (!password) {
      this.error = 'Password is required';
      return;
    }

    if (password.length < this.minPasswordLength) {
      this.error = `Password must be at least ${this.minPasswordLength} characters`;
      return;
    }

    if (password.length > this.maxPasswordLength) {
      this.error = `Password cannot exceed ${this.maxPasswordLength} characters`;
      return;
    }

    if (otp && !this.isValidOtp(otp)) {
      this.error = `OTP must be a ${this.otpLength}-digit code`;
      return;
    }

    this.form = { email, password, otp };

    this.authService.login({ username: email, password }).subscribe({
      next: (resp) => {
        if (resp?.requiresTwoFactor) {
          if (!otp) {
            this.error = 'OTP required. Click Request OTP, then enter the code.';
            return;
          }
          this.authService.verifyOtp({ email, code: otp }).subscribe({
            next: (verifyResp) => {
              this.authService.saveToken(verifyResp.token);
              const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl');
              this.router.navigateByUrl(returnUrl && returnUrl.startsWith('/') ? returnUrl : '/master-password');
            },
            error: (err) => {
              this.error = err?.error?.message ?? 'Invalid OTP';
            }
          });
          return;
        }

        this.authService.saveToken(resp.token);
        const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl');
        this.router.navigateByUrl(returnUrl && returnUrl.startsWith('/') ? returnUrl : '/master-password');
      },
      error: (err) => {
        this.error = err?.error?.message ?? 'Login failed';
      }
    });
  }

  requestOtp() {
    this.error = '';
    this.message = '';
    const email = this.form.email.trim();
    if (!email) {
      this.error = 'Email is required to request OTP';
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

    this.authService.requestOtp(email).subscribe({
      next: (resp) => {
        this.message = resp.message;
      },
      error: (err) => {
        this.error = err?.error?.message ?? 'Failed to request OTP';
      }
    });
  }

  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  private isValidOtp(otp: string): boolean {
    return new RegExp(`^\\d{${this.otpLength}}$`).test(otp);
  }
}
