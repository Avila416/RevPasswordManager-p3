import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent {
  private readonly maxNameLength = 120;
  private readonly maxEmailLength = 255;
  private readonly minPasswordLength = 8;
  private readonly maxPasswordLength = 128;

  form = {
    name: '',
    email: '',
    password: '',
    phone: ''
  };

  message = '';
  error = '';

  constructor(private authService: AuthService, private router: Router) {}

  register() {
    this.error = '';
    this.message = '';

    const name = this.form.name.trim();
    const email = this.form.email.trim();
    const password = this.form.password.trim();
    const phone = this.form.phone.trim();

    if (!name) {
      this.error = 'Name is required';
      return;
    }

    if (name.length > this.maxNameLength) {
      this.error = `Name cannot exceed ${this.maxNameLength} characters`;
      return;
    }

    if (!email) {
      this.error = 'Email is required';
      return;
    }

    if (email.length > this.maxEmailLength) {
      this.error = `Email cannot exceed ${this.maxEmailLength} characters`;
      return;
    }

    if (!this.isValidEmail(email)) {
      this.error = 'Enter a valid email address';
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

    if (phone && !this.isValidPhone(phone)) {
      this.error = 'Phone number must be 10 digits and start with 7, 8, or 9';
      return;
    }

    this.form = { name, email, password, phone };

    this.authService.register({ username: name, email, password, phone }).subscribe({
      next: (resp) => {
        this.message = resp.message;
        this.authService.clearToken();
        this.router.navigate(['/login']);
      },
      error: (err) => {
        this.error = this.extractError(err);
      }
    });
  }

  private extractError(err: any): string {
    const payload = err?.error;
    if (typeof payload === 'string' && payload.trim()) {
      return payload.trim();
    }

    const message = payload?.message ?? payload?.error;
    if (typeof message === 'string' && message.trim()) {
      return message.trim();
    }

    const details = payload?.details;
    if (details && typeof details === 'object') {
      const firstDetail = Object.values(details)[0];
      if (typeof firstDetail === 'string' && firstDetail.trim()) {
        return firstDetail.trim();
      }
    }

    return 'Registration failed';
  }

  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  private isValidPhone(phone: string): boolean {
    return /^[789]\d{9}$/.test(phone);
  }
}

