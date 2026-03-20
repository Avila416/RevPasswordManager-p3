import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface AuthResponse {
  token: string;
  message: string;
  requiresTwoFactor?: boolean;
}

export interface UserProfile {
  id: number;
  username: string;
  firstName?: string | null;
  lastName?: string | null;
  email: string;
  twoFactorEnabled: boolean;
  phone: string | null;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly baseUrl = `${environment.apiGatewayUrl}/api/auth`;
  private readonly tokenKey = 'pm_token';
  private readonly legacyTokenKey = 'token';

  constructor(private http: HttpClient) {}

  register(payload: {
    username: string;
    email: string;
    password: string;
    phone: string;
  }): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.baseUrl}/register`, payload);
  }

  login(payload: { username: string; password: string }): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.baseUrl}/login`, payload);
  }

  requestOtp(email: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.baseUrl}/2fa/request`, { email });
  }

  verifyOtp(payload: { email: string; code: string }): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.baseUrl}/2fa/verify`, payload);
  }

  requestForgotPasswordCode(email: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.baseUrl}/password/forgot/request`, { email });
  }

  resetForgotPassword(payload: {
    email: string;
    verificationCode: string;
    newPassword: string;
    confirmPassword: string;
  }): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.baseUrl}/password/forgot/reset`, payload);
  }

  requestForgotMasterPasswordCode(email: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.baseUrl}/master-password/forgot/request`, { email });
  }

  resetForgotMasterPassword(payload: {
    email: string;
    verificationCode: string;
    newMasterPassword: string;
    confirmMasterPassword: string;
  }): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.baseUrl}/master-password/forgot/reset`, payload);
  }

  logout(): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(
      `${this.baseUrl}/logout`,
      {},
      { headers: this.authHeaders() }
    );
  }

  getAccount(): Observable<UserProfile> {
    return this.http.get<UserProfile>(`${this.baseUrl}/account`, { headers: this.authHeaders() });
  }

  setupMasterPassword(masterPassword: string, confirmMasterPassword: string) {
    return this.http.post<{ message: string }>(
      `${this.baseUrl}/master-password/setup`,
      { masterPassword },
      { headers: this.authHeaders() }
    );
  }

  changeMasterPassword(oldMasterPassword: string, newMasterPassword: string) {
    return this.http.put<{ message: string }>(
      `${this.baseUrl}/master-password/change`,
      { currentMasterPassword: oldMasterPassword, masterPassword: newMasterPassword },
      { headers: this.authHeaders() }
    );
  }

  update2fa(enabled: boolean) {
    return this.http.put<{ enabled: boolean }>(
      `${this.baseUrl}/2fa/status`,
      { enabled },
      { headers: this.authHeaders() }
    );
  }

  saveToken(token: string) {
    // Keep both keys for cross-module compatibility.
    localStorage.setItem(this.tokenKey, token);
    localStorage.setItem(this.legacyTokenKey, token);
  }

  clearToken() {
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.legacyTokenKey);
  }

  getToken(): string | null {
    const token = localStorage.getItem(this.tokenKey);
    if (token) {
      return token;
    }

    const legacyToken = localStorage.getItem(this.legacyTokenKey);
    if (legacyToken) {
      // Self-heal old sessions that used `token`.
      localStorage.setItem(this.tokenKey, legacyToken);
      return legacyToken;
    }

    return null;
  }

  isAuthenticated(): boolean {
    return !!this.getToken();
  }

  authHeaders(): HttpHeaders {
    return new HttpHeaders({
      Authorization: `Bearer ${this.getToken() ?? ''}`,
      'Content-Type': 'application/json'
    });
  }

  getUserIdFromToken(): number | null {
    const token = this.getToken();
    if (!token) {
      return null;
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    try {
      const payload = JSON.parse(atob(parts[1]));
      const userId = payload?.userId;
      return typeof userId === 'number' ? userId : Number.isFinite(Number(userId)) ? Number(userId) : null;
    } catch {
      return null;
    }
  }
}
