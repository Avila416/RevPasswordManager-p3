import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  AlertResponse,
  AuditResponse,
  GeneratePasswordRequest,
  PasswordEntryResponse,
  PasswordResponse,
  SavePasswordRequest,
  StoredPasswordAnalysisResponse
} from '../models/generator.models';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class GeneratorApiService {
  private readonly baseUrl = `${environment.apiGatewayUrl}/api/generator`;
  private readonly vaultUrl = `${environment.apiGatewayUrl}/api/vault`;

  constructor(private readonly http: HttpClient) {}

  generatePasswords(payload: GeneratePasswordRequest): Observable<PasswordResponse[]> {
    return this.http.post<PasswordResponse[]>(`${this.baseUrl}/generate`, payload);
  }

  runAudit(masterPassword?: string): Observable<AuditResponse> {
    const options = masterPassword
      ? { headers: new HttpHeaders({ 'X-Master-Password': masterPassword }) }
      : {};
    return this.http.get<AuditResponse>(`${this.baseUrl}/audit`, options);
  }

  getAlerts(): Observable<AlertResponse[]> {
    return this.http.get<AlertResponse[]>(`${this.baseUrl}/audit/alerts`);
  }

  getPasswordAnalysis(masterPassword?: string): Observable<StoredPasswordAnalysisResponse[]> {
    const options = masterPassword
      ? { headers: new HttpHeaders({ 'X-Master-Password': masterPassword }) }
      : {};
    return this.http.get<StoredPasswordAnalysisResponse[]>(`${this.baseUrl}/audit/passwords-analysis`, options);
  }

  savePassword(payload: SavePasswordRequest): Observable<PasswordEntryResponse> {
    return this.http.post<PasswordEntryResponse>(this.vaultUrl, payload);
  }

  getVaultPasswords(): Observable<PasswordEntryResponse[]> {
    return this.http.get<PasswordEntryResponse[]>(this.vaultUrl);
  }
}
