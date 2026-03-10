import { HttpClient, HttpParams } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';

interface AuditLog {
  action: string;
  ip: string;
  status: string;
  time: string;
}

@Component({
  selector: 'app-security-audit',
  templateUrl: './security-audit.component.html',
  styleUrls: ['./security-audit.component.css']
})
export class SecurityAuditComponent implements OnInit {
  logs: AuditLog[] = [];
  filter = {
    action: '',
    status: '',
    ip: ''
  };
  error = '';

  constructor(private readonly http: HttpClient) {}

  ngOnInit(): void {
    this.fetchLogs();
  }

  fetchLogs(): void {
    let params = new HttpParams();
    if (this.filter.action.trim()) params = params.set('action', this.filter.action.trim());
    if (this.filter.status.trim()) params = params.set('status', this.filter.status.trim());
    if (this.filter.ip.trim()) params = params.set('ip', this.filter.ip.trim());

    this.http.get<AuditLog[]>('/api/audit', { params }).subscribe({
      next: (data) => {
        this.logs = data;
        this.error = '';
      },
      error: () => {
        this.error = 'Failed to load audit logs.';
      }
    });
  }

  clear(): void {
    this.filter = { action: '', status: '', ip: '' };
    this.fetchLogs();
  }
}
