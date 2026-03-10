import { Component, OnInit } from '@angular/core';
import { GeneratorApiService } from '../../core/services/generator-api.service';
import { NotificationService } from '../../core/services/notification.service';
import { catchError, finalize, of } from 'rxjs';
import {
  AlertResponse,
  AuditResponse,
  StoredPasswordAnalysisResponse
} from '../../core/models/generator.models';

@Component({
  selector: 'app-audit',
  templateUrl: './audit.component.html',
  styleUrls: ['./audit.component.css']
})
export class AuditComponent implements OnInit {
  audit: AuditResponse | null = null;
  alerts: AlertResponse[] = [];
  analysis: StoredPasswordAnalysisResponse[] = [];
  loading = false;
  alertBanner = '';
  masterPasswordInput = '';

  constructor(
    private readonly api: GeneratorApiService,
    private readonly notifications: NotificationService
  ) {}

  ngOnInit(): void {
    this.alertBanner = 'Click "Run Audit Again" to generate a fresh audit report.';
    this.loadAlertsAndAnalysis();
  }

  refreshAll(): void {
    const masterPassword = this.masterPasswordInput.trim();
    if (!masterPassword) {
      this.notifications.show({ type: 'warning', text: 'Enter master password to run the audit.' });
      this.alertBanner = 'Enter master password to run a fresh audit report.';
      this.loadAlertsAndAnalysis();
      return;
    }

    this.loading = true;
    this.api.runAudit(masterPassword)
      .pipe(
        catchError(() => {
          this.notifications.show({ type: 'error', text: 'Audit run failed. Showing latest available data.' });
          this.alertBanner = 'Audit service is unavailable right now.';
          return of(null);
        }),
        finalize(() => {
          this.loadAlertsAndAnalysis();
        })
      )
      .subscribe({
        next: (audit) => {
          if (!audit) {
            return;
          }
          this.audit = audit;
          this.alertBanner = audit.alertCount > 0
            ? `${audit.alertCount} security alert(s) detected in this audit run.`
            : 'No new security alerts were created in this run.';
        }
      });
  }

  riskTags(item: StoredPasswordAnalysisResponse): string[] {
    const tags: string[] = [];
    if (item.weak) {
      tags.push('Weak');
    }
    if (item.reused) {
      tags.push('Reused');
    }
    if (item.old) {
      tags.push('Old');
    }
    if (tags.length === 0) {
      tags.push('Safe');
    }
    return tags;
  }

  private loadAlertsAndAnalysis(): void {
    const masterPassword = this.masterPasswordInput.trim();
    this.api.getAlerts()
      .pipe(
        catchError(() => {
          this.notifications.show({ type: 'warning', text: 'Could not load alerts.' });
          return of([] as AlertResponse[]);
        })
      )
      .subscribe({
        next: (alerts) => {
          this.alerts = alerts;
        }
      });

    if (!masterPassword) {
      this.analysis = [];
      return;
    }

    this.api.getPasswordAnalysis(masterPassword)
      .pipe(
        catchError(() => {
          this.notifications.show({ type: 'warning', text: 'Could not load password analysis.' });
          return of([] as StoredPasswordAnalysisResponse[]);
        }),
        finalize(() => {
          this.loading = false;
        })
      )
      .subscribe({
        next: (analysis) => {
          this.analysis = analysis;
        }
      });
  }
}
