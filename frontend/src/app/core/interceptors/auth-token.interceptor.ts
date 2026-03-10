import { Injectable } from '@angular/core';
import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';
import { readAuthToken } from '../auth/token.util';

@Injectable()
export class AuthTokenInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    const token = readAuthToken();
    const isApiRequest = req.url.startsWith('/api/') || req.url.includes('/api/');

    if (!token || !isApiRequest) {
      return next.handle(req);
    }

    const userId = this.extractUserId(token);
    return next.handle(
      req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
          ...(userId ? { 'X-User-Id': String(userId) } : {})
        }
      })
    );
  }

  private extractUserId(token: string): number | null {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    try {
      const payload = JSON.parse(this.decodeBase64Url(parts[1]));
      const userId = payload?.userId;
      return typeof userId === 'number' ? userId : Number.isFinite(Number(userId)) ? Number(userId) : null;
    } catch {
      return null;
    }
  }

  private decodeBase64Url(input: string): string {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    return atob(padded);
  }
}
