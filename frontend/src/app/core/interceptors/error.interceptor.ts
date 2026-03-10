import { Injectable } from '@angular/core';
import {
  HttpErrorResponse,
  HttpEvent,
  HttpHandler,
  HttpInterceptor,
  HttpRequest
} from '@angular/common/http';
import { Observable, catchError, throwError } from 'rxjs';
import { NotificationService } from '../services/notification.service';

@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
  constructor(private readonly notifications: NotificationService) {}

  intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    return next.handle(req).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 400) {
          this.notifications.show({ type: 'warning', text: 'Bad request. Check input values.' });
        } else if (error.status === 401) {
          this.notifications.show({ type: 'error', text: 'Unauthorized request.' });
        } else if (error.status === 404) {
          this.notifications.show({ type: 'warning', text: 'Requested data not found.' });
        } else if (error.status >= 500) {
          this.notifications.show({ type: 'error', text: 'Server error occurred.' });
        }

        return throwError(() => error);
      })
    );
  }
}
