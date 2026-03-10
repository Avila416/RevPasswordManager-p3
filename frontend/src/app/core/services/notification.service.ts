import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface ToastMessage {
  text: string;
  type: 'success' | 'warning' | 'error' | 'info';
}

@Injectable({
  providedIn: 'root'
})
export class NotificationService {
  private readonly messageSubject = new BehaviorSubject<ToastMessage | null>(null);
  readonly message$ = this.messageSubject.asObservable();

  show(message: ToastMessage): void {
    this.messageSubject.next(message);
    setTimeout(() => this.clear(), 3000);
  }

  clear(): void {
    this.messageSubject.next(null);
  }
}
