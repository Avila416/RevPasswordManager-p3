import { Component } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-auth-required',
  templateUrl: './auth-required.component.html',
  styleUrls: ['./auth-required.component.css']
})
export class AuthRequiredComponent {
  constructor(
    private readonly router: Router,
    private readonly route: ActivatedRoute
  ) {}

  useDemoAccess(): void {
    localStorage.setItem('pm_token', 'demo-token');
    localStorage.setItem('token', 'demo-token');
    this.router.navigateByUrl(this.getReturnUrl());
  }

  openLogin(): void {
    this.router.navigate(['/login'], { queryParams: { returnUrl: this.getReturnUrl() } });
  }

  private getReturnUrl(): string {
    const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl');
    return returnUrl && returnUrl.startsWith('/') ? returnUrl : '/generator';
  }
}
