import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { readAuthToken } from '../auth/token.util';

export const moduleAuthGuard: CanActivateFn = (_route, state) => {
  const router = inject(Router);
  const token = readAuthToken();
  return token
    ? true
    : router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
};
