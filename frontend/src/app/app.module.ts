import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

import { AppComponent } from './app.component';
import { AppRoutingModule } from './app-routing.module';

import { GeneratorComponent } from './pages/generator/generator.component';
import { AuditComponent } from './pages/audit/audit.component';
import { AuthRequiredComponent } from './pages/auth-required/auth-required.component';
import { ToastComponent } from './core/components/toast/toast.component';

import { VaultComponent } from './vault/vault.component';
import { RegisterComponent } from './register/register.component';
import { LoginComponent } from './login/login.component';
import { MasterPasswordComponent } from './master-password/master-password.component';
import { ForgotPasswordComponent } from './forgot-password/forgot-password.component';
import { ConsoleComponent } from './pages/console/console.component';

import { AuthTokenInterceptor } from './core/interceptors/auth-token.interceptor';
import { ErrorInterceptor } from './core/interceptors/error.interceptor';

@NgModule({
  declarations: [
    AppComponent,
    GeneratorComponent,
    AuditComponent,
    AuthRequiredComponent,
    ToastComponent,
    VaultComponent,
    RegisterComponent,
    LoginComponent,
    MasterPasswordComponent,
    ForgotPasswordComponent,
    ConsoleComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    FormsModule,
    ReactiveFormsModule,
    AppRoutingModule
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthTokenInterceptor, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: ErrorInterceptor, multi: true }
  ],
  bootstrap: [AppComponent]
})
export class AppModule {}
