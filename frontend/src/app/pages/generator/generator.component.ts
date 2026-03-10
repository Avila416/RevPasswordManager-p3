import { Component } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { GeneratorApiService } from '../../core/services/generator-api.service';
import { NotificationService } from '../../core/services/notification.service';
import { PasswordResponse, SavePasswordRequest } from '../../core/models/generator.models';

type GeneratorForm = FormGroup<{
  length: FormControl<number | null>;
  count: FormControl<number | null>;
  uppercase: FormControl<boolean | null>;
  lowercase: FormControl<boolean | null>;
  numbers: FormControl<boolean | null>;
  specialChars: FormControl<boolean | null>;
  excludeSimilar: FormControl<boolean | null>;
}>;

type SaveToVaultForm = FormGroup<{
  title: FormControl<string | null>;
  username: FormControl<string | null>;
  website: FormControl<string | null>;
  category: FormControl<'SOCIAL' | 'BANKING' | 'WORK' | 'SHOPPING' | 'OTHER' | null>;
}>;

@Component({
  selector: 'app-generator',
  templateUrl: './generator.component.html',
  styleUrls: ['./generator.component.css']
})
export class GeneratorComponent {
  generatedPasswords: PasswordResponse[] = [];
  isGenerating = false;
  isSaving = false;
  showSaveDialog = false;
  passwordToSave = '';
  readonly categories: Array<'SOCIAL' | 'BANKING' | 'WORK' | 'SHOPPING' | 'OTHER'> = [
    'SOCIAL',
    'BANKING',
    'WORK',
    'SHOPPING',
    'OTHER'
  ];

  readonly form: GeneratorForm;
  readonly saveForm: SaveToVaultForm;

  constructor(
    private readonly fb: FormBuilder,
    private readonly api: GeneratorApiService,
    private readonly notifications: NotificationService
  ) {
    this.form = this.fb.group({
      length: [null, [Validators.required, Validators.min(8), Validators.max(64)]],
      count: [null, [Validators.required, Validators.min(1), Validators.max(20)]],
      uppercase: [false],
      lowercase: [false],
      numbers: [false],
      specialChars: [false],
      excludeSimilar: [false]
    }) as GeneratorForm;

    this.saveForm = this.fb.group({
      title: [''],
      username: ['generated-user', [Validators.required, Validators.maxLength(120)]],
      website: ['', [Validators.required, Validators.maxLength(200)]],
      category: [null, Validators.required]
    }) as SaveToVaultForm;
  }

  generate(): void {
    const validationMessage = this.validateGenerationSettings();
    if (validationMessage) {
      this.notifications.show({ type: 'warning', text: validationMessage });
      return;
    }

    const values = this.form.getRawValue();
    if (values.length === null || values.count === null) {
      this.notifications.show({ type: 'warning', text: 'Enter password length and count.' });
      return;
    }

    this.isGenerating = true;
    this.api.generatePasswords({
      length: values.length,
      count: values.count,
      uppercase: !!values.uppercase,
      lowercase: !!values.lowercase,
      numbers: !!values.numbers,
      specialChars: !!values.specialChars,
      excludeSimilar: !!values.excludeSimilar
    }).subscribe({
      next: (response) => {
        this.generatedPasswords = response;
        this.notifications.show({ type: 'success', text: `Generated ${response.length} password(s).` });
      },
      error: () => {
        this.notifications.show({ type: 'error', text: 'Password generation failed.' });
      },
      complete: () => {
        this.isGenerating = false;
      }
    });
  }

  copy(password: string): void {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(password)
        .then(() => this.notifications.show({ type: 'info', text: 'Password copied to clipboard.' }))
        .catch(() => this.fallbackCopy(password));
      return;
    }

    this.fallbackCopy(password);
  }

  save(password: string): void {
    this.passwordToSave = password;
    this.showSaveDialog = true;
    this.saveForm.controls.website.markAsPristine();
    this.saveForm.controls.category.markAsPristine();
  }

  closeSaveDialog(): void {
    this.showSaveDialog = false;
    this.passwordToSave = '';
    this.saveForm.patchValue({
      title: '',
      username: this.saveForm.controls.username.value || 'generated-user',
      website: '',
      category: null
    });
    this.saveForm.markAsPristine();
    this.saveForm.markAsUntouched();
  }

  confirmSave(): void {
    if (!this.passwordToSave) {
      this.notifications.show({ type: 'warning', text: 'Select a generated password first.' });
      return;
    }

    this.saveForm.markAllAsTouched();
    if (this.saveForm.invalid) {
      this.notifications.show({ type: 'warning', text: 'Website and category are required.' });
      return;
    }

    const values = this.saveForm.getRawValue();
    this.isSaving = true;
    const savePayload: SavePasswordRequest = {
      title: values.title?.trim() || '',
      username: values.username?.trim() || 'generated-user',
      website: values.website?.trim() || '',
      category: values.category || undefined,
      password: this.passwordToSave
    };

    this.api.savePassword(savePayload).subscribe({
      next: () => {
        this.notifications.show({ type: 'success', text: 'Password saved to vault.' });
        this.closeSaveDialog();
      },
      error: () => {
        this.notifications.show({ type: 'error', text: 'Saving to vault failed.' });
      },
      complete: () => {
        this.isSaving = false;
      }
    });
  }

  strengthWidth(strength: string): number {
    switch (strength) {
      case 'WEAK':
        return 30;
      case 'MEDIUM':
        return 50;
      case 'STRONG':
      case 'VERY_STRONG':
        return 100;
      default:
        return 0;
    }
  }

  get lengthError(): string {
    const control = this.form.controls.length;
    if (!control.touched && !control.dirty) {
      return '';
    }
    if (control.hasError('required')) {
      return 'Password length is required.';
    }
    if (control.hasError('min') || control.hasError('max')) {
      return 'Use length between 8 and 64.';
    }
    return '';
  }

  get countError(): string {
    const control = this.form.controls.count;
    if (!control.touched && !control.dirty) {
      return '';
    }
    if (control.hasError('required')) {
      return 'Number of passwords is required.';
    }
    if (control.hasError('min') || control.hasError('max')) {
      return 'Use count between 1 and 20.';
    }
    return '';
  }

  get charSetError(): string {
    const values = this.form.getRawValue();
    if (this.form.pristine) {
      return '';
    }
    const valid = !!values.uppercase || !!values.lowercase || !!values.numbers || !!values.specialChars;
    return valid ? '' : 'Select at least one character set.';
  }

  get saveWebsiteError(): string {
    const control = this.saveForm.controls.website;
    if (!control.touched && !control.dirty) {
      return '';
    }
    if (control.hasError('required')) {
      return 'Website is required.';
    }
    if (control.hasError('maxlength')) {
      return 'Website must be at most 200 characters.';
    }
    return '';
  }

  get saveCategoryError(): string {
    const control = this.saveForm.controls.category;
    if (!control.touched && !control.dirty) {
      return '';
    }
    if (control.hasError('required')) {
      return 'Select a category.';
    }
    return '';
  }

  private fallbackCopy(text: string): void {
    const input = document.createElement('textarea');
    input.value = text;
    input.style.position = 'fixed';
    input.style.opacity = '0';
    document.body.appendChild(input);
    input.focus();
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
    this.notifications.show({ type: 'info', text: 'Password copied to clipboard.' });
  }

  private validateGenerationSettings(): string | null {
    const values = this.form.getRawValue();

    if (values.length === null || Number.isNaN(values.length)) {
      return 'Enter password length.';
    }
    if (values.length < 8 || values.length > 64) {
      return 'Change password length: use 8 to 64 characters.';
    }

    if (values.count === null || Number.isNaN(values.count)) {
      return 'Enter number of passwords to generate.';
    }
    if (values.count < 1 || values.count > 20) {
      return 'Number of passwords must be between 1 and 20.';
    }

    if (!values.uppercase && !values.lowercase && !values.numbers && !values.specialChars) {
      return 'Select at least one character set (uppercase, lowercase, numbers, special chars).';
    }

    return null;
  }
}
