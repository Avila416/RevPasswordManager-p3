import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { map, Observable } from 'rxjs';
import { SearchPayload, VaultEntry, VaultEntryPayload } from '../models/vault.models';

@Injectable({ providedIn: 'root' })
export class VaultApiService {
  private readonly baseUrl = '/api/vault';

  constructor(private http: HttpClient) {}

  getAllEntries(): Observable<VaultEntry[]> {
    return this.http.get<any[]>(this.baseUrl).pipe(
      map((rows) =>
        rows.map((row) => ({
          id: row.id,
          title: row.title ?? '',
          username: row.username ?? '',
          website: row.website ?? '',
          category: row.category ?? 'OTHER',
          favorite: !!row.favorite,
          createdAt: row.createdAt,
          password: row.password ?? ''
        } as VaultEntry))
      )
    );
  }

  addEntry(payload: VaultEntryPayload): Observable<VaultEntry> {
    const request = {
      username: payload.username,
      password: payload.password ?? '',
      title: payload.title,
      website: payload.website,
      category: payload.category
    };

    return this.http.post<any>(this.baseUrl, request).pipe(
      map((row) => ({
        id: row.id,
        title: row.title ?? payload.title ?? '',
        username: row.username ?? payload.username,
        website: row.website ?? payload.website ?? '',
        category: row.category ?? payload.category ?? 'OTHER',
        favorite: !!row.favorite,
        createdAt: row.createdAt,
        password: row.password ?? payload.password ?? ''
      } as VaultEntry))
    );
  }

  updateEntry(id: number, payload: VaultEntryPayload): Observable<VaultEntry> {
    const request: { username: string; title?: string; website?: string; category?: string; password?: string } = {
      username: payload.username,
      title: payload.title ?? '',
      website: payload.website ?? ''
    };
    request.category = payload.category ?? 'OTHER';

    if (payload.password && payload.password.trim()) {
      request.password = payload.password;
    }

    return this.http.put<any>(`${this.baseUrl}/${id}`, request).pipe(
      map((row) => ({
        id: row.id,
        title: row.title ?? payload.title ?? '',
        username: row.username ?? payload.username,
        website: row.website ?? payload.website ?? '',
        category: row.category ?? payload.category ?? 'OTHER',
        favorite: !!row.favorite,
        createdAt: row.createdAt,
        password: row.password ?? payload.password ?? ''
      } as VaultEntry))
    );
  }

  deleteEntry(id: number, masterPassword: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${id}`, {
      headers: {
        'X-Master-Password': masterPassword
      }
    });
  }

  markFavorite(id: number): Observable<void> {
    return this.http.put<void>(`${this.baseUrl}/${id}/favorite`, {});
  }

  getFavorites(): Observable<VaultEntry[]> {
    return this.http.get<any[]>(`${this.baseUrl}/favorites`).pipe(
      map((rows) =>
        rows.map((row) => ({
          id: row.id,
          title: row.title ?? '',
          username: row.username ?? '',
          website: row.website ?? '',
          category: row.category ?? 'OTHER',
          favorite: !!row.favorite,
          createdAt: row.createdAt,
          password: row.password ?? ''
        } as VaultEntry))
      )
    );
  }

  verifyAndGet(id: number, masterPassword: string): Observable<VaultEntry> {
    return this.http
      .get<any>(`${this.baseUrl}/${id}?decrypt=true`, {
        headers: {
          'X-Master-Password': masterPassword
        }
      })
      .pipe(
      map((row) => ({
        id: row.id,
        title: row.title ?? '',
        username: row.username ?? '',
        website: row.website ?? '',
        category: row.category ?? 'OTHER',
        favorite: !!row.favorite,
        createdAt: row.createdAt,
        password: row.password ?? ''
      } as VaultEntry))
    );
  }

  searchEntries(payload: SearchPayload, sortBy?: string, direction: string = 'asc'): Observable<VaultEntry[]> {
    const body = {
      keyword: payload.keyword ?? '',
      category: payload.category ?? ''
    };
    const params = new URLSearchParams();
    if (sortBy) params.set('sortBy', sortBy);
    if (direction) params.set('direction', direction);

    return this.http
      .post<any[]>(`${this.baseUrl}/search?${params.toString()}`, body)
      .pipe(
        map((rows) =>
          rows.map((row) => ({
            id: row.id,
            title: row.title ?? '',
            username: row.username ?? '',
            website: row.website ?? '',
            category: row.category ?? 'OTHER',
            favorite: !!row.favorite,
            createdAt: row.createdAt,
            password: row.password ?? ''
          } as VaultEntry))
        )
      );
  }
}
