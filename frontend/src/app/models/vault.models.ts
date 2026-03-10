export type Category = 'SOCIAL' | 'BANKING' | 'WORK' | 'SHOPPING' | 'OTHER';

export interface VaultEntry {
  id: number;
  title: string;
  username: string;
  website: string;
  category: Category;
  favorite: boolean;
  createdAt: string;
  password: string;
}

export interface VaultEntryPayload {
  title: string;
  username: string;
  website: string;
  category: Category;
  password?: string;
}

export interface SearchPayload {
  keyword?: string;
  category?: Category;
  sortBy?: string;
}
