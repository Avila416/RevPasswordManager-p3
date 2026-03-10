export function readAuthToken(storage: Storage = localStorage): string {
  const keys = ['pm_token', 'token', 'access_token', 'authToken', 'jwt'];
  for (const key of keys) {
    const value = storage.getItem(key);
    if (value && value.trim().length > 0) {
      return value.trim();
    }
  }
  return '';
}
