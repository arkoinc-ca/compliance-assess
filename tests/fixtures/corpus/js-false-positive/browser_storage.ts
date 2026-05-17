// Corpus fixture — FALSE POSITIVE guard.
// Every call below is a `.delete()` on a browser/runtime store — none of them
// erase personal data, so missing-audit / missing-dsr must NOT flag any of them.
// This is the exact pattern class that compliance-assess v0.2.0 mis-reported.

export function clearLocale() {
  cookieStore.delete('locale');
}

export async function evictCache(key: string) {
  await caches.delete(key);
}

export function dropRecord(objectStore: IDBObjectStore, id: string) {
  objectStore.delete(id);
}

export function clearSessionMap(sessionMap: Map<string, unknown>, k: string) {
  sessionMap.delete(k);
}

export function stripHeader(headers: Headers) {
  headers.delete('authorization');
}
