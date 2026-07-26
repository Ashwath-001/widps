import { useState, useEffect, useCallback } from 'react';
import type { PageKey } from '../App';

const PAGE_KEYS: PageKey[] = [
  'overview', 'network', 'traffic', 'ai', 'threats',
  'log', 'stats', 'topology', 'reports', 'settings',
];

function getSessionKey(): string {
  let key = sessionStorage.getItem('widps_route_key');
  if (!key) {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    key = Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
    sessionStorage.setItem('widps_route_key', key);
  }
  return key;
}

function hashWithKey(page: string, key: string): string {
  const input = key + ':' + page + ':' + key.split('').reverse().join('');
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  let h3 = 0x9e3779b9;

  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
    h3 = Math.imul(h3 ^ ch, 2246822507);
  }

  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h3 ^ (h3 >>> 13), 1597334677);
  h3 = Math.imul(h3 ^ (h3 >>> 16), 3266489909);
  h3 ^= Math.imul(h1 ^ (h1 >>> 13), 2654435761);

  const combined = [h1 >>> 0, h2 >>> 0, h3 >>> 0]
    .map((n) => n.toString(36).padStart(7, '0'))
    .join('');

  return combined.substring(0, 18);
}

function buildMaps(key: string) {
  const pageToHash: Record<string, string> = {};
  const hashToPage: Record<string, PageKey> = {};

  for (const page of PAGE_KEYS) {
    const h = hashWithKey(page, key);
    pageToHash[page] = h;
    hashToPage[h] = page;
  }

  return { pageToHash, hashToPage };
}

const sessionKey = getSessionKey();
const { pageToHash, hashToPage } = buildMaps(sessionKey);

function getPageFromUrl(): PageKey {
  const fragment = window.location.hash.replace('#/', '').replace('#', '');
  if (!fragment) return 'overview';
  return hashToPage[fragment] || 'overview';
}

export function useHashRoute(): [PageKey, (page: PageKey) => void] {
  const [page, setPageState] = useState<PageKey>(getPageFromUrl);

  useEffect(() => {
    if (!window.location.hash) {
      window.location.hash = `/${pageToHash['overview']}`;
    }

    const handler = () => setPageState(getPageFromUrl());
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);

  const navigate = useCallback((key: PageKey) => {
    const hash = pageToHash[key];
    window.location.hash = `/${hash}`;
    setPageState(key);
  }, []);

  return [page, navigate];
}
