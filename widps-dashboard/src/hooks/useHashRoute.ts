import { useState, useEffect, useCallback } from 'react';
import { ALL_PAGE_KEYS, type PageKey } from '../config/navigation';


function getPageFromUrl(): PageKey {
  const path = window.location.pathname.replace(/^\//, '').replace(/\/$/, '');
  if (!path || path === 'index.html') return 'overview';
  if (ALL_PAGE_KEYS.includes(path as PageKey)) {
    return path as PageKey;
  }
  return 'overview';
}

export function useHashRoute(): [PageKey, (page: PageKey) => void] {
  const [page, setPageState] = useState<PageKey>(getPageFromUrl);

  useEffect(() => {
    if (window.location.pathname === '/' || window.location.pathname === '/index.html') {
      window.history.replaceState(null, '', '/overview');
    }

    const handler = () => setPageState(getPageFromUrl());
    window.addEventListener('popstate', handler);
    return () => window.removeEventListener('popstate', handler);
  }, []);

  const navigate = useCallback((key: PageKey) => {
    window.history.pushState(null, '', `/${key}`);
    setPageState(key);
  }, []);

  return [page, navigate];
}
