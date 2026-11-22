import { createContext, useContext } from 'react';
import type { SessionInfo } from '../../lib/session';

export const SessionContext = createContext<{ session: SessionInfo; onSignedOut: () => void } | null>(null);

export function useSession() {
  return useContext(SessionContext);
}
