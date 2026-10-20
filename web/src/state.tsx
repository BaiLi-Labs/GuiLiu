import { createContext, useContext } from 'react';
import type { Me, Meta, Page, Provider } from './types';

export interface AppContextValue {
  me: Me | null;
  meta: Meta | null;
  providers: Provider[];
  isAdmin: boolean;
  page: Page;
  go: (page: Page) => void;
  toast: (message: string, error?: boolean) => void;
  refreshNonce: number;
  refresh: () => void;
}

export const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const value = useContext(AppContext);
  if (!value) throw new Error('AppContext is missing');
  return value;
}
