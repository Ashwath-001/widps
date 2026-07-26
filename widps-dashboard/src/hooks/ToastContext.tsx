import React, { createContext, useContext } from 'react';
import { useToast, type ToastType } from './useToast';
import ToastContainer from '../components/common/ToastContainer';

interface ToastContextValue {
  show: (message: string, type?: ToastType, duration?: number) => void;
}

const ToastContext = createContext<ToastContextValue>({ show: () => {} });

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const { toasts, show, dismiss } = useToast();

  return (
    <ToastContext.Provider value={{ show }}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

export function useToastContext() {
  return useContext(ToastContext);
}
