import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { ToastProvider } from './hooks/ToastContext.tsx'
import AuthGate from './components/auth/AuthGate.tsx'
import { installFetchWrapper } from './lib/session.ts'

installFetchWrapper()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ToastProvider>
      <AuthGate>
        <App />
      </AuthGate>
    </ToastProvider>
  </StrictMode>,
)
