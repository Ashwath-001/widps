import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  error: string;
}

export default class ErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false, error: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error: error.message };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center py-20 px-4 text-center">
          <div className="w-14 h-14 rounded-2xl bg-[var(--color-accent-danger)]/10 flex items-center justify-center mb-4">
            <AlertTriangle size={28} className="text-[var(--color-accent-danger)]" />
          </div>
          <h2 className="text-lg font-semibold text-[var(--color-text)]">Something went wrong</h2>
          <p className="text-sm text-[var(--color-text-muted)] mt-2 max-w-md">
            This page encountered an error. This usually happens when the backend returns unexpected data.
          </p>
          <p className="text-xs data-mono text-[var(--color-text-muted)] mt-3 px-4 py-2 rounded bg-[var(--color-card)] border border-[var(--color-border-soft)] max-w-md truncate">
            {this.state.error}
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: '' })}
            className="mt-6 flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[var(--color-accent-blue)] text-white text-sm font-medium hover:bg-[var(--color-accent-blue-soft)] transition-colors"
          >
            <RotateCcw size={14} />
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
