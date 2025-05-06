import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';
import { ThemeProvider } from 'styled-components';
import App from './App';
import ErrorBoundary from './components/ErrorBoundary';
import { darkTheme } from './theme';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <ThemeProvider theme={darkTheme}>
        <QueryClientProvider client={queryClient}>
          <App />
          <Toaster position="top-right" />
        </QueryClientProvider>
      </ThemeProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
