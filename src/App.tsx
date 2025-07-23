
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import Dashboard from '@/pages/Dashboard';
import Fuzzer from '@/pages/Fuzzer';
import Analysis from '@/pages/Analysis';
import Reports from '@/pages/Reports';
import Settings from '@/pages/Settings';
import MLAnalysis from '@/pages/MLAnalysis';
import AuthPage from '@/components/auth/AuthPage';
import ProtectedRoute from '@/components/auth/ProtectedRoute';
import { AuthProvider } from '@/contexts/AuthContext';
import { DVWAConnectionProvider } from '@/context/DVWAConnectionContext';
import { SocketProvider } from '@/context/SocketContext';
import { FuzzingProvider } from '@/context/FuzzingContext';

// Create QueryClient instance correctly
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <FuzzingProvider>
          <SocketProvider>
            <DVWAConnectionProvider>
              <Router>
                <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900">
                  <Routes>
                    <Route path="/auth" element={<AuthPage />} />
                    <Route path="/" element={
                      <ProtectedRoute>
                        <Dashboard />
                      </ProtectedRoute>
                    } />
                    <Route path="/fuzzer" element={
                      <ProtectedRoute>
                        <Fuzzer />
                      </ProtectedRoute>
                    } />
                    <Route path="/analysis" element={
                      <ProtectedRoute>
                        <Analysis />
                      </ProtectedRoute>
                    } />
                    <Route path="/reports" element={
                      <ProtectedRoute>
                        <Reports />
                      </ProtectedRoute>
                    } />
                    <Route path="/settings" element={
                      <ProtectedRoute>
                        <Settings />
                      </ProtectedRoute>
                    } />
                    <Route path="/ml-analysis" element={
                      <ProtectedRoute>
                        <MLAnalysis />
                      </ProtectedRoute>
                    } />
                  </Routes>
                  <Toaster position="top-right" />
                </div>
              </Router>
            </DVWAConnectionProvider>
          </SocketProvider>
        </FuzzingProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
