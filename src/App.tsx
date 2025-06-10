
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import Dashboard from '@/pages/Dashboard';
import Fuzzer from '@/pages/Fuzzer';
import Analysis from '@/pages/Analysis';
import Reports from '@/pages/Reports';
import Settings from '@/pages/Settings';
import MachineLearning from '@/pages/MachineLearning';
import MLAnalysis from '@/pages/MLAnalysis';
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
      <FuzzingProvider>
        <SocketProvider>
          <DVWAConnectionProvider>
            <Router>
              <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900">
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/fuzzer" element={<Fuzzer />} />
                  <Route path="/analysis" element={<Analysis />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/machine-learning" element={<MachineLearning />} />
                  <Route path="/ml-analysis" element={<MLAnalysis />} />
                </Routes>
                <Toaster position="top-right" />
              </div>
            </Router>
          </DVWAConnectionProvider>
        </SocketProvider>
      </FuzzingProvider>
    </QueryClientProvider>
  );
}

export default App;
