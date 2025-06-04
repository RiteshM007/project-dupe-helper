
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import Dashboard from '@/pages/Index';
import Fuzzer from '@/pages/Fuzzer';
import Reports from '@/pages/Reports';
import Settings from '@/pages/Settings';
import MachineLearning from '@/pages/MachineLearning';
import MLAnalysis from '@/pages/MLAnalysis';
import Terminal from '@/pages/Terminal';

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
      <Router>
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/fuzzer" element={<Fuzzer />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/machine-learning" element={<MachineLearning />} />
            <Route path="/ml-analysis" element={<MLAnalysis />} />
            <Route path="/terminal" element={<Terminal />} />
          </Routes>
          <Toaster position="top-right" richColors />
        </div>
      </Router>
    </QueryClientProvider>
  );
}

export default App;
