
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import React from "react";
import Index from "./pages/Index";
import Fuzzer from "./pages/Fuzzer";
import MachineLearning from "./pages/MachineLearning";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Terminal from "./pages/Terminal";
import NotFound from "./pages/NotFound";
import MLAnalysis from "./pages/MLAnalysis";
import { DVWAConnectionProvider } from "./context/DVWAConnectionContext";

// Create a client instance properly without 'new' keyword
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const App = () => (
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <BrowserRouter>
          <DVWAConnectionProvider>
            <Toaster />
            <Sonner />
            <Routes>
              <Route path="/" element={<Index />} />
              <Route path="/fuzzer" element={<Fuzzer />} />
              <Route path="/machine-learning" element={<MachineLearning />} />
              <Route path="/ml-analysis" element={<MLAnalysis />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/terminal" element={<Terminal />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </DVWAConnectionProvider>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </React.StrictMode>
);

export default App;
