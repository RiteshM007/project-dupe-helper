
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import ScanControl from "./pages/ScanControl";
import Fuzzer from "./pages/Fuzzer";
import MachineLearning from "./pages/MachineLearning";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/scan" element={<ScanControl />} />
          <Route path="/fuzzer" element={<Fuzzer />} />
          <Route path="/machine-learning" element={<MachineLearning />} />
          {/* Placeholder routes for future implementation */}
          <Route path="/reports" element={<Index />} />
          <Route path="/ai-analysis" element={<Index />} />
          <Route path="/settings" element={<Index />} />
          <Route path="/terminal" element={<Index />} />
          {/* Catch-all route */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
