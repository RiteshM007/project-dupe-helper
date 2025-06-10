
import React, { createContext, useState, useContext, useEffect, ReactNode } from "react";

interface FuzzingResult {
  sessionId: string;
  targetUrl: string;
  vulnerabilities: number;
  payloadsTested: number;
  duration: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  timestamp: string;
  status: 'completed' | 'failed' | 'in-progress';
  findings?: any[];
  payloadSet?: string;
  fuzzingMode?: string;
  dvwaModule?: string;
}

interface FuzzingContextType {
  fuzzingResult: FuzzingResult | null;
  setFuzzingResult: (result: FuzzingResult | null) => void;
  mlResults: any[];
  setMlResults: (results: any[]) => void;
  threatReports: any[];
  setThreatReports: (reports: any[]) => void;
  addThreatReport: (report: any) => void;
  clearAllData: () => void;
  lastUpdated: string | null;
}

const FuzzingContext = createContext<FuzzingContextType | null>(null);

interface FuzzingProviderProps {
  children: ReactNode;
}

export const FuzzingProvider: React.FC<FuzzingProviderProps> = ({ children }) => {
  const [fuzzingResult, setFuzzingResultState] = useState<FuzzingResult | null>(null);
  const [mlResults, setMlResultsState] = useState<any[]>([]);
  const [threatReports, setThreatReportsState] = useState<any[]>([]);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const cachedFuzzingResult = localStorage.getItem("fuzzingResult");
      const cachedMlResults = localStorage.getItem("mlResults");
      const cachedThreatReports = localStorage.getItem("threatReports");
      const cachedLastUpdated = localStorage.getItem("lastUpdated");

      if (cachedFuzzingResult) {
        setFuzzingResultState(JSON.parse(cachedFuzzingResult));
      }
      if (cachedMlResults) {
        setMlResultsState(JSON.parse(cachedMlResults));
      }
      if (cachedThreatReports) {
        setThreatReportsState(JSON.parse(cachedThreatReports));
      }
      if (cachedLastUpdated) {
        setLastUpdated(cachedLastUpdated);
      }
      
      console.log('FuzzingContext: Loaded data from localStorage');
    } catch (error) {
      console.error('FuzzingContext: Error loading from localStorage:', error);
    }
  }, []);

  // Save fuzzing result to localStorage whenever it changes
  useEffect(() => {
    if (fuzzingResult) {
      try {
        localStorage.setItem("fuzzingResult", JSON.stringify(fuzzingResult));
        const timestamp = new Date().toISOString();
        localStorage.setItem("lastUpdated", timestamp);
        setLastUpdated(timestamp);
        console.log('FuzzingContext: Saved fuzzing result to localStorage', fuzzingResult);
      } catch (error) {
        console.error('FuzzingContext: Error saving fuzzing result to localStorage:', error);
      }
    }
  }, [fuzzingResult]);

  // Save ML results to localStorage whenever they change
  useEffect(() => {
    if (mlResults.length > 0) {
      try {
        localStorage.setItem("mlResults", JSON.stringify(mlResults));
        console.log('FuzzingContext: Saved ML results to localStorage');
      } catch (error) {
        console.error('FuzzingContext: Error saving ML results to localStorage:', error);
      }
    }
  }, [mlResults]);

  // Save threat reports to localStorage whenever they change
  useEffect(() => {
    if (threatReports.length > 0) {
      try {
        localStorage.setItem("threatReports", JSON.stringify(threatReports));
        console.log('FuzzingContext: Saved threat reports to localStorage');
      } catch (error) {
        console.error('FuzzingContext: Error saving threat reports to localStorage:', error);
      }
    }
  }, [threatReports]);

  // Set up global event listeners for fuzzing events
  useEffect(() => {
    const handleFuzzingComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Received fuzzingComplete event:', event.detail);
      setFuzzingResult(event.detail);
    };

    const handleScanComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Received scanComplete event:', event.detail);
      setFuzzingResult(event.detail);
    };

    const handleGlobalScanComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Received globalScanComplete event:', event.detail);
      setFuzzingResult(event.detail);
    };

    const handleMLAnalysisComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Received mlAnalysisComplete event:', event.detail);
      setMlResults(prev => [event.detail, ...prev].slice(0, 10));
    };

    const handleThreatDetected = (event: CustomEvent) => {
      console.log('FuzzingContext: Received threatDetected event:', event.detail);
      addThreatReport({
        id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        timestamp: new Date(),
        threatType: event.detail.vulnerabilityType || event.detail.type || 'Unknown',
        payload: event.detail.payload || 'N/A',
        severity: (event.detail.severity || 'medium').toLowerCase(),
        target: event.detail.field || event.detail.target || 'General'
      });
    };

    // Add event listeners
    window.addEventListener('fuzzingComplete', handleFuzzingComplete as EventListener);
    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    window.addEventListener('globalScanComplete', handleGlobalScanComplete as EventListener);
    window.addEventListener('mlAnalysisComplete', handleMLAnalysisComplete as EventListener);
    window.addEventListener('threatDetected', handleThreatDetected as EventListener);
    window.addEventListener('globalThreatDetected', handleThreatDetected as EventListener);

    console.log('FuzzingContext: Global event listeners set up');

    return () => {
      window.removeEventListener('fuzzingComplete', handleFuzzingComplete as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
      window.removeEventListener('globalScanComplete', handleGlobalScanComplete as EventListener);
      window.removeEventListener('mlAnalysisComplete', handleMLAnalysisComplete as EventListener);
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
      window.removeEventListener('globalThreatDetected', handleThreatDetected as EventListener);
      console.log('FuzzingContext: Global event listeners cleaned up');
    };
  }, []);

  const setFuzzingResult = (result: FuzzingResult | null) => {
    console.log('FuzzingContext: Setting fuzzing result:', result);
    setFuzzingResultState(result);
  };

  const setMlResults = (results: any[]) => {
    console.log('FuzzingContext: Setting ML results:', results);
    setMlResultsState(results);
  };

  const setThreatReports = (reports: any[]) => {
    console.log('FuzzingContext: Setting threat reports:', reports);
    setThreatReportsState(reports);
  };

  const addThreatReport = (report: any) => {
    console.log('FuzzingContext: Adding threat report:', report);
    setThreatReportsState(prev => {
      const updated = [report, ...prev].slice(0, 50); // Keep only 50 most recent
      return updated;
    });
  };

  const clearAllData = () => {
    console.log('FuzzingContext: Clearing all data');
    setFuzzingResultState(null);
    setMlResultsState([]);
    setThreatReportsState([]);
    setLastUpdated(null);
    localStorage.removeItem("fuzzingResult");
    localStorage.removeItem("mlResults");
    localStorage.removeItem("threatReports");
    localStorage.removeItem("lastUpdated");
  };

  const contextValue: FuzzingContextType = {
    fuzzingResult,
    setFuzzingResult,
    mlResults,
    setMlResults,
    threatReports,
    setThreatReports,
    addThreatReport,
    clearAllData,
    lastUpdated,
  };

  return (
    <FuzzingContext.Provider value={contextValue}>
      {children}
    </FuzzingContext.Provider>
  );
};

export const useFuzzing = (): FuzzingContextType => {
  const context = useContext(FuzzingContext);
  if (!context) {
    throw new Error('useFuzzing must be used within a FuzzingProvider');
  }
  return context;
};

export { FuzzingContext };
