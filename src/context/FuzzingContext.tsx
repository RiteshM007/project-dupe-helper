
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
}

const FuzzingContext = createContext<FuzzingContextType | null>(null);

interface FuzzingProviderProps {
  children: ReactNode;
}

export const FuzzingProvider: React.FC<FuzzingProviderProps> = ({ children }) => {
  const [fuzzingResult, setFuzzingResultState] = useState<FuzzingResult | null>(null);
  const [mlResults, setMlResultsState] = useState<any[]>([]);
  const [threatReports, setThreatReportsState] = useState<any[]>([]);

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const cachedFuzzingResult = localStorage.getItem("fuzzingResult");
      const cachedMlResults = localStorage.getItem("mlResults");
      const cachedThreatReports = localStorage.getItem("threatReports");

      if (cachedFuzzingResult) {
        setFuzzingResultState(JSON.parse(cachedFuzzingResult));
      }
      if (cachedMlResults) {
        setMlResultsState(JSON.parse(cachedMlResults));
      }
      if (cachedThreatReports) {
        setThreatReportsState(JSON.parse(cachedThreatReports));
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
        console.log('FuzzingContext: Saved fuzzing result to localStorage');
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
    localStorage.removeItem("fuzzingResult");
    localStorage.removeItem("mlResults");
    localStorage.removeItem("threatReports");
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
