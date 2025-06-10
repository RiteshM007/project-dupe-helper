
import React, { createContext, useContext, useState, useEffect } from 'react';

export interface FuzzingResult {
  sessionId: string;
  targetUrl: string;
  vulnerabilities: number;
  payloadsTested: number;
  duration: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  timestamp: string;
  status: 'completed' | 'failed' | 'stopped';
  findings: any[];
  payloadSet?: string;
  fuzzingMode?: string;
  dvwaModule?: string;
}

export interface MLResult {
  sessionId: string;
  patterns: number;
  accuracy: number;
  riskLevel: string;
  type: string;
  timestamp: string;
}

export interface ThreatReport {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectedAt: Date;
  source: string;
  threatType: string;
  timestamp: Date;
  target: string;
  payload: string;
}

interface FuzzingContextType {
  fuzzingResult: FuzzingResult | null;
  setFuzzingResult: (result: FuzzingResult | null) => void;
  mlResults: MLResult[];
  setMlResults: React.Dispatch<React.SetStateAction<MLResult[]>>;
  threatReports: ThreatReport[];
  setThreatReports: React.Dispatch<React.SetStateAction<ThreatReport[]>>;
  scanHistory: FuzzingResult[];
  setScanHistory: React.Dispatch<React.SetStateAction<FuzzingResult[]>>;
  lastUpdated: string | null;
  addThreatReport: (threat: Omit<ThreatReport, 'id'>) => void;
}

const FuzzingContext = createContext<FuzzingContextType | null>(null);

export const FuzzingProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [fuzzingResult, setFuzzingResult] = useState<FuzzingResult | null>(null);
  const [mlResults, setMlResults] = useState<MLResult[]>([]);
  const [threatReports, setThreatReports] = useState<ThreatReport[]>([]);
  const [scanHistory, setScanHistory] = useState<FuzzingResult[]>([]);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const addThreatReport = (threat: Omit<ThreatReport, 'id'>) => {
    const newThreat: ThreatReport = {
      ...threat,
      id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
    };
    
    setThreatReports(prev => [newThreat, ...prev.slice(0, 19)]);
    setLastUpdated(new Date().toISOString());
  };

  // Load data from localStorage on mount
  useEffect(() => {
    try {
      const storedResult = localStorage.getItem('fuzzingResult');
      const storedMlResults = localStorage.getItem('mlResults');
      const storedThreatReports = localStorage.getItem('threatReports');
      const storedScanHistory = localStorage.getItem('scanHistory');

      if (storedResult) {
        const parsed = JSON.parse(storedResult);
        setFuzzingResult(parsed);
        console.log('FuzzingContext: Loaded fuzzing result from localStorage');
      }

      if (storedMlResults) {
        const parsed = JSON.parse(storedMlResults);
        setMlResults(parsed);
        console.log('FuzzingContext: Loaded ML results from localStorage');
      }

      if (storedThreatReports) {
        const parsed = JSON.parse(storedThreatReports);
        setThreatReports(parsed);
        console.log('FuzzingContext: Loaded threat reports from localStorage');
      }

      if (storedScanHistory) {
        const parsed = JSON.parse(storedScanHistory);
        setScanHistory(parsed);
        console.log('FuzzingContext: Loaded scan history from localStorage');
      }

      console.log('FuzzingContext: Loaded data from localStorage');
    } catch (error) {
      console.error('FuzzingContext: Error loading from localStorage:', error);
    }
  }, []);

  // Save to localStorage when data changes
  useEffect(() => {
    if (fuzzingResult) {
      localStorage.setItem('fuzzingResult', JSON.stringify(fuzzingResult));
      setLastUpdated(new Date().toISOString());
      console.log('FuzzingContext: Saved fuzzing result to localStorage');
    }
  }, [fuzzingResult]);

  useEffect(() => {
    if (mlResults.length > 0) {
      localStorage.setItem('mlResults', JSON.stringify(mlResults));
      setLastUpdated(new Date().toISOString());
      console.log('FuzzingContext: Saved ML results to localStorage');
    }
  }, [mlResults]);

  useEffect(() => {
    if (threatReports.length > 0) {
      localStorage.setItem('threatReports', JSON.stringify(threatReports));
      console.log('FuzzingContext: Saved threat reports to localStorage');
    }
  }, [threatReports]);

  useEffect(() => {
    if (scanHistory.length > 0) {
      localStorage.setItem('scanHistory', JSON.stringify(scanHistory));
      console.log('FuzzingContext: Saved scan history to localStorage');
    }
  }, [scanHistory]);

  // Global event listeners
  useEffect(() => {
    const handleFuzzingComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Fuzzing complete event received:', event.detail);
      const result = event.detail as FuzzingResult;
      setFuzzingResult(result);
      
      // Add to scan history
      setScanHistory(prev => {
        const updated = [result, ...prev.slice(0, 9)]; // Keep last 10 scans
        return updated;
      });
    };

    const handleMLComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: ML analysis complete event received:', event.detail);
      const mlResult = event.detail as MLResult;
      setMlResults(prev => [mlResult, ...prev.slice(0, 4)]); // Keep last 5 ML results
    };

    const handleThreatDetected = (event: CustomEvent) => {
      console.log('FuzzingContext: Threat detected event received:', event.detail);
      const { payload, vulnerabilityType, severity = 'medium', field } = event.detail;
      
      const newThreat: ThreatReport = {
        id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        title: field ? `${vulnerabilityType} in ${field}` : vulnerabilityType || 'Security Issue',
        severity: severity as 'low' | 'medium' | 'high' | 'critical',
        detectedAt: new Date(),
        source: 'fuzzer',
        threatType: vulnerabilityType || 'Unknown',
        timestamp: new Date(),
        target: field || 'General',
        payload: payload || 'N/A'
      };
      
      setThreatReports(prev => {
        const updated = [newThreat, ...prev.slice(0, 19)]; // Keep last 20 threats
        return updated;
      });
    };

    // Add event listeners
    window.addEventListener('fuzzingComplete', handleFuzzingComplete as EventListener);
    window.addEventListener('globalFuzzingComplete', handleFuzzingComplete as EventListener);
    window.addEventListener('scanComplete', handleFuzzingComplete as EventListener);
    window.addEventListener('globalScanComplete', handleFuzzingComplete as EventListener);
    window.addEventListener('mlAnalysisComplete', handleMLComplete as EventListener);
    window.addEventListener('globalMLAnalysisComplete', handleMLComplete as EventListener);
    window.addEventListener('threatDetected', handleThreatDetected as EventListener);
    window.addEventListener('globalThreatDetected', handleThreatDetected as EventListener);

    console.log('FuzzingContext: Global event listeners set up');

    return () => {
      window.removeEventListener('fuzzingComplete', handleFuzzingComplete as EventListener);
      window.removeEventListener('globalFuzzingComplete', handleFuzzingComplete as EventListener);
      window.removeEventListener('scanComplete', handleFuzzingComplete as EventListener);
      window.removeEventListener('globalScanComplete', handleFuzzingComplete as EventListener);
      window.removeEventListener('mlAnalysisComplete', handleMLComplete as EventListener);
      window.removeEventListener('globalMLAnalysisComplete', handleMLComplete as EventListener);
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
      window.removeEventListener('globalThreatDetected', handleThreatDetected as EventListener);
      console.log('FuzzingContext: Global event listeners cleaned up');
    };
  }, []);

  const value: FuzzingContextType = {
    fuzzingResult,
    setFuzzingResult,
    mlResults,
    setMlResults,
    threatReports,
    setThreatReports,
    scanHistory,
    setScanHistory,
    lastUpdated,
    addThreatReport,
  };

  return (
    <FuzzingContext.Provider value={value}>
      {children}
    </FuzzingContext.Provider>
  );
};

export const useFuzzing = () => {
  const context = useContext(FuzzingContext);
  if (!context) {
    throw new Error('useFuzzing must be used within a FuzzingProvider');
  }
  return context;
};
