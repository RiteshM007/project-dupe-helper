import React, { createContext, useState, useContext, useEffect } from 'react';

interface FuzzingContextType {
  isScanning: boolean;
  setIsScanning: (scanning: boolean) => void;
  fuzzingResult: any | null;
  setFuzzingResult: (result: any) => void;
  mlResults: any[];
  setMlResults: (results: any[]) => void;
  addThreatReport: (report: any) => void;
  threatReports: any[];
  lastScanResult: any | null;
  setLastScanResult: (result: any) => void;
}

const FuzzingContext = createContext<FuzzingContextType>({
  isScanning: false,
  setIsScanning: () => {},
  fuzzingResult: null,
  setFuzzingResult: () => {},
  mlResults: [],
  setMlResults: () => {},
  addThreatReport: () => {},
  threatReports: [],
  lastScanResult: null,
  setLastScanResult: () => {},
});

export const useFuzzing = () => useContext(FuzzingContext);

export const FuzzingProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [fuzzingResult, setFuzzingResult] = useState<any | null>(null);
  const [mlResults, setMlResults] = useState<any[]>([]);
  const [threatReports, setThreatReports] = useState<any[]>([]);
  const [lastScanResult, setLastScanResult] = useState<any | null>(null);

  const addThreatReport = (report: any) => {
    setThreatReports(prev => [...prev, report]);
  };

  useEffect(() => {
    const handleScanComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Handling scan complete event:', event.detail);
      const result = event.detail;
      
      setFuzzingResult({
        sessionId: result.sessionId || `scan-${Date.now()}`,
        targetUrl: result.targetUrl || result.target || 'Unknown',
        vulnerabilities: result.vulnerabilities || 0,
        payloadsTested: result.payloadsTested || 0,
        duration: result.duration || 'Unknown',
        severity: result.severity || 'low',
        type: result.type || 'scan',
        timestamp: result.timestamp || new Date().toISOString(),
        status: 'completed',
        findings: result.findings || []
      });
      
      setLastScanResult(result);
      setIsScanning(false);
    };

    const handleMLComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Handling ML complete event:', event.detail);
      const result = event.detail;
      
      // Update ML results
      setMlResults(prev => [...prev.slice(-4), {
        sessionId: result.sessionId || `ml-${Date.now()}`,
        patterns: result.patterns || 0,
        accuracy: result.model_performance?.accuracy || result.accuracy || 0.85,
        riskLevel: result.anomaly_detection_rate > 0.3 ? 'High' : 'Medium',
        type: 'ml_analysis',
        timestamp: new Date().toISOString()
      }]);

      // Also update fuzzing result for dashboard display
      setFuzzingResult({
        sessionId: result.sessionId || `ml-${Date.now()}`,
        targetUrl: 'ML Analysis Pipeline',
        vulnerabilities: result.patterns || 0,
        payloadsTested: result.generated_payloads_count || 0,
        duration: '2m 30s',
        severity: result.anomaly_detection_rate > 0.3 ? 'high' : 'medium',
        type: 'machine-learning',
        timestamp: new Date().toISOString(),
        status: 'completed',
        findings: []
      });
      
      setIsScanning(false);
    };

    // Listen to multiple event types for maximum compatibility
    const events = [
      'scanComplete',
      'globalScanComplete', 
      'fuzzingComplete',
      'mlAnalysisComplete',
      'globalMLAnalysisComplete'
    ];

    events.forEach(eventType => {
      if (eventType.includes('ML') || eventType.includes('ml')) {
        window.addEventListener(eventType, handleMLComplete as EventListener);
      } else {
        window.addEventListener(eventType, handleScanComplete as EventListener);
      }
    });

    return () => {
      events.forEach(eventType => {
        if (eventType.includes('ML') || eventType.includes('ml')) {
          window.removeEventListener(eventType, handleMLComplete as EventListener);
        } else {
          window.removeEventListener(eventType, handleScanComplete as EventListener);
        }
      });
    };
  }, []);

  const contextValue: FuzzingContextType = {
    isScanning,
    setIsScanning,
    fuzzingResult,
    setFuzzingResult,
    mlResults,
    setMlResults,
    addThreatReport,
    threatReports,
    lastScanResult,
    setLastScanResult,
  };

  return (
    <FuzzingContext.Provider value={contextValue}>
      {children}
    </FuzzingContext.Provider>
  );
};
