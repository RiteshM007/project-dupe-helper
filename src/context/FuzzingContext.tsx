
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
  lastUpdated: string | null;
  setLastUpdated: (timestamp: string) => void;
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
  lastUpdated: null,
  setLastUpdated: () => {},
});

export const useFuzzing = () => useContext(FuzzingContext);

export const FuzzingProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [fuzzingResult, setFuzzingResult] = useState<any | null>(null);
  const [mlResults, setMlResults] = useState<any[]>([]);
  const [threatReports, setThreatReports] = useState<any[]>([]);
  const [lastScanResult, setLastScanResult] = useState<any | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const addThreatReport = (report: any) => {
    setThreatReports(prev => [...prev, report]);
    setLastUpdated(new Date().toISOString());
  };

  useEffect(() => {
    const handleScanComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Handling scan complete event:', event.detail);
      const result = event.detail;
      
      setFuzzingResult({
        sessionId: result.sessionId || result.session_id || `scan-${Date.now()}`,
        targetUrl: result.targetUrl || result.target_url || result.target || 'Unknown',
        vulnerabilities: result.vulnerabilities || result.vulnerabilitiesFound || 0,
        payloadsTested: result.payloadsTested || result.payloads_tested || 0,
        duration: result.duration || 'Unknown',
        severity: result.severity || 'low',
        type: result.type || 'scan',
        timestamp: result.timestamp || new Date().toISOString(),
        status: 'completed',
        findings: result.findings || result.threats || []
      });
      
      setLastScanResult(result);
      setIsScanning(false);
      setLastUpdated(new Date().toISOString());
    };

    const handleMLComplete = (event: CustomEvent) => {
      console.log('FuzzingContext: Handling ML complete event:', event.detail);
      const result = event.detail;
      
      // Update ML results
      const newMlResult = {
        sessionId: result.sessionId || `ml-${Date.now()}`,
        patterns: result.patterns?.length || result.patterns || 0,
        accuracy: result.model_performance?.accuracy || result.accuracy || 0.85,
        riskLevel: result.anomaly_detection_rate > 0.3 ? 'High' : 'Medium',
        type: 'ml_analysis',
        timestamp: new Date().toISOString(),
        payloads: result.payloads || [],
        anomaly_detection_rate: result.anomaly_detection_rate || 0.15
      };

      setMlResults(prev => [...prev.slice(-4), newMlResult]);

      // Also update fuzzing result for dashboard display
      setFuzzingResult({
        sessionId: result.sessionId || `ml-${Date.now()}`,
        targetUrl: 'ML Analysis Pipeline',
        vulnerabilities: result.patterns?.length || result.patterns || 0,
        payloadsTested: result.payloads?.length || 0,
        duration: '2m 30s',
        severity: result.anomaly_detection_rate > 0.3 ? 'high' : 'medium',
        type: 'machine-learning',
        timestamp: new Date().toISOString(),
        status: 'completed',
        findings: []
      });
      
      setIsScanning(false);
      setLastUpdated(new Date().toISOString());
    };

    const handleThreatDetected = (event: CustomEvent) => {
      console.log('FuzzingContext: Handling threat detected event:', event.detail);
      const threat = event.detail;
      
      const threatReport = {
        title: threat.type || 'Security Threat Detected',
        severity: threat.severity || 'medium',
        detectedAt: new Date(),
        source: 'real-time-scanner',
        threatType: threat.type?.toLowerCase().replace(' ', '_') || 'unknown',
        timestamp: new Date(),
        target: threat.target || threat.target_url || 'Unknown',
        payload: threat.payload || 'N/A',
        status_code: threat.status_code
      };
      
      addThreatReport(threatReport);
    };

    const handleMLPayloadsGenerated = (event: CustomEvent) => {
      console.log('FuzzingContext: ML Payloads generated:', event.detail);
      // Could update a separate payloads state if needed
    };

    const handleFuzzingProgress = (event: CustomEvent) => {
      console.log('FuzzingContext: Fuzzing progress:', event.detail);
      // Update progress if needed for UI
    };

    const handleScanStart = (event: CustomEvent) => {
      console.log('FuzzingContext: Scan started:', event.detail);
      setIsScanning(true);
      setLastUpdated(new Date().toISOString());
    };

    // Listen to all relevant events
    const events = [
      { name: 'scanComplete', handler: handleScanComplete },
      { name: 'globalScanComplete', handler: handleScanComplete },
      { name: 'fuzzingComplete', handler: handleScanComplete },
      { name: 'globalFuzzingComplete', handler: handleScanComplete },
      { name: 'mlAnalysisComplete', handler: handleMLComplete },
      { name: 'globalMLAnalysisComplete', handler: handleMLComplete },
      { name: 'threatDetected', handler: handleThreatDetected },
      { name: 'globalThreatDetected', handler: handleThreatDetected },
      { name: 'mlPayloadsGenerated', handler: handleMLPayloadsGenerated },
      { name: 'fuzzing_progress', handler: handleFuzzingProgress },
      { name: 'scanStart', handler: handleScanStart },
      { name: 'fuzzingStarted', handler: handleScanStart }
    ];

    events.forEach(({ name, handler }) => {
      window.addEventListener(name, handler as EventListener);
    });

    return () => {
      events.forEach(({ name, handler }) => {
        window.removeEventListener(name, handler as EventListener);
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
    lastUpdated,
    setLastUpdated,
  };

  return (
    <FuzzingContext.Provider value={contextValue}>
      {children}
    </FuzzingContext.Provider>
  );
};
