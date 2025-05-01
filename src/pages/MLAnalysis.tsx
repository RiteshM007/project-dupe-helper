
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { MachineLearningScanner } from '@/components/dashboard/MachineLearningScanner';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScanningStatus } from '@/components/fuzzer/ScanningStatus';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { AlertTriangle } from 'lucide-react';

const MLAnalysis = () => {
  const [scanActive, setScanActive] = useState(false);
  const [scanCompleted, setScanCompleted] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dataset, setDataset] = useState<any[]>([]);
  const [threatLevel, setThreatLevel] = useState<'none' | 'low' | 'medium' | 'high' | 'critical'>('none');
  const [datasetReceived, setDatasetReceived] = useState(false);

  // Listen for events from the fuzzer component
  useEffect(() => {
    const handleScanStart = (event: CustomEvent) => {
      console.log("Scan started:", event.detail);
      setScanActive(true);
      setScanCompleted(false);
      setProgress(0);
      setDataset([]);
      setThreatLevel('none');
    };

    const handleScanUpdate = (event: CustomEvent) => {
      const { progress, status } = event.detail;
      if (progress !== undefined) {
        setProgress(progress);
      }
      
      if (status === 'completed') {
        setTimeout(() => {
          setScanActive(false);
          setScanCompleted(true);
          setProgress(100); // Ensure progress is at 100%
        }, 500);
      }
    };

    const handleDatasetEntry = (event: CustomEvent) => {
      setDataset(prev => [...prev, event.detail]);
      setDatasetReceived(true);
      
      // Update threat level based on detected vulnerabilities
      if (event.detail.severity === 'critical') {
        setThreatLevel('critical');
      } else if (event.detail.severity === 'high' && threatLevel !== 'critical') {
        setThreatLevel('high');
      } else if (event.detail.severity === 'medium' && threatLevel !== 'critical' && threatLevel !== 'high') {
        setThreatLevel('medium');
      } else if (event.detail.severity === 'low' && threatLevel === 'none') {
        setThreatLevel('low');
      }
    };

    const handleScanComplete = () => {
      setScanActive(false);
      setScanCompleted(true);
      setProgress(100);
    };

    window.addEventListener('scanStart', handleScanStart as EventListener);
    window.addEventListener('scanUpdate', handleScanUpdate as EventListener);
    window.addEventListener('datasetEntry', handleDatasetEntry as EventListener);
    window.addEventListener('scanComplete', handleScanComplete);

    return () => {
      window.removeEventListener('scanStart', handleScanStart as EventListener);
      window.removeEventListener('scanUpdate', handleScanUpdate as EventListener);
      window.removeEventListener('datasetEntry', handleDatasetEntry as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete);
    };
  }, [threatLevel]);

  return (
    <DashboardLayout>
      <div className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-6">Machine Learning Analysis</h1>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <div className="col-span-1">
            <ScanningStatus isScanning={scanActive} progress={progress} />
          </div>
          <div className="col-span-2">
            {!datasetReceived && !scanActive ? (
              <Card>
                <CardContent className="p-6">
                  <Alert variant="default" className="bg-yellow-500/10 text-yellow-500 border-yellow-500/50">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>No Dataset Available</AlertTitle>
                    <AlertDescription>
                      Start a fuzzing process on the Fuzzer page to generate data for ML analysis.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardHeader>
                  <CardTitle>
                    Dataset Statistics
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                    <div className="p-3 bg-muted rounded-md">
                      <div className="text-2xl font-bold">{dataset.length}</div>
                      <div className="text-sm text-muted-foreground">Data Points</div>
                    </div>
                    <div className="p-3 bg-muted rounded-md">
                      <div className="text-2xl font-bold">
                        {dataset.filter(d => d.label === 'malicious' || d.vulnerabilityDetected).length}
                      </div>
                      <div className="text-sm text-muted-foreground">Threats</div>
                    </div>
                    <div className="p-3 bg-muted rounded-md">
                      <div className="text-2xl font-bold">
                        {dataset.filter(d => d.module === 'exec').length}
                      </div>
                      <div className="text-sm text-muted-foreground">Command Inj.</div>
                    </div>
                    <div className="p-3 bg-muted rounded-md">
                      <div className="text-2xl font-bold">
                        {dataset.filter(d => d.module === 'sqli' || d.module === 'xss').length}
                      </div>
                      <div className="text-sm text-muted-foreground">XSS/SQLi</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>

        <MachineLearningScanner
          scanActive={scanActive}
          scanCompleted={scanCompleted}
          dataset={dataset}
          threatLevel={threatLevel}
        />
      </div>
    </DashboardLayout>
  );
};

export default MLAnalysis;
