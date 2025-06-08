import React, { useState, useCallback, useRef, useEffect } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { toast } from "@/hooks/use-toast"
import { useDVWAConnection } from '@/context/DVWAConnectionContext';
import { Progress } from '@/components/ui/progress';
import { fuzzerApi } from '@/services/api';

interface Vulnerability {
  id: string;
  payload: string;
  description: string;
}

export const RealTimeFuzzing: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState<string>('http://localhost:8080');
  const [payload, setPayload] = useState<string>('<script>alert("XSS")</script>');
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [payloadCount, setPayloadCount] = useState<number>(0);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [scanStartTime, setScanStartTime] = useState<number>(0);
  const { isConnected } = useDVWAConnection();
  const [fuzzingStatus, setFuzzingStatus] = useState<string>('Ready');
  const [backendConnected, setBackendConnected] = useState<boolean>(false);

  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Check backend connection on mount
  useEffect(() => {
    const checkBackendConnection = async () => {
      try {
        await fuzzerApi.checkHealth();
        setBackendConnected(true);
        console.log('Backend connection established');
      } catch (error) {
        setBackendConnected(false);
        console.error('Backend connection failed:', error);
        toast({
          title: "Backend Connection Failed",
          description: "Please ensure the Python backend server is running on port 5000",
          variant: "destructive",
        });
      }
    };

    checkBackendConnection();
  }, []);

  const startScan = useCallback(async () => {
    console.log('=== STARTING REAL FUZZING SCAN ===');
    
    if (isScanning) {
      toast({
        title: "Already Scanning",
        description: "A scan is already in progress.",
        variant: "destructive",
      });
      return;
    }

    if (!backendConnected) {
      toast({
        title: "Backend Not Available",
        description: "Please ensure the Python backend server is running on port 5000",
        variant: "destructive",
      });
      return;
    }
    
    // Clear any existing intervals
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
      progressIntervalRef.current = null;
    }
    
    // Reset state
    setIsScanning(true);
    setVulnerabilities([]);
    setProgress(0);
    setPayloadCount(0);
    setScanStartTime(Date.now());
    setFuzzingStatus('Creating Session');
    
    try {
      // Create fuzzer session on backend
      console.log('Creating fuzzer session on backend...');
      const createResponse = await fuzzerApi.createFuzzer(targetUrl);
      
      if (!createResponse.success) {
        throw new Error(createResponse.error || 'Failed to create fuzzer session');
      }
      
      const sessionId = createResponse.session_id;
      setCurrentSessionId(sessionId);
      setFuzzingStatus('Starting');
      
      console.log('RealTimeFuzzing: Backend session created:', sessionId);
      
      // Dispatch scan start events
      const scanDetail = { 
        sessionId, 
        targetUrl,
        type: 'fuzzing',
        timestamp: new Date().toISOString()
      };
      
      window.dispatchEvent(new CustomEvent('scanStart', { detail: scanDetail }));
      window.dispatchEvent(new CustomEvent('fuzzingStarted', { detail: scanDetail }));
      
      // Start fuzzing on backend
      console.log('Starting fuzzing on backend...');
      const startResponse = await fuzzerApi.startFuzzing(sessionId, ['xss', 'sqli', 'lfi'], [payload]);
      
      if (startResponse.success) {
        console.log('RealTimeFuzzing: Backend fuzzing started successfully');
        toast({
          title: "Fuzzing Started",
          description: "Real fuzzing scan initiated on backend server.",
        });
        setFuzzingStatus('Scanning');
        
        // Start monitoring progress
        monitorFuzzingProgress(sessionId);
      } else {
        throw new Error(startResponse.error || 'Failed to start fuzzing');
      }
    } catch (error: any) {
      console.error('RealTimeFuzzing: Error starting real fuzzing:', error);
      toast({
        title: "Fuzzing Error",
        description: `Error starting fuzzing: ${error.message}`,
        variant: "destructive",
      });
      setIsScanning(false);
      setFuzzingStatus('Error');
      setCurrentSessionId(null);
    }
  }, [targetUrl, payload, isScanning, backendConnected]);

  const monitorFuzzingProgress = (sessionId: string) => {
    console.log('Starting to monitor fuzzing progress...');
    
    progressIntervalRef.current = setInterval(async () => {
      try {
        const status = await fuzzerApi.getFuzzingStatus(sessionId);
        
        if (status.success) {
          setProgress(status.progress || 0);
          setPayloadCount(status.payloads_processed || 0);
          
          // Dispatch progress events
          window.dispatchEvent(new CustomEvent('payloadSent', {
            detail: { count: status.payloads_processed || 0 }
          }));
          
          // Check if scan is complete
          if (!status.active || status.progress >= 100) {
            console.log('Fuzzing completed, getting results...');
            completeScan(sessionId);
          }
        }
      } catch (error) {
        console.error('Error monitoring fuzzing progress:', error);
      }
    }, 2000); // Check every 2 seconds
  };

  const completeScan = useCallback(async (sessionId: string) => {
    console.log('RealTimeFuzzing: === COMPLETING REAL FUZZING SCAN ===');
    
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
      progressIntervalRef.current = null;
    }
    
    try {
      // Get final results from backend
      const results = await fuzzerApi.getFuzzingResults(sessionId);
      
      if (results.success) {
        const finalResults = results.results;
        setProgress(100);
        setFuzzingStatus('Complete');
        setIsScanning(false);
        
        const scanDuration = Math.floor((Date.now() - scanStartTime) / 1000);
        
        const scanResults = {
          sessionId,
          targetUrl,
          vulnerabilities: finalResults.vulnerabilitiesFound || 0,
          payloadsTested: finalResults.totalPayloads || payloadCount,
          duration: `${scanDuration}s`,
          severity: finalResults.vulnerabilitiesFound > 3 ? 'critical' : 
                   finalResults.vulnerabilitiesFound > 1 ? 'high' : 
                   finalResults.vulnerabilitiesFound > 0 ? 'medium' : 'low',
          type: 'fuzzing',
          timestamp: new Date().toISOString(),
          status: 'completed',
          findings: finalResults.threats || []
        };

        console.log('RealTimeFuzzing: Real scan completed with results:', scanResults);
        
        // Dispatch completion events
        setTimeout(() => {
          window.dispatchEvent(new CustomEvent('scanComplete', { detail: scanResults }));
        }, 200);
        
        setTimeout(() => {
          window.dispatchEvent(new CustomEvent('globalScanComplete', { detail: scanResults }));
        }, 400);
        
        setTimeout(() => {
          window.dispatchEvent(new CustomEvent('fuzzingComplete', { detail: scanResults }));
        }, 600);
        
        toast({
          title: "Real Fuzzing Complete!",
          description: `Found ${scanResults.vulnerabilities} vulnerabilities in ${scanResults.payloadsTested} payloads`,
        });
      }
    } catch (error: any) {
      console.error('Error completing scan:', error);
      toast({
        title: "Error Getting Results",
        description: `Failed to get scan results: ${error.message}`,
        variant: "destructive",
      });
    } finally {
      setTimeout(() => {
        setCurrentSessionId(null);
        setFuzzingStatus('Ready');
      }, 3000);
    }
  }, [payloadCount, scanStartTime, targetUrl]);

  const stopScan = useCallback(async () => {
    console.log('RealTimeFuzzing: === STOPPING REAL FUZZING SCAN ===');
    
    if (!isScanning || !currentSessionId) {
      toast({
        title: "Not Scanning",
        description: "No scan in progress.",
        variant: "destructive",
      });
      return;
    }
    
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
      progressIntervalRef.current = null;
    }
    
    setFuzzingStatus('Stopping');
    
    try {
      await fuzzerApi.stopFuzzing(currentSessionId);
      
      setIsScanning(false);
      
      window.dispatchEvent(new CustomEvent('scanStop', {
        detail: { sessionId: currentSessionId }
      }));
      
      toast({
        title: "Fuzzing Stopped",
        description: "Real fuzzing scan has been stopped.",
      });
      setFuzzingStatus('Stopped');
    } catch (error: any) {
      console.error('RealTimeFuzzing: Error stopping real fuzzing:', error);
      toast({
        title: "Stop Error",
        description: `Error stopping fuzzing: ${error.message}`,
        variant: "destructive",
      });
    } finally {
      setTimeout(() => {
        setFuzzingStatus('Ready');
        setCurrentSessionId(null);
      }, 1000);
    }
  }, [isScanning, currentSessionId]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
    };
  }, []);

  return (
    <Card className="col-span-2 bg-card/90 backdrop-blur-md border-blue-900/30">
      <CardHeader>
        <CardTitle>Real-Time Fuzzing</CardTitle>
        <CardDescription>
          Configure and run a real-time fuzzing scan against your target using the Python backend
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {!backendConnected && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
            <p className="text-red-400 font-medium">Backend Server Not Connected</p>
            <p className="text-sm text-gray-400">Please ensure the Python backend server is running on port 5000</p>
          </div>
        )}
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <Label htmlFor="targetUrl">Target URL</Label>
            <Input
              id="targetUrl"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:8080"
              disabled={isScanning}
            />
          </div>
          <div>
            <Label htmlFor="payload">Test Payload</Label>
            <Input
              id="payload"
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder='<script>alert("XSS")</script>'
              disabled={isScanning}
            />
          </div>
        </div>

        <div>
          <Label htmlFor="payloadTextarea">Custom Payload (Advanced)</Label>
          <Textarea
            id="payloadTextarea"
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder="Enter your custom payload here for testing..."
            disabled={isScanning}
            rows={3}
          />
        </div>
        
        <div className="flex items-center justify-between p-4 bg-black/20 rounded-lg border border-gray-700/50">
          <div className="space-y-1">
            <p className="text-sm font-medium">
              Status: <span className="text-blue-400">{fuzzingStatus}</span>
              {backendConnected && <span className="ml-2 text-green-400">(Backend Connected)</span>}
            </p>
            <p className="text-sm text-gray-400">Payloads Tested: <span className="text-white">{payloadCount}</span></p>
            <p className="text-sm text-gray-400">Vulnerabilities Found: <span className="text-red-400">{vulnerabilities.length}</span></p>
            {currentSessionId && (
              <p className="text-xs text-gray-500">Session: {currentSessionId}</p>
            )}
          </div>
          <Button
            onClick={isScanning ? stopScan : startScan}
            size="lg"
            className={isScanning ? "bg-red-600 hover:bg-red-700" : "bg-green-600 hover:bg-green-700"}
            disabled={!backendConnected && !isScanning}
          >
            {isScanning ? "Stop Scan" : "Start Real Fuzzing"}
          </Button>
        </div>
        
        {isScanning && (
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Progress</span>
              <span>{Math.round(progress)}%</span>
            </div>
            <Progress value={progress} className="w-full" />
          </div>
        )}

        {vulnerabilities.length > 0 && (
          <div className="space-y-2">
            <Label>Found Vulnerabilities</Label>
            <div className="max-h-32 overflow-y-auto space-y-1">
              {vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="p-2 bg-red-900/20 border border-red-500/30 rounded text-sm">
                  <p className="font-medium text-red-400">{vuln.description}</p>
                  <p className="text-xs text-gray-400 truncate">Payload: {vuln.payload}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
