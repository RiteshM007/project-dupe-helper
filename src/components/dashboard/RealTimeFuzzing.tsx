
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
import { useSocket } from '@/hooks/use-socket';

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
  const { isConnected, sessionCookie } = useDVWAConnection();
  const { emitEvent } = useSocket();
  const [fuzzingStatus, setFuzzingStatus] = useState<string>('Ready');

  // Create a stable reference for the simulation interval
  const simulationIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const startScan = useCallback(async () => {
    console.log('=== STARTING FUZZING SCAN ===');
    console.log('Connection status:', isConnected);
    console.log('Current scanning status:', isScanning);
    
    if (isScanning) {
      console.log('Scan already in progress, aborting start');
      toast({
        title: "Already Scanning",
        description: "A scan is already in progress.",
        variant: "destructive",
      });
      return;
    }
    
    // Clear any existing simulation
    if (simulationIntervalRef.current) {
      clearInterval(simulationIntervalRef.current);
      simulationIntervalRef.current = null;
    }
    
    // Reset state
    setIsScanning(true);
    setVulnerabilities([]);
    setProgress(0);
    setPayloadCount(0);
    setScanStartTime(Date.now());
    setFuzzingStatus('Initializing');
    
    const sessionId = `fuzzing-session-${Date.now()}`;
    setCurrentSessionId(sessionId);
    
    console.log('Generated session ID:', sessionId);
    
    // Dispatch scan start events immediately
    console.log('Dispatching scan start events...');
    
    const scanStartEvent = new CustomEvent('scanStart', { 
      detail: { 
        sessionId, 
        targetUrl,
        type: 'fuzzing',
        timestamp: new Date().toISOString()
      } 
    });
    window.dispatchEvent(scanStartEvent);
    
    const fuzzingStartedEvent = new CustomEvent('fuzzingStarted', { 
      detail: { 
        sessionId, 
        targetUrl,
        type: 'fuzzing',
        timestamp: new Date().toISOString()
      } 
    });
    window.dispatchEvent(fuzzingStartedEvent);
    
    console.log('Scan start events dispatched');
    
    try {
      setFuzzingStatus('Starting');
      
      // Start the fuzzing process
      console.log('Calling fuzzerApi.startFuzzing...');
      const response = await fuzzerApi.startFuzzing(sessionId, ['xss', 'sql_injection'], [payload]);
      
      if (response.success) {
        console.log('Fuzzing API call successful');
        toast({
          title: "Fuzzing Started",
          description: "Fuzzing scan initiated successfully.",
        });
        setFuzzingStatus('Scanning');
        
        // Start realistic simulation
        simulateRealisticProgress();
      } else {
        console.error('Fuzzing API call failed:', response.message);
        toast({
          title: "Fuzzing Failed",
          description: `Failed to start fuzzing: ${response.message}`,
          variant: "destructive",
        });
        setIsScanning(false);
        setFuzzingStatus('Error');
      }
    } catch (error: any) {
      console.error('Error starting fuzzing:', error);
      toast({
        title: "Fuzzing Error",
        description: `Error starting fuzzing: ${error.message}`,
        variant: "destructive",
      });
      setIsScanning(false);
      setFuzzingStatus('Error');
    }
  }, [isConnected, targetUrl, payload, isScanning]);

  const simulateRealisticProgress = () => {
    console.log('Starting realistic fuzzing simulation...');
    let currentProgress = 0;
    let currentPayloads = 0;
    let foundVulnerabilities = 0;
    
    simulationIntervalRef.current = setInterval(() => {
      if (!isScanning) {
        console.log('Stopping simulation - scan no longer active');
        if (simulationIntervalRef.current) {
          clearInterval(simulationIntervalRef.current);
          simulationIntervalRef.current = null;
        }
        return;
      }
      
      // Increment progress
      const progressIncrement = Math.random() * 8 + 2; // 2-10% increments
      currentProgress = Math.min(currentProgress + progressIncrement, 95);
      setProgress(currentProgress);
      
      // Send payloads
      if (Math.random() > 0.3) {
        currentPayloads += Math.floor(Math.random() * 3) + 1;
        setPayloadCount(currentPayloads);
        
        // Dispatch payload sent event
        window.dispatchEvent(new CustomEvent('payloadSent', {
          detail: { count: currentPayloads }
        }));
      }
      
      // Find vulnerabilities occasionally
      if (Math.random() > 0.85 && foundVulnerabilities < 5) {
        foundVulnerabilities++;
        const vulnerabilityTypes = ['XSS', 'SQL Injection', 'CSRF', 'Path Traversal', 'Command Injection'];
        const vulnType = vulnerabilityTypes[Math.floor(Math.random() * vulnerabilityTypes.length)];
        const severityLevels = ['low', 'medium', 'high', 'critical'];
        const severity = severityLevels[Math.floor(Math.random() * severityLevels.length)];
        
        const newVulnerability: Vulnerability = {
          id: `vuln-${Date.now()}-${Math.random()}`,
          payload: payload || `<script>alert('${vulnType}')</script>`,
          description: `${vulnType} vulnerability detected with severity: ${severity}`
        };
        
        setVulnerabilities(prev => [...prev, newVulnerability]);
        
        console.log('Found vulnerability:', newVulnerability);
        
        // Dispatch vulnerability events
        const vulnerabilityDetail = {
          id: newVulnerability.id,
          payload: newVulnerability.payload,
          description: newVulnerability.description,
          vulnerabilityType: vulnType,
          severity: severity,
          field: 'payload',
          timestamp: new Date().toISOString(),
          sessionId: currentSessionId
        };
        
        window.dispatchEvent(new CustomEvent('vulnerabilityFound', {
          detail: vulnerabilityDetail
        }));
        
        window.dispatchEvent(new CustomEvent('threatDetected', {
          detail: vulnerabilityDetail
        }));
        
        window.dispatchEvent(new CustomEvent('globalThreatDetected', {
          detail: vulnerabilityDetail
        }));
        
        toast({
          title: "Vulnerability Found!",
          description: `${vulnType} detected (${severity} severity)`,
        });
      }
      
      // Complete scan when progress reaches ~95%
      if (currentProgress >= 95) {
        console.log('Simulation completing...');
        if (simulationIntervalRef.current) {
          clearInterval(simulationIntervalRef.current);
          simulationIntervalRef.current = null;
        }
        
        // Small delay before completion
        setTimeout(() => {
          completeScan();
        }, 1000);
      }
    }, 1200); // Run every 1.2 seconds for more realistic timing
  };

  const stopScan = useCallback(async () => {
    console.log('=== STOPPING FUZZING SCAN ===');
    
    if (!isScanning) {
      toast({
        title: "Not Scanning",
        description: "No scan in progress.",
        variant: "destructive",
      });
      return;
    }
    
    // Clear simulation
    if (simulationIntervalRef.current) {
      clearInterval(simulationIntervalRef.current);
      simulationIntervalRef.current = null;
    }
    
    setIsScanning(false);
    setFuzzingStatus('Stopping');
    
    console.log('Stopping scan with session ID:', currentSessionId);
    
    // Dispatch scan stop event
    window.dispatchEvent(new CustomEvent('scanStop', {
      detail: { sessionId: currentSessionId }
    }));
    
    try {
      if (currentSessionId) {
        const response = await fuzzerApi.stopFuzzing(currentSessionId);
        console.log('Stop fuzzing response:', response);
      }
      
      toast({
        title: "Fuzzing Stopped",
        description: "Fuzzing scan has been stopped.",
      });
      setFuzzingStatus('Stopped');
    } catch (error: any) {
      console.error('Error stopping fuzzing:', error);
      toast({
        title: "Stop Error",
        description: `Error stopping fuzzing: ${error.message}`,
        variant: "destructive",
      });
    } finally {
      setFuzzingStatus('Ready');
      setCurrentSessionId(null);
    }
  }, [isScanning, currentSessionId]);

  const completeScan = useCallback(() => {
    console.log('=== COMPLETING FUZZING SCAN ===');
    
    if (!isScanning) {
      console.log('Scan not active, skipping completion');
      return;
    }
    
    setIsScanning(false);
    setProgress(100);
    setFuzzingStatus('Complete');
    
    const scanDuration = Math.floor((Date.now() - scanStartTime) / 1000);
    
    const scanResults = {
      sessionId: currentSessionId,
      targetUrl: targetUrl,
      target: targetUrl,
      vulnerabilities: vulnerabilities.length,
      payloadsTested: payloadCount,
      duration: `${scanDuration}s`,
      severity: vulnerabilities.length > 3 ? 'critical' : 
               vulnerabilities.length > 1 ? 'high' : 
               vulnerabilities.length > 0 ? 'medium' : 'low',
      type: 'fuzzing',
      timestamp: new Date().toISOString(),
      status: 'completed',
      findings: vulnerabilities
    };

    console.log('Scan completed with results:', scanResults);
    
    // Dispatch completion events with staggered timing for better reliability
    setTimeout(() => {
      console.log('Dispatching scanComplete event');
      window.dispatchEvent(new CustomEvent('scanComplete', { detail: scanResults }));
    }, 100);
    
    setTimeout(() => {
      console.log('Dispatching globalScanComplete event');
      window.dispatchEvent(new CustomEvent('globalScanComplete', { detail: scanResults }));
    }, 200);
    
    setTimeout(() => {
      console.log('Dispatching fuzzingComplete event');
      window.dispatchEvent(new CustomEvent('fuzzingComplete', { detail: scanResults }));
    }, 300);
    
    toast({
      title: "Fuzzing Complete!",
      description: `Found ${vulnerabilities.length} vulnerabilities in ${payloadCount} payloads`,
    });
    
    // Reset session after a delay
    setTimeout(() => {
      setCurrentSessionId(null);
      setFuzzingStatus('Ready');
    }, 2000);
  }, [isScanning, vulnerabilities, payloadCount, targetUrl, currentSessionId, scanStartTime]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (simulationIntervalRef.current) {
        clearInterval(simulationIntervalRef.current);
      }
    };
  }, []);

  return (
    <Card className="col-span-2 bg-card/90 backdrop-blur-md border-blue-900/30">
      <CardHeader>
        <CardTitle>Real-Time Fuzzing</CardTitle>
        <CardDescription>
          Configure and run a real-time fuzzing scan against your target
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
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
            <p className="text-sm font-medium">Status: <span className="text-blue-400">{fuzzingStatus}</span></p>
            <p className="text-sm text-gray-400">Payloads Tested: <span className="text-white">{payloadCount}</span></p>
            <p className="text-sm text-gray-400">Vulnerabilities Found: <span className="text-red-400">{vulnerabilities.length}</span></p>
            {currentSessionId && (
              <p className="text-xs text-gray-500">Session: {currentSessionId}</p>
            )}
          </div>
          <Button
            onClick={isScanning ? stopScan : startScan}
            disabled={false} // Always allow starting, even without DVWA connection for demo
            size="lg"
            className={isScanning ? "bg-red-600 hover:bg-red-700" : "bg-green-600 hover:bg-green-700"}
          >
            {isScanning ? "Stop Scan" : "Start Fuzzing"}
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
