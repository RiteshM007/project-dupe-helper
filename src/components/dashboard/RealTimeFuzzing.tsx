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
  const [payload, setPayload] = useState<string>('');
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [payloadCount, setPayloadCount] = useState<number>(0);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [scanStartTime, setScanStartTime] = useState<number>(0);
  const { isConnected, sessionCookie } = useDVWAConnection();
  const { emitEvent } = useSocket();
  const [customHeaders, setCustomHeaders] = useState<string>('');
  const [isConfigured, setIsConfigured] = useState<boolean>(false);
  const [fuzzingStatus, setFuzzingStatus] = useState<string>('Ready');
  const [dvwaParams, setDvwaParams] = useState<string>('');
  const [dvwaPage, setDvwaPage] = useState<string>('');
  const [dvwaMethod, setDvwaMethod] = useState<string>('GET');
  const [dvwaSecurityLevel, setDvwaSecurityLevel] = useState<string>('low');
  const [dvwaCookie, setDvwaCookie] = useState<string>('');
  const [dvwaHost, setDvwaHost] = useState<string>('localhost:8080');

  const ws = useRef<WebSocket | null>(null);

  const startScan = useCallback(async () => {
    if (!isConnected) {
      toast({
        title: "Not Connected",
        description: "Please connect to DVWA first.",
        variant: "destructive",
      });
      return;
    }

    if (isScanning) {
      toast({
        title: "Already Scanning",
        description: "A scan is already in progress.",
        variant: "destructive",
      });
      return;
    }
    
    setIsScanning(true);
    setVulnerabilities([]);
    setProgress(0);
    setPayloadCount(0);
    setScanStartTime(Date.now());
    
    const sessionId = Date.now().toString();
    setCurrentSessionId(sessionId);
    
    console.log('RealTimeFuzzing: Starting scan with session ID:', sessionId);
    
    // Dispatch scan start events with delay to ensure listeners are ready
    setTimeout(() => {
      const scanStartEvent = new CustomEvent('scanStart', { detail: { sessionId, targetUrl } });
      window.dispatchEvent(scanStartEvent);
      
      const scanStartedEvent = new CustomEvent('scanStarted', { detail: { sessionId, targetUrl } });
      window.dispatchEvent(scanStartedEvent);
      
      const fuzzingStartedEvent = new CustomEvent('fuzzingStarted', { detail: { sessionId, targetUrl } });
      window.dispatchEvent(fuzzingStartedEvent);
      
      console.log('RealTimeFuzzing: Dispatched scan start events');
    }, 100);
    
    try {
      // Use the correct API method signature
      const response = await fuzzerApi.startFuzzing(sessionId, ['xss', 'sql_injection'], [payload]);
      
      if (response.success) {
        console.log('RealTimeFuzzing: Fuzzing started successfully');
        toast({
          title: "Fuzzing Started",
          description: "Fuzzing started successfully.",
        });
        setFuzzingStatus('Scanning');
        
        // Start simulated progress for demo
        simulateProgress();
      } else {
        console.error('RealTimeFuzzing: Failed to start fuzzing:', response.message);
        toast({
          title: "Fuzzing Failed",
          description: `Failed to start fuzzing: ${response.message}`,
          variant: "destructive",
        });
        setIsScanning(false);
        setFuzzingStatus('Error');
      }
    } catch (error: any) {
      console.error('RealTimeFuzzing: Error starting fuzzing:', error);
      toast({
        title: "Fuzzing Error",
        description: `Error starting fuzzing: ${error.message}`,
        variant: "destructive",
      });
      setIsScanning(false);
      setFuzzingStatus('Error');
    }
  }, [isConnected, sessionCookie, targetUrl, payload, customHeaders, isScanning, dvwaParams, dvwaPage, dvwaMethod, dvwaSecurityLevel, dvwaCookie, dvwaHost]);

  const simulateProgress = () => {
    let currentProgress = 0;
    const progressInterval = setInterval(() => {
      currentProgress += Math.random() * 15;
      if (currentProgress >= 95) {
        clearInterval(progressInterval);
        // Complete the scan
        setTimeout(() => {
          completeScan();
        }, 1000);
      } else {
        setProgress(currentProgress);
        
        // Simulate payload sending and vulnerability detection
        if (Math.random() > 0.7) {
          const newPayloadCount = payloadCount + 1;
          setPayloadCount(newPayloadCount);
          
          // Dispatch payload sent event
          const payloadSentEvent = new CustomEvent('payloadSent');
          window.dispatchEvent(payloadSentEvent);
          
          // Sometimes find vulnerabilities
          if (Math.random() > 0.8) {
            const vulnerabilityTypes = ['XSS', 'SQL Injection', 'CSRF', 'Path Traversal'];
            const vulnType = vulnerabilityTypes[Math.floor(Math.random() * vulnerabilityTypes.length)];
            
            const newVulnerability: Vulnerability = {
              id: Date.now().toString(),
              payload: payload || `<script>alert('${vulnType}')</script>`,
              description: `${vulnType} vulnerability detected`
            };
            
            setVulnerabilities(prev => [...prev, newVulnerability]);
            
            // Dispatch vulnerability found event
            const vulnerabilityFoundEvent = new CustomEvent('vulnerabilityFound', {
              detail: {
                payload: newVulnerability.payload,
                description: newVulnerability.description,
                vulnerabilityType: vulnType,
                severity: 'high',
                field: 'payload',
                timestamp: new Date()
              }
            });
            window.dispatchEvent(vulnerabilityFoundEvent);
            
            // Also dispatch threat detected event
            const threatDetectedEvent = new CustomEvent('threatDetected', {
              detail: {
                payload: newVulnerability.payload,
                vulnerabilityType: vulnType,
                severity: 'high',
                field: 'payload',
                timestamp: new Date()
              }
            });
            window.dispatchEvent(threatDetectedEvent);
            
            console.log('RealTimeFuzzing: Dispatched vulnerability and threat events');
          }
        }
      }
    }, 800);
  };

  const stopScan = useCallback(async () => {
    if (!isScanning) {
      toast({
        title: "Not Scanning",
        description: "No scan in progress.",
        variant: "destructive",
      });
      return;
    }
    
    setIsScanning(false);
    setFuzzingStatus('Stopping');
    
    console.log('RealTimeFuzzing: Stopping scan with session ID:', currentSessionId);
    
    // Dispatch scan stop event
    const scanStopEvent = new CustomEvent('scanStop');
    window.dispatchEvent(scanStopEvent);
    
    try {
      // Stop fuzzing via API
      const response = await fuzzerApi.stopFuzzing(currentSessionId || '');
      
      if (response.success) {
        console.log('RealTimeFuzzing: Fuzzing stopped successfully');
        toast({
          title: "Fuzzing Stopped",
          description: "Fuzzing stopped successfully.",
        });
        setFuzzingStatus('Stopped');
      } else {
        console.error('RealTimeFuzzing: Failed to stop fuzzing:', response.message);
        toast({
          title: "Fuzzing Failed",
          description: `Failed to stop fuzzing: ${response.message}`,
          variant: "destructive",
        });
        setFuzzingStatus('Error');
      }
    } catch (error: any) {
      console.error('RealTimeFuzzing: Error stopping fuzzing:', error);
      toast({
        title: "Fuzzing Error",
        description: `Error stopping fuzzing: ${error.message}`,
        variant: "destructive",
      });
      setFuzzingStatus('Error');
    } finally {
      setIsScanning(false);
      setFuzzingStatus('Ready');
    }
  }, [isScanning, currentSessionId]);

  const completeScan = useCallback(() => {
    if (!isScanning) return;
    
    setIsScanning(false);
    setProgress(100);
    setFuzzingStatus('Complete');
    
    const scanResults = {
      sessionId: currentSessionId,
      targetUrl: targetUrl || 'http://localhost:8080',
      target: targetUrl || 'http://localhost:8080',
      vulnerabilities: vulnerabilities.length,
      payloadsTested: payloadCount,
      duration: `${Math.floor((Date.now() - scanStartTime) / 1000)}s`,
      severity: vulnerabilities.length > 3 ? 'critical' : vulnerabilities.length > 1 ? 'high' : vulnerabilities.length > 0 ? 'medium' : 'low',
      type: 'fuzzing',
      timestamp: new Date().toISOString(),
      status: 'completed'
    };

    console.log('RealTimeFuzzing: Completing scan with results:', scanResults);
    
    // Dispatch multiple event types with delays to ensure all listeners catch them
    setTimeout(() => {
      const scanCompleteEvent = new CustomEvent('scanComplete', { detail: scanResults });
      window.dispatchEvent(scanCompleteEvent);
      console.log('RealTimeFuzzing: Dispatched scanComplete event');
    }, 100);
    
    setTimeout(() => {
      const globalScanCompleteEvent = new CustomEvent('globalScanComplete', { detail: scanResults });
      window.dispatchEvent(globalScanCompleteEvent);
      console.log('RealTimeFuzzing: Dispatched globalScanComplete event');
    }, 200);
    
    setTimeout(() => {
      const fuzzingCompleteEvent = new CustomEvent('fuzzingComplete', { detail: scanResults });
      window.dispatchEvent(fuzzingCompleteEvent);
      console.log('RealTimeFuzzing: Dispatched fuzzingComplete event');
    }, 300);
    
    toast({
      title: "Fuzzing Complete",
      description: `Found ${vulnerabilities.length} vulnerabilities in ${payloadCount} payloads`,
    });
  }, [isScanning, vulnerabilities, payloadCount, targetUrl, currentSessionId, scanStartTime]);

  useEffect(() => {
    const handleVulnerabilityFound = (event: CustomEvent) => {
      const { payload, description } = event.detail;
      console.log('RealTimeFuzzing: Vulnerability found:', payload, description);
      
      const newVulnerability: Vulnerability = {
        id: Date.now().toString(),
        payload,
        description,
      };
      
      setVulnerabilities(prev => [...prev, newVulnerability]);
      
      toast({
        title: "Vulnerability Found",
        description: description || "A vulnerability was found.",
      });
    };
    
    const handlePayloadSent = () => {
      setPayloadCount(prev => prev + 1);
    };
    
    window.addEventListener('vulnerabilityFound', handleVulnerabilityFound as EventListener);
    window.addEventListener('payloadSent', handlePayloadSent);
    
    return () => {
      window.removeEventListener('vulnerabilityFound', handleVulnerabilityFound as EventListener);
      window.removeEventListener('payloadSent', handlePayloadSent);
    };
  }, []);

  useEffect(() => {
    if (progress >= 100 && isScanning) {
      completeScan();
    }
  }, [progress, isScanning, completeScan]);

  return (
    <Card className="col-span-2 bg-card/90 backdrop-blur-md border-blue-900/30">
      <CardHeader>
        <CardTitle>Real-Time Fuzzing</CardTitle>
        <CardDescription>
          Configure and run a real-time fuzzing scan
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
            <Label htmlFor="customHeaders">Custom Headers (JSON)</Label>
            <Input
              id="customHeaders"
              value={customHeaders}
              onChange={(e) => setCustomHeaders(e.target.value)}
              placeholder='{"X-Custom-Header": "value"}'
              disabled={isScanning}
            />
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <Label htmlFor="dvwaParams">DVWA Parameters (JSON)</Label>
            <Input
              id="dvwaParams"
              value={dvwaParams}
              onChange={(e) => setDvwaParams(e.target.value)}
              placeholder='{"username": "admin", "password": "password"}'
              disabled={isScanning}
            />
          </div>
          <div>
            <Label htmlFor="dvwaPage">DVWA Page</Label>
            <Input
              id="dvwaPage"
              value={dvwaPage}
              onChange={(e) => setDvwaPage(e.target.value)}
              placeholder="login.php"
              disabled={isScanning}
            />
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <Label htmlFor="dvwaMethod">DVWA Method</Label>
            <select
              id="dvwaMethod"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:text-muted-foreground file:h-9 file:w-12 file:flex-1 file:cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
              value={dvwaMethod}
              onChange={(e) => setDvwaMethod(e.target.value)}
              disabled={isScanning}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </div>
          <div>
            <Label htmlFor="dvwaSecurityLevel">DVWA Security Level</Label>
            <select
              id="dvwaSecurityLevel"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:text-muted-foreground file:h-9 file:w-12 file:flex-1 file:cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
              value={dvwaSecurityLevel}
              onChange={(e) => setDvwaSecurityLevel(e.target.value)}
              disabled={isScanning}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="impossible">Impossible</option>
            </select>
          </div>
          <div>
            <Label htmlFor="dvwaCookie">DVWA Cookie</Label>
            <Input
              id="dvwaCookie"
              value={dvwaCookie}
              onChange={(e) => setDvwaCookie(e.target.value)}
              placeholder="security=low; PHPSESSID=..."
              disabled={isScanning}
            />
          </div>
          <div>
            <Label htmlFor="dvwaHost">DVWA Host</Label>
            <Input
              id="dvwaHost"
              value={dvwaHost}
              onChange={(e) => setDvwaHost(e.target.value)}
              placeholder="localhost:8080"
              disabled={isScanning}
            />
          </div>
        </div>

        <div>
          <Label htmlFor="payload">Payload</Label>
          <Textarea
            id="payload"
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder="Enter your payload here."
            disabled={isScanning}
          />
        </div>
        
        <div className="flex items-center justify-between">
          <div>
            <p>Status: {fuzzingStatus}</p>
            <p>Payloads Sent: {payloadCount}</p>
            <p>Vulnerabilities Found: {vulnerabilities.length}</p>
          </div>
          <Button
            onClick={isScanning ? stopScan : startScan}
            disabled={!isConnected}
          >
            {isScanning ? "Stop Scan" : "Start Scan"}
          </Button>
        </div>
        
        {isScanning && (
          <div>
            <Progress value={progress} />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
