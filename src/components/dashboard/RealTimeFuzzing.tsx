
import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Link, Bug, Shield, Zap, Loader } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { PayloadUploader } from '@/components/fuzzer/PayloadUploader';
import { LiveLogs } from '@/components/fuzzer/LiveLogs';
import { checkDVWAConnection, loginToDVWA, fuzzerRequest, DVWAResponse } from '@/utils/dvwaFuzzer';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';

export const RealTimeFuzzing: React.FC = () => {
  const { isConnected, setIsConnected, dvwaUrl, setDvwaUrl, sessionCookie, setSessionCookie } = useDVWAConnection();
  const [url, setUrl] = useState(dvwaUrl || "http://localhost:8080");
  const [module, setModule] = useState("exec");
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);
  const [customPayloads, setCustomPayloads] = useState<string[]>([]);
  const [payloadSet, setPayloadSet] = useState("custom");
  const [fuzzingMode, setFuzzingMode] = useState("thorough");
  const [scanStats, setScanStats] = useState({
    payloadsSent: 0,
    responsesReceived: 0,
    threatsDetected: 0,
  });
  const [payloadsReady, setPayloadsReady] = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  
  // Add a ref to track if the component is unmounted
  const isMountedRef = useRef(true);
  // Add a ref to track the active fuzzing state
  const activeFuzzingRef = useRef(false);

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const handlePayloadsUploaded = (payloads: string[]) => {
    setCustomPayloads(payloads);
    setPayloadsReady(true);
    addLog(`Loaded ${payloads.length} custom payloads`);
  };

  const handleConnect = async () => {
    addLog(`Attempting to connect to DVWA at ${url}`);
    
    const isReachable = await checkDVWAConnection(url);
    if (!isReachable) {
      toast({
        title: "Connection Failed",
        description: "DVWA server not reachable. Please start DVWA and try again.",
        variant: "destructive",
      });
      return;
    }

    const loginResult = await loginToDVWA(url, 'admin', 'password');
    if (loginResult.success && loginResult.cookie) {
      setIsConnected(true);
      setDvwaUrl(url);
      setSessionCookie(loginResult.cookie);
      addLog('Successfully connected to DVWA');
      toast({
        title: "Connected",
        description: "Successfully connected to DVWA",
      });
    } else {
      toast({
        title: "Login Failed",
        description: "Could not authenticate with DVWA",
        variant: "destructive",
      });
    }
  };

  const handleStartFuzzing = async () => {
    if (!isConnected) {
      toast({
        title: "Not Connected",
        description: "Please connect to DVWA first",
        variant: "destructive",
      });
      return;
    }

    if (!payloadsReady || customPayloads.length === 0) {
      toast({
        title: "No Payloads",
        description: "Please upload custom payloads first",
        variant: "destructive",
      });
      return;
    }

    // Set the active fuzzing ref to true
    activeFuzzingRef.current = true;
    
    setIsFuzzing(true);
    setProgress(0);
    setScanStats({
      payloadsSent: 0,
      responsesReceived: 0,
      threatsDetected: 0,
    });

    // Generate a unique scan ID
    const scanId = Math.random().toString(36).substring(2, 11);
    setCurrentScanId(scanId);
    
    // Dispatch scan start event
    window.dispatchEvent(new CustomEvent('scanStart', {
      detail: { 
        scanId, 
        status: 'in-progress'
      }
    }));
    
    addLog(`Started scan #${scanId}`);

    // Process each payload
    for (let i = 0; i < customPayloads.length; i++) {
      // Check if component is still mounted and fuzzing is still active
      if (!isMountedRef.current || !activeFuzzingRef.current) {
        // If stopped early, mark as failed
        if (isMountedRef.current) {
          window.dispatchEvent(new CustomEvent('scanUpdate', {
            detail: { 
              scanId,
              status: 'failed'
            }
          }));
          addLog(`Scan #${scanId} stopped prematurely`);
          setCurrentScanId(null);
        }
        break;
      }

      const payload = customPayloads[i];
      addLog(`Testing payload: ${payload}`);

      try {
        setScanStats(prev => ({
          ...prev,
          payloadsSent: prev.payloadsSent + 1
        }));

        const result = await fuzzerRequest(dvwaUrl, payload, sessionCookie, module);
        
        // Check again if fuzzing is still active after the request
        if (!isMountedRef.current || !activeFuzzingRef.current) break;
        
        setScanStats(prev => ({
          ...prev, 
          responsesReceived: prev.responsesReceived + 1
        }));

        if (result.vulnerabilityDetected) {
          setScanStats(prev => ({
            ...prev,
            threatsDetected: prev.threatsDetected + 1
          }));
          
          // Dispatch threat detected event
          window.dispatchEvent(new CustomEvent('threatDetected', {
            detail: { 
              payload,
              vulnerabilityType: moduleToVulnerabilityType(module),
              severity: determineSeverity(payload, module)
            }
          }));
          
          addLog(`⚠️ ALERT: Potential vulnerability detected with payload: ${payload}`);
          toast({
            title: "Vulnerability Detected",
            description: `A potential vulnerability was found using payload: ${payload}`,
            variant: "destructive",
          });
        }

        // Update progress
        const newProgress = ((i + 1) / customPayloads.length) * 100;
        setProgress(newProgress);
      } catch (error) {
        addLog(`Error testing payload: ${payload}`);
        console.error("Fuzzing error:", error);
      }

      // Rate limiting - avoid overloading the server
      if (i < customPayloads.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }

    // Check if fuzzing is still active and component is mounted
    if (activeFuzzingRef.current && isMountedRef.current) {
      setIsFuzzing(false);
      activeFuzzingRef.current = false;
      
      // Dispatch scan complete event with final stats
      window.dispatchEvent(new CustomEvent('scanUpdate', {
        detail: {
          scanId,
          status: 'completed',
          vulnerabilities: scanStats.threatsDetected
        }
      }));
      
      window.dispatchEvent(new CustomEvent('scanComplete', {
        detail: {
          scanId,
          vulnerabilities: scanStats.threatsDetected,
          payloadsTested: scanStats.payloadsSent
        }
      }));
      
      addLog(`Scan #${scanId} completed successfully`);
      setCurrentScanId(null);
      toast({
        title: "Fuzzing Completed",
        description: `Scan complete with ${scanStats.threatsDetected} vulnerabilities detected`,
      });
    }
  };

  // Map DVWA modules to vulnerability types
  const moduleToVulnerabilityType = (module: string): string => {
    const mappings: Record<string, string> = {
      'exec': 'rce',
      'sqli': 'sqli',
      'xss_r': 'xss',
      'xss_s': 'xss',
      'upload': 'upload',
      'csrf': 'csrf'
    };
    return mappings[module] || 'unknown';
  };
  
  // Determine severity based on payload and vulnerability type
  const determineSeverity = (payload: string, module: string): string => {
    // Simplistic severity determination logic
    if (module === 'sqli' && payload.includes('DROP TABLE')) {
      return 'critical';
    }
    if ((module === 'xss_r' || module === 'xss_s') && payload.includes('<script>')) {
      return 'high';
    }
    if (module === 'exec' && (payload.includes('rm -rf') || payload.includes('format'))) {
      return 'critical';
    }
    
    // Default severity based on module
    const defaultSeverities: Record<string, string> = {
      'exec': 'high',
      'sqli': 'medium',
      'xss_r': 'medium',
      'xss_s': 'high',
      'upload': 'medium',
      'csrf': 'low'
    };
    
    return defaultSeverities[module] || 'medium';
  };

  const handleStopFuzzing = () => {
    // Update the active fuzzing ref first
    activeFuzzingRef.current = false;
    
    setIsFuzzing(false);
    addLog("Fuzzing process stopped by user.");
    toast({
      title: "Fuzzing Stopped",
      description: "The fuzzing process has been stopped",
    });
    
    // If there's an active scan, mark it as failed
    if (currentScanId) {
      window.dispatchEvent(new CustomEvent('scanUpdate', {
        detail: { 
          scanId: currentScanId,
          status: 'failed'
        }
      }));
      addLog(`Scan #${currentScanId} marked as failed`);
      setCurrentScanId(null);
    }
  };

  // Update the cleanup function to properly handle unmounting
  useEffect(() => {
    return () => {
      isMountedRef.current = false;
      activeFuzzingRef.current = false;
      setCustomPayloads([]);
    };
  }, []);

  return (
    <div className="space-y-6">
      <Card className="overflow-hidden border-emerald-900/20 bg-card/60 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>Web Application Fuzzer</CardTitle>
          <CardDescription>Configure and test fuzzing on web applications</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target-url">Target URL</Label>
            <div className="flex items-center space-x-2">
              <Link className="h-5 w-5 text-muted-foreground" />
              <Input 
                id="target-url" 
                placeholder="https://example.com" 
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={isFuzzing}
                className="flex-1"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="payload-set">Payload Set</Label>
              <Select 
                value={payloadSet} 
                onValueChange={setPayloadSet}
                disabled={isFuzzing}
              >
                <SelectTrigger id="payload-set">
                  <SelectValue placeholder="Select payload set" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">Default Payloads</SelectItem>
                  <SelectItem value="xss">XSS Specialized</SelectItem>
                  <SelectItem value="sqli">SQL Injection</SelectItem>
                  <SelectItem value="custom">Custom Payloads</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="fuzzing-mode">Fuzzing Mode</Label>
              <Select 
                value={fuzzingMode} 
                onValueChange={setFuzzingMode}
                disabled={isFuzzing}
              >
                <SelectTrigger id="fuzzing-mode">
                  <SelectValue placeholder="Select fuzzing mode" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="stealth">Stealth Mode</SelectItem>
                  <SelectItem value="aggressive">Aggressive</SelectItem>
                  <SelectItem value="thorough">Thorough Scan</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="module-select">DVWA Module</Label>
            <Select 
              value={module} 
              onValueChange={setModule}
              disabled={isFuzzing}
            >
              <SelectTrigger id="module-select">
                <SelectValue placeholder="Select DVWA module" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="exec">Command Injection</SelectItem>
                <SelectItem value="sqli">SQL Injection</SelectItem>
                <SelectItem value="xss_r">XSS Reflected</SelectItem>
                <SelectItem value="xss_s">XSS Stored</SelectItem>
                <SelectItem value="upload">File Upload</SelectItem>
                <SelectItem value="csrf">CSRF</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex justify-between items-center gap-4">
            {!isConnected ? (
              <Button 
                onClick={handleConnect} 
                variant="outline"
                disabled={isFuzzing}
                className="w-full"
              >
                Connect to DVWA
              </Button>
            ) : (
              <div className="flex items-center space-x-2 px-4 py-2 rounded-md bg-green-500/10 text-green-500 w-full">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                <span className="text-sm font-medium">Connected to DVWA</span>
              </div>
            )}
            
            <PayloadUploader onPayloadsUploaded={handlePayloadsUploaded} />
            
            <Button
              onClick={isFuzzing ? handleStopFuzzing : handleStartFuzzing}
              variant={isFuzzing ? "destructive" : "default"}
              disabled={!isConnected || !payloadsReady || customPayloads.length === 0}
              className="w-full"
            >
              {isFuzzing ? (
                <>
                  Stop Fuzzing
                  <Loader className="ml-2 h-4 w-4 animate-spin" />
                </>
              ) : (
                "Start Fuzzing"
              )}
            </Button>
          </div>

          {isFuzzing && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs">
                <span>Fuzzing Progress</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="col-span-1 bg-card/60 backdrop-blur-sm border-emerald-900/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center">
              <Zap className="h-4 w-4 mr-2" />
              Payloads Sent
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{scanStats.payloadsSent}</div>
          </CardContent>
        </Card>
        
        <Card className="col-span-1 bg-card/60 backdrop-blur-sm border-emerald-900/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center">
              <Shield className="h-4 w-4 mr-2" />
              Responses Received
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{scanStats.responsesReceived}</div>
          </CardContent>
        </Card>
        
        <Card className="col-span-1 bg-card/60 backdrop-blur-sm border-emerald-900/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center">
              <Bug className="h-4 w-4 mr-2" />
              Threats Detected
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-500">{scanStats.threatsDetected}</div>
          </CardContent>
        </Card>
      </div>

      <LiveLogs logs={logs} isActive={isFuzzing} />
    </div>
  );
};
