import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Link, Bug, Shield, Zap, Loader, Play, StopCircle } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { PayloadUploader } from '@/components/fuzzer/PayloadUploader';
import { LiveLogs } from '@/components/fuzzer/LiveLogs';
import { checkDVWAConnection, loginToDVWA } from '@/utils/dvwaFuzzer';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';
import { fuzzerApi } from '@/services/api';
import { useSocket } from '@/hooks/use-socket';

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
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  
  // Reference to track if component is mounted
  const isMountedRef = useRef(true);
  // Socket.IO hooks
  const { addEventListener, emitEvent, isConnected: socketConnected } = useSocket();

  // Log component mount status
  useEffect(() => {
    console.log('RealTimeFuzzing component mounted');
    
    // Set up cleanup on unmount
    return () => {
      console.log('RealTimeFuzzing component unmounted');
      isMountedRef.current = false;
      
      // Clean up any active fuzzing session
      if (currentSessionId && isFuzzing) {
        console.log('Cleaning up active fuzzing session on unmount:', currentSessionId);
        fuzzerApi.stopFuzzing(currentSessionId).catch(err => {
          console.error('Error stopping fuzzing on unmount:', err);
        });
      }
    };
  }, []);

  // Log current status for debugging
  useEffect(() => {
    console.log('Current fuzzing status:', {
      isFuzzing,
      currentSessionId,
      progress,
      payloadsReady,
      payloadCount: customPayloads.length,
      socketConnected
    });
  }, [isFuzzing, currentSessionId, progress, payloadsReady, customPayloads.length, socketConnected]);

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
    console.log(`Fuzzing Log: [${timestamp}] ${message}`);
  };

  const handlePayloadsUploaded = (payloads: string[]) => {
    setCustomPayloads(payloads);
    setPayloadsReady(true);
    addLog(`Loaded ${payloads.length} custom payloads`);
  };

  const handleConnect = async () => {
    addLog(`Attempting to connect to DVWA at ${url}`);
    
    try {
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
    } catch (error) {
      console.error('Error connecting to DVWA:', error);
      toast({
        title: "Connection Error",
        description: "An error occurred while connecting to DVWA",
        variant: "destructive",
      });
    }
  };

  // Socket.IO event listeners for fuzzing process
  useEffect(() => {
    if (!socketConnected) {
      console.log('Socket not connected, not setting up event listeners yet');
      return;
    }
    
    console.log('Setting up Socket.IO event listeners');
    
    // Listen for fuzzing progress updates
    const removeProgressListener = addEventListener<{ progress: number, sessionId: string }>('fuzzing_progress', (data) => {
      console.log('Socket fuzzing_progress received:', data);
      if (data.sessionId === currentSessionId) {
        setProgress(data.progress);
        
        // Update payloads sent based on progress (simulated)
        const totalPayloads = customPayloads.length;
        const completedPayloads = Math.floor((data.progress / 100) * totalPayloads);
        
        setScanStats(prev => ({
          ...prev,
          payloadsSent: completedPayloads,
          responsesReceived: completedPayloads
        }));
      }
    });
    
    // Listen for fuzzing completion
    const removeCompleteListener = addEventListener<{ sessionId: string, vulnerabilities: number }>('fuzzing_complete', (data) => {
      console.log('Socket fuzzing_complete received:', data);
      
      if (data.sessionId === currentSessionId) {
        setIsFuzzing(false);
        setProgress(100);
        
        // Update final stats
        setScanStats(prev => ({
          ...prev,
          threatsDetected: data.vulnerabilities || prev.threatsDetected
        }));
        
        addLog(`Fuzzing session ${data.sessionId} completed successfully`);
        
        // Dispatch scan complete event for other components
        window.dispatchEvent(new CustomEvent('scanComplete', {
          detail: {
            sessionId: data.sessionId,
            vulnerabilities: data.vulnerabilities,
            payloadsTested: scanStats.payloadsSent
          }
        }));
        
        toast({
          title: "Fuzzing Completed",
          description: `Scan complete with ${data.vulnerabilities} vulnerabilities detected`,
        });
        
        setCurrentSessionId(null);
      }
    });
    
    // Listen for fuzzing errors
    const removeErrorListener = addEventListener<{ message: string, sessionId: string }>('fuzzing_error', (data) => {
      console.error('Socket fuzzing_error received:', data);
      
      if (data.sessionId === currentSessionId) {
        setIsFuzzing(false);
        addLog(`ERROR: ${data.message}`);
        
        toast({
          title: "Fuzzing Error",
          description: data.message || "An error occurred during fuzzing",
          variant: "destructive",
        });
        
        setCurrentSessionId(null);
      }
    });
    
    // Listen for threat detection
    const removeThreatListener = addEventListener<{ payload: string, sessionId: string }>('threat_detected', (data) => {
      console.log('Socket threat_detected received:', data);
      
      if (data.sessionId === currentSessionId) {
        addLog(`⚠️ ALERT: Potential vulnerability detected with payload: ${data.payload}`);
        
        setScanStats(prev => ({
          ...prev,
          threatsDetected: prev.threatsDetected + 1
        }));
        
        // Dispatch threat detected event for other components
        window.dispatchEvent(new CustomEvent('threatDetected', {
          detail: { 
            payload: data.payload,
            sessionId: data.sessionId
          }
        }));
      }
    });
    
    return () => {
      // Clean up all listeners
      removeProgressListener();
      removeCompleteListener();
      removeErrorListener();
      removeThreatListener();
    };
  }, [addEventListener, currentSessionId, customPayloads.length, scanStats.payloadsSent, socketConnected]);

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

    // Reset states before starting
    setIsFuzzing(true);
    setProgress(0);
    setScanStats({
      payloadsSent: 0,
      responsesReceived: 0,
      threatsDetected: 0,
    });
    
    // Add initial log
    addLog("Starting new fuzzing session...");

    try {
      addLog("Creating fuzzing session...");
      
      // Create a fuzzing session on the server
      const sessionResponse = await fuzzerApi.createFuzzer(url, 'custom_wordlist.txt');
      
      console.log("Session response:", sessionResponse);
      
      // Check if session was created successfully
      if (!sessionResponse || !sessionResponse.session_id || !sessionResponse.success) {
        throw new Error(`Failed to create fuzzing session - ${sessionResponse?.message || 'No session ID returned'}`);
      }
      
      // Use session_id from the response
      const sessionId = sessionResponse.session_id;
      setCurrentSessionId(sessionId);
      
      addLog(`Created fuzzing session with ID: ${sessionId}`);
      
      try {
        // Upload custom payloads to the server
        addLog(`Uploading ${customPayloads.length} payloads to server...`);
        const uploadResponse = await fuzzerApi.uploadPayloads(sessionId, customPayloads);
        
        if (!uploadResponse || !uploadResponse.success) {
          throw new Error(`Failed to upload payloads: ${uploadResponse?.message || 'Unknown error'}`);
        }
        
        addLog(`Uploaded ${customPayloads.length} payloads to server successfully`);
        
        // Start the fuzzing process on the server - FIXED: Changed to use vulnerabilityType array directly
        // since server doesn't support setVulnerabilityTypes method
        addLog("Starting fuzzing process on server...");
        
        // Get the vulnerability type based on the selected module
        const vulnType = moduleToVulnerabilityType(module);
        
        const startResponse = await fuzzerApi.startFuzzing(
          sessionId, 
          // Pass vulnerability type without calling setVulnerabilityTypes on server
          vulnType ? [vulnType] : ['all'], 
          customPayloads // Pass payloads directly to ensure they're available to the server
        );
        
        if (!startResponse || !startResponse.success) {
          throw new Error(`Failed to start fuzzing: ${startResponse?.message || 'Unknown error'}`);
        }
        
        addLog(`Started fuzzing with mode: ${fuzzingMode}`);
        addLog(`Target module: ${module}`);
        
        // Dispatch scan start event
        window.dispatchEvent(new CustomEvent('scanStart', {
          detail: { 
            sessionId, 
            status: 'in-progress'
          }
        }));
        
        // Emit event to socket server that we're starting (optional, depends on your backend implementation)
        const emitSuccess = emitEvent('start_fuzzing', {
          sessionId,
          module,
          fuzzingMode,
          payloadCount: customPayloads.length
        });
        
        if (emitSuccess) {
          addLog("Notified server of fuzzing start via Socket.IO");
        } else {
          addLog("Warning: Could not notify server via Socket.IO - continue with HTTP API");
        }
        
        toast({
          title: "Fuzzing Started",
          description: `Starting fuzzing session with ${customPayloads.length} payloads`,
        });
      } catch (error: any) {
        // If we fail at uploading payloads or starting fuzzing, we should clean up
        addLog(`Error during fuzzing setup: ${error.message}`);
        
        if (sessionId) {
          try {
            await fuzzerApi.stopFuzzing(sessionId);
            addLog(`Cleaned up session ${sessionId} due to error`);
          } catch (cleanupError) {
            console.error('Error during session cleanup:', cleanupError);
          }
        }
        
        throw error; // Rethrow to be caught by outer catch block
      }
    } catch (error: any) {
      console.error('Error starting fuzzing:', error);
      setIsFuzzing(false);
      
      addLog(`Error starting fuzzing: ${error.message || "Unknown error"}`);
      
      toast({
        title: "Error Starting Fuzzing",
        description: error.message || "Failed to start fuzzing process",
        variant: "destructive",
      });
      
      setCurrentSessionId(null);
    }
  };

  const handleStopFuzzing = async () => {
    if (!currentSessionId) {
      setIsFuzzing(false);
      return;
    }
    
    try {
      addLog(`Stopping fuzzing session ${currentSessionId}...`);
      
      // Call the API to stop the fuzzing process
      await fuzzerApi.stopFuzzing(currentSessionId);
      
      addLog("Fuzzing process stopped by user");
      setIsFuzzing(false);
      
      // Dispatch scan stop event
      window.dispatchEvent(new CustomEvent('scanStop', {
        detail: { 
          sessionId: currentSessionId,
          status: 'stopped'
        }
      }));
      
      // Notify server via Socket.IO (optional)
      emitEvent('stop_fuzzing', { sessionId: currentSessionId });
      
      toast({
        title: "Fuzzing Stopped",
        description: "The fuzzing process has been stopped",
      });
      
      setCurrentSessionId(null);
    } catch (error: any) {
      console.error('Error stopping fuzzing:', error);
      addLog(`Error stopping fuzzing: ${error.message || "Unknown error"}`);
      
      toast({
        title: "Error Stopping Fuzzing",
        description: error.message || "Failed to stop fuzzing process",
        variant: "destructive",
      });
      
      // Force state reset even if API call failed
      setIsFuzzing(false);
      setCurrentSessionId(null);
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

  // Handle component cleanup on unmount
  useEffect(() => {
    return () => {
      isMountedRef.current = false;
      
      // If a fuzzing session is active when component unmounts, stop it
      if (currentSessionId && isFuzzing) {
        console.log('Cleaning up active fuzzing session on unmount:', currentSessionId);
        fuzzerApi.stopFuzzing(currentSessionId).catch(err => {
          console.error('Error stopping fuzzing on unmount:', err);
        });
      }
    };
  }, [currentSessionId, isFuzzing]);

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
                  <StopCircle className="ml-2 h-4 w-4" />
                </>
              ) : (
                <>
                  Start Fuzzing
                  <Play className="ml-2 h-4 w-4" />
                </>
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
