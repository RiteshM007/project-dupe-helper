
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
  const [pollingInterval, setPollingInterval] = useState<number | null>(null);
  
  // Reference to track if component is mounted
  const isMountedRef = useRef(true);
  
  // Custom events from useSocket hook
  const { addEventListener, emitEvent } = useSocket();

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
      
      // Clear the polling interval if it exists
      if (pollingInterval) {
        clearInterval(pollingInterval);
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
      payloadCount: customPayloads.length
    });
  }, [isFuzzing, currentSessionId, progress, payloadsReady, customPayloads.length]);

  // Set up polling for status updates when actively fuzzing
  useEffect(() => {
    if (isFuzzing && currentSessionId) {
      // Start polling for status updates
      const intervalId = window.setInterval(async () => {
        if (!isMountedRef.current) {
          clearInterval(intervalId);
          return;
        }
        
        try {
          const response = await fuzzerApi.getFuzzerStatus(currentSessionId);
          
          if (response && response.success) {
            // Update progress
            setProgress(response.progress);
            
            // Update logs if available
            if (response.logs && response.logs.length > 0) {
              setLogs(prevLogs => {
                // Add only new logs that aren't already in the state
                const existingLogSet = new Set(prevLogs);
                const newLogs = response.logs.filter((log: string) => !existingLogSet.has(log));
                
                if (newLogs.length > 0) {
                  return [...prevLogs, ...newLogs];
                }
                return prevLogs;
              });
            }
            
            // Update payload stats
            setScanStats(prev => ({
              ...prev,
              payloadsSent: response.payloads_processed || prev.payloadsSent,
              responsesReceived: response.payloads_processed || prev.responsesReceived
            }));
            
            // Emit progress custom event
            const progressEvent = new CustomEvent('fuzzing_progress', {
              detail: {
                progress: response.progress,
                sessionId: currentSessionId
              }
            });
            window.dispatchEvent(progressEvent);
            
            // Handle completion
            if (!response.active && response.progress >= 100) {
              // Get dataset to count vulnerabilities
              const datasetResponse = await fuzzerApi.getDataset(currentSessionId);
              const vulnerabilities = datasetResponse?.dataset?.filter(
                (item: any) => item.is_vulnerability
              ).length || 0;
              
              // Dispatch completion event
              const completeEvent = new CustomEvent('fuzzing_complete', {
                detail: {
                  sessionId: currentSessionId,
                  vulnerabilities
                }
              });
              window.dispatchEvent(completeEvent);
              
              // Cleanup
              clearInterval(intervalId);
              setPollingInterval(null);
              setIsFuzzing(false);
              
              // Add completion log
              addLog(`Fuzzing session completed with ${vulnerabilities} vulnerabilities detected`);
              
              setScanStats(prev => ({
                ...prev,
                threatsDetected: vulnerabilities
              }));
            }
          }
        } catch (error) {
          console.error('Error polling fuzzer status:', error);
          
          // Allow a few failed attempts before showing an error
          addLog('Warning: Could not get status update from server');
        }
      }, 1000); // Poll every second
      
      setPollingInterval(intervalId);
      
      return () => {
        clearInterval(intervalId);
        setPollingInterval(null);
      };
    }
  }, [isFuzzing, currentSessionId]);

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

  // Set up event listeners for custom events
  useEffect(() => {
    // Handle fuzzing progress updates
    const handleFuzzingProgress = (event: CustomEvent) => {
      console.log('Custom event fuzzing_progress received:', event.detail);
      if (event.detail.sessionId === currentSessionId) {
        setProgress(event.detail.progress);
        
        // Update payloads sent based on progress (simulated)
        const totalPayloads = customPayloads.length;
        const completedPayloads = Math.floor((event.detail.progress / 100) * totalPayloads);
        
        setScanStats(prev => ({
          ...prev,
          payloadsSent: completedPayloads,
          responsesReceived: completedPayloads
        }));
      }
    };
    
    // Handle fuzzing completion
    const handleFuzzingComplete = (event: CustomEvent) => {
      console.log('Custom event fuzzing_complete received:', event.detail);
      
      if (event.detail.sessionId === currentSessionId) {
        setIsFuzzing(false);
        setProgress(100);
        
        // Update final stats
        setScanStats(prev => ({
          ...prev,
          threatsDetected: event.detail.vulnerabilities || prev.threatsDetected
        }));
        
        addLog(`Fuzzing session ${event.detail.sessionId} completed successfully`);
        
        // Dispatch scan complete event for other components
        window.dispatchEvent(new CustomEvent('scanComplete', {
          detail: {
            sessionId: event.detail.sessionId,
            vulnerabilities: event.detail.vulnerabilities,
            payloadsTested: scanStats.payloadsSent
          }
        }));
        
        toast({
          title: "Fuzzing Completed",
          description: `Scan complete with ${event.detail.vulnerabilities} vulnerabilities detected`,
        });
        
        setCurrentSessionId(null);
      }
    };
    
    // Handle fuzzing errors
    const handleFuzzingError = (event: CustomEvent) => {
      console.error('Custom event fuzzing_error received:', event.detail);
      
      if (event.detail.sessionId === currentSessionId) {
        setIsFuzzing(false);
        addLog(`ERROR: ${event.detail.message}`);
        
        toast({
          title: "Fuzzing Error",
          description: event.detail.message || "An error occurred during fuzzing",
          variant: "destructive",
        });
        
        setCurrentSessionId(null);
      }
    };
    
    // Handle threat detection
    const handleThreatDetected = (event: CustomEvent) => {
      console.log('Custom event threat_detected received:', event.detail);
      
      if (event.detail.sessionId === currentSessionId) {
        addLog(`⚠️ ALERT: Potential vulnerability detected with payload: ${event.detail.payload}`);
        
        setScanStats(prev => ({
          ...prev,
          threatsDetected: prev.threatsDetected + 1
        }));
        
        // Dispatch threat detected event for other components
        window.dispatchEvent(new CustomEvent('threatDetected', {
          detail: { 
            payload: event.detail.payload,
            sessionId: event.detail.sessionId
          }
        }));
      }
    };
    
    // Add event listeners
    window.addEventListener('fuzzing_progress', handleFuzzingProgress as EventListener);
    window.addEventListener('fuzzing_complete', handleFuzzingComplete as EventListener);
    window.addEventListener('fuzzing_error', handleFuzzingError as EventListener);
    window.addEventListener('threat_detected', handleThreatDetected as EventListener);
    
    return () => {
      // Clean up all listeners
      window.removeEventListener('fuzzing_progress', handleFuzzingProgress as EventListener);
      window.removeEventListener('fuzzing_complete', handleFuzzingComplete as EventListener);
      window.removeEventListener('fuzzing_error', handleFuzzingError as EventListener);
      window.removeEventListener('threat_detected', handleThreatDetected as EventListener);
    };
  }, [currentSessionId, customPayloads.length, scanStats.payloadsSent]);

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
        
        // Start the fuzzing process on the server
        addLog("Starting fuzzing process on server...");
        const startResponse = await fuzzerApi.startFuzzing(sessionId, [moduleToVulnerabilityType(module)], []);
        
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
        
        // Emit custom event
        emitEvent('start_fuzzing', {
          sessionId,
          module,
          fuzzingMode,
          payloadCount: customPayloads.length
        });
        
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
      
      // Emit custom event
      emitEvent('stop_fuzzing', { sessionId: currentSessionId });
      
      toast({
        title: "Fuzzing Stopped",
        description: "The fuzzing process has been stopped",
      });
      
      setCurrentSessionId(null);
      
      // Clear any polling interval
      if (pollingInterval) {
        clearInterval(pollingInterval);
        setPollingInterval(null);
      }
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
      
      // Clear any polling interval
      if (pollingInterval) {
        clearInterval(pollingInterval);
        setPollingInterval(null);
      }
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
      
      // Clear any polling interval
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, [currentSessionId, isFuzzing, pollingInterval]);

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
