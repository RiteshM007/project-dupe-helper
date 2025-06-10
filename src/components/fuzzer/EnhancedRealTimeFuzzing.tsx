
import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "@/hooks/use-toast";
import { useDVWAConnection } from '@/context/DVWAConnectionContext';
import { useFuzzing } from '@/context/FuzzingContext';
import { fuzzerApi } from '@/services/api';
import { Upload, Link, Play, Square } from 'lucide-react';
import { PayloadUploader } from './PayloadUploader';

export const EnhancedRealTimeFuzzing: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState<string>('http://localhost:8080');
  const [payloadSet, setPayloadSet] = useState<string>('default');
  const [fuzzingMode, setFuzzingMode] = useState<string>('thorough');
  const [dvwaModule, setDvwaModule] = useState<string>('xss');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [customPayloads, setCustomPayloads] = useState<string[]>([]);
  const [backendConnected, setBackendConnected] = useState<boolean>(false);
  const { isConnected } = useDVWAConnection();
  const { setFuzzingResult } = useFuzzing();

  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Check backend connection on mount
  useEffect(() => {
    const checkBackendConnection = async () => {
      try {
        await fuzzerApi.checkHealth();
        setBackendConnected(true);
        console.log('EnhancedRealTimeFuzzing: Backend connection established');
      } catch (error) {
        setBackendConnected(false);
        console.error('EnhancedRealTimeFuzzing: Backend connection failed:', error);
      }
    };

    checkBackendConnection();
  }, []);

  const handleCustomPayloads = useCallback((payloads: string[]) => {
    setCustomPayloads(payloads);
    setPayloadSet('custom');
    console.log('EnhancedRealTimeFuzzing: Custom payloads loaded:', payloads.length);
  }, []);

  const connectToDVWA = useCallback(async () => {
    if (!backendConnected) {
      toast({
        title: "Backend Not Available",
        description: "Please ensure the Python backend server is running",
        variant: "destructive",
      });
      return;
    }

    try {
      // This will be handled by the existing DVWA connection logic
      toast({
        title: "Connecting to DVWA",
        description: "Establishing connection to DVWA server...",
      });
    } catch (error) {
      console.error('EnhancedRealTimeFuzzing: DVWA connection error:', error);
    }
  }, [backendConnected]);

  const startFuzzing = useCallback(async () => {
    console.log('EnhancedRealTimeFuzzing: === STARTING ENHANCED FUZZING SCAN ===');
    
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

    setIsScanning(true);
    
    try {
      // Create fuzzer session on backend
      console.log('EnhancedRealTimeFuzzing: Creating fuzzer session on backend...');
      const createResponse = await fuzzerApi.createFuzzer(targetUrl);
      
      if (!createResponse.success) {
        throw new Error(createResponse.error || 'Failed to create fuzzer session');
      }
      
      const sessionId = createResponse.session_id;
      setCurrentSessionId(sessionId);
      
      console.log('EnhancedRealTimeFuzzing: Backend session created:', sessionId);
      
      // Determine vulnerability types based on module selection
      const vulnTypes = dvwaModule === 'all' ? ['xss', 'sqli', 'lfi', 'rce'] : [dvwaModule];
      
      // Use custom payloads if available, otherwise use default
      const payloadsToUse = payloadSet === 'custom' && customPayloads.length > 0 
        ? customPayloads 
        : [`<script>alert('XSS')</script>`]; // Default payload
      
      // Dispatch scan start events
      const scanDetail = { 
        sessionId, 
        targetUrl,
        type: 'fuzzing',
        timestamp: new Date().toISOString(),
        vulnerabilityTypes: vulnTypes,
        payloadSet,
        fuzzingMode
      };
      
      window.dispatchEvent(new CustomEvent('scanStart', { detail: scanDetail }));
      window.dispatchEvent(new CustomEvent('fuzzingStarted', { detail: scanDetail }));
      
      // Start fuzzing on backend
      console.log('EnhancedRealTimeFuzzing: Starting fuzzing on backend...');
      const startResponse = await fuzzerApi.startFuzzing(sessionId, vulnTypes, payloadsToUse);
      
      if (startResponse.success) {
        console.log('EnhancedRealTimeFuzzing: Backend fuzzing started successfully');
        toast({
          title: "Fuzzing Started",
          description: `Real fuzzing scan initiated with ${vulnTypes.join(', ')} tests`,
        });
        
        // Start monitoring progress
        monitorFuzzingProgress(sessionId);
      } else {
        throw new Error(startResponse.error || 'Failed to start fuzzing');
      }
    } catch (error: any) {
      console.error('EnhancedRealTimeFuzzing: Error starting enhanced fuzzing:', error);
      toast({
        title: "Fuzzing Error",
        description: `Error starting fuzzing: ${error.message}`,
        variant: "destructive",
      });
      setIsScanning(false);
      setCurrentSessionId(null);
    }
  }, [targetUrl, payloadSet, fuzzingMode, dvwaModule, customPayloads, isScanning, backendConnected]);

  const monitorFuzzingProgress = (sessionId: string) => {
    console.log('EnhancedRealTimeFuzzing: Starting to monitor fuzzing progress...');
    
    progressIntervalRef.current = setInterval(async () => {
      try {
        const status = await fuzzerApi.getFuzzingStatus(sessionId);
        
        if (status.success) {
          // Dispatch progress events for other components
          window.dispatchEvent(new CustomEvent('fuzzing_progress', {
            detail: { 
              progress: status.progress || 0,
              session_id: sessionId,
              payloads_processed: status.payloads_processed || 0
            }
          }));
          
          // Check if scan is complete
          if (!status.active || status.progress >= 100) {
            console.log('EnhancedRealTimeFuzzing: Fuzzing completed, getting results...');
            completeScan(sessionId);
          }
        }
      } catch (error) {
        console.error('EnhancedRealTimeFuzzing: Error monitoring fuzzing progress:', error);
      }
    }, 2000);
  };

  const completeScan = useCallback(async (sessionId: string) => {
    console.log('EnhancedRealTimeFuzzing: === COMPLETING ENHANCED FUZZING SCAN ===');
    
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
      progressIntervalRef.current = null;
    }
    
    try {
      // Get final results from backend
      const results = await fuzzerApi.getFuzzingResults(sessionId);
      
      if (results.success) {
        const finalResults = results.results;
        setIsScanning(false);
        
        const scanResults = {
          sessionId,
          targetUrl,
          vulnerabilities: finalResults.vulnerabilitiesFound || 0,
          payloadsTested: finalResults.totalPayloads || 0,
          duration: `${Math.floor((Date.now() - Date.now()) / 1000)}s`,
          severity: finalResults.vulnerabilitiesFound > 3 ? 'critical' : 
                   finalResults.vulnerabilitiesFound > 1 ? 'high' : 
                   finalResults.vulnerabilitiesFound > 0 ? 'medium' : 'low',
          type: 'fuzzing',
          timestamp: new Date().toISOString(),
          status: 'completed',
          findings: finalResults.threats || [],
          payloadSet,
          fuzzingMode,
          dvwaModule
        };

        console.log('EnhancedRealTimeFuzzing: Enhanced scan completed with results:', scanResults);
        
        // Update global context immediately
        setFuzzingResult(scanResults);
        
        // Dispatch completion events with delay for proper propagation
        setTimeout(() => {
          window.dispatchEvent(new CustomEvent('scanComplete', { detail: scanResults }));
        }, 100);
        
        setTimeout(() => {
          window.dispatchEvent(new CustomEvent('globalScanComplete', { detail: scanResults }));
        }, 200);
        
        setTimeout(() => {
          window.dispatchEvent(new CustomEvent('fuzzingComplete', { detail: scanResults }));
        }, 300);
        
        toast({
          title: "Enhanced Fuzzing Complete!",
          description: `Found ${scanResults.vulnerabilities} vulnerabilities in ${scanResults.payloadsTested} payloads`,
        });
      }
    } catch (error: any) {
      console.error('EnhancedRealTimeFuzzing: Error completing scan:', error);
      toast({
        title: "Error Getting Results",
        description: `Failed to get scan results: ${error.message}`,
        variant: "destructive",
      });
    } finally {
      setTimeout(() => {
        setCurrentSessionId(null);
      }, 2000);
    }
  }, [targetUrl, payloadSet, fuzzingMode, dvwaModule, setFuzzingResult]);

  const stopFuzzing = useCallback(async () => {
    if (!isScanning || !currentSessionId) return;
    
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
      progressIntervalRef.current = null;
    }
    
    try {
      await fuzzerApi.stopFuzzing(currentSessionId);
      setIsScanning(false);
      
      window.dispatchEvent(new CustomEvent('scanStop', {
        detail: { sessionId: currentSessionId }
      }));
      
      toast({
        title: "Fuzzing Stopped",
        description: "Enhanced fuzzing scan has been stopped.",
      });
    } catch (error: any) {
      console.error('EnhancedRealTimeFuzzing: Error stopping fuzzing:', error);
    } finally {
      setCurrentSessionId(null);
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
    <div className="space-y-6">
      <Card className="bg-card/90 backdrop-blur-md border-blue-900/30">
        <CardHeader>
          <CardTitle className="text-2xl font-bold text-white">Web Application Fuzzer</CardTitle>
          <p className="text-gray-400">Configure and test fuzzing on web applications</p>
        </CardHeader>
        <CardContent className="space-y-6">
          {!backendConnected && (
            <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
              <p className="text-red-400 font-medium">Backend Server Not Connected</p>
              <p className="text-sm text-gray-400">Please ensure the Python backend server is running on port 5000</p>
            </div>
          )}
          
          <div className="space-y-4">
            <div>
              <Label htmlFor="targetUrl" className="text-white font-medium">Target URL</Label>
              <div className="relative mt-2">
                <Link className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  id="targetUrl"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="http://localhost:8080"
                  disabled={isScanning}
                  className="pl-10 bg-gray-800 border-gray-700 text-white"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label className="text-white font-medium">Payload Set</Label>
                <Select value={payloadSet} onValueChange={setPayloadSet} disabled={isScanning}>
                  <SelectTrigger className="bg-gray-800 border-gray-700 text-white">
                    <SelectValue placeholder="Select payload set" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="default">Default Wordlist</SelectItem>
                    <SelectItem value="custom">Custom Payloads</SelectItem>
                    <SelectItem value="extended">Extended Wordlist</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label className="text-white font-medium">Fuzzing Mode</Label>
                <Select value={fuzzingMode} onValueChange={setFuzzingMode} disabled={isScanning}>
                  <SelectTrigger className="bg-gray-800 border-gray-700 text-white">
                    <SelectValue placeholder="Select fuzzing mode" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">Quick Scan</SelectItem>
                    <SelectItem value="thorough">Thorough Scan</SelectItem>
                    <SelectItem value="deep">Deep Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label className="text-white font-medium">DVWA Module</Label>
              <Select value={dvwaModule} onValueChange={setDvwaModule} disabled={isScanning}>
                <SelectTrigger className="bg-gray-800 border-gray-700 text-white">
                  <SelectValue placeholder="Select DVWA module" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="xss">Cross-Site Scripting (XSS)</SelectItem>
                  <SelectItem value="sqli">SQL Injection</SelectItem>
                  <SelectItem value="lfi">Local File Inclusion</SelectItem>
                  <SelectItem value="rce">Remote Code Execution</SelectItem>
                  <SelectItem value="csrf">CSRF</SelectItem>
                  <SelectItem value="auth">Authentication Bypass</SelectItem>
                  <SelectItem value="all">All Modules</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex gap-4">
              <Button
                onClick={connectToDVWA}
                variant="outline"
                disabled={isConnected || isScanning}
                className="flex-1"
              >
                {isConnected ? 'Connected to DVWA' : 'Connect to DVWA'}
              </Button>
              
              <PayloadUploader onPayloadsUploaded={handleCustomPayloads} />
              
              <Button
                onClick={isScanning ? stopFuzzing : startFuzzing}
                size="lg"
                className={`flex-1 ${isScanning ? "bg-red-600 hover:bg-red-700" : "bg-purple-600 hover:bg-purple-700"}`}
                disabled={!backendConnected && !isScanning}
              >
                {isScanning ? (
                  <>
                    <Square className="mr-2 h-4 w-4" />
                    Stop Fuzzing
                  </>
                ) : (
                  <>
                    <Play className="mr-2 h-4 w-4" />
                    Start Fuzzing
                  </>
                )}
              </Button>
            </div>

            {payloadSet === 'custom' && customPayloads.length > 0 && (
              <div className="p-4 bg-green-900/20 border border-green-500/30 rounded-lg">
                <p className="text-green-400 font-medium">Custom Payloads Loaded</p>
                <p className="text-sm text-gray-400">{customPayloads.length} custom payloads ready for testing</p>
              </div>
            )}

            {currentSessionId && (
              <div className="p-4 bg-blue-900/20 border border-blue-500/30 rounded-lg">
                <p className="text-blue-400 font-medium">Active Session</p>
                <p className="text-sm text-gray-400 font-mono">{currentSessionId}</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
