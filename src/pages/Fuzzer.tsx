
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { EnhancedRealTimeFuzzing } from '@/components/fuzzer/EnhancedRealTimeFuzzing';
import { Grid, GridItem } from '@/components/ui/grid';
import { FuzzerStats } from '@/components/fuzzer/FuzzerStats';
import { LiveLogs } from '@/components/fuzzer/LiveLogs';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';
import { useFuzzing } from '@/context/FuzzingContext';
import { checkDVWAConnection, loginToDVWA } from '@/utils/dvwaFuzzer';
import { toast } from '@/hooks/use-toast';
import { Badge } from '@/components/ui/badge';
import { useSocket } from '@/hooks/use-socket';
import { ScanningStatus } from '@/components/fuzzer/ScanningStatus';
import { fuzzerApi } from '@/services/api';

const Fuzzer = () => {
  const { isConnected, setIsConnected, setDvwaUrl, setSessionCookie } = useDVWAConnection();
  const { fuzzingResult } = useFuzzing();
  const [statsData, setStatsData] = useState({
    requestsSent: 0,
    vulnerabilitiesFound: 0,
    successRate: 100
  });
  const [connecting, setConnecting] = useState(false);
  const [dvwaStatus, setDvwaStatus] = useState<'online' | 'offline' | 'checking' | 'simulation'>('checking');
  const [backendStatus, setBackendStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const { isConnected: socketConnected } = useSocket();
  const [progress, setProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  // Update stats based on fuzzing result
  useEffect(() => {
    if (fuzzingResult) {
      setStatsData({
        requestsSent: fuzzingResult.payloadsTested || 0,
        vulnerabilitiesFound: fuzzingResult.vulnerabilities || 0,
        successRate: fuzzingResult.payloadsTested > 0 
          ? Math.round((1 - (fuzzingResult.vulnerabilities / fuzzingResult.payloadsTested)) * 100)
          : 100
      });
      console.log('Fuzzer: Updated stats from fuzzing result:', fuzzingResult);
    }
  }, [fuzzingResult]);

  // Check backend connection on mount
  useEffect(() => {
    const checkBackend = async () => {
      try {
        setBackendStatus('checking');
        await fuzzerApi.checkHealth();
        setBackendStatus('online');
        console.log('Backend server is online');
      } catch (error) {
        setBackendStatus('offline');
        console.error('Backend server is offline:', error);
        toast({
          title: "Backend Server Offline",
          description: "Please start the Python backend server on port 5000",
          variant: "destructive",
        });
      }
    };

    checkBackend();
  }, []);

  // Auto-connect to DVWA when the page loads (only if backend is online)
  useEffect(() => {
    const connectToDVWA = async () => {
      if (!isConnected && !connecting && backendStatus === 'online') {
        setConnecting(true);
        setDvwaStatus('checking');
        const dvwaServerUrl = 'http://localhost:8080';
        
        try {
          console.log('Attempting to connect to DVWA server via backend:', dvwaServerUrl);
          
          // Use backend API to check and connect to DVWA
          const isReachable = await checkDVWAConnection(dvwaServerUrl);
          
          if (!isReachable) {
            console.log('DVWA server not reachable via backend');
            setDvwaStatus('offline');
            toast({
              title: "DVWA Server Offline",
              description: "DVWA server at localhost:8080 is not accessible. Please ensure DVWA is running.",
              variant: "destructive",
            });
            setConnecting(false);
            return;
          }
          
          setDvwaStatus('online');
          
          const loginResult = await loginToDVWA(dvwaServerUrl, 'admin', 'password');
          
          if (loginResult.success && loginResult.cookie) {
            setIsConnected(true);
            setDvwaUrl(dvwaServerUrl);
            setSessionCookie(loginResult.cookie);
            console.log('Successfully connected to DVWA via backend');
            toast({
              title: "Connected to DVWA",
              description: "Successfully connected to DVWA server via backend",
            });
          } else {
            setDvwaStatus('offline');
            toast({
              title: "DVWA Login Failed",
              description: "Failed to login to DVWA. Check credentials and server status.",
              variant: "destructive",
            });
          }
        } catch (error) {
          console.error('Error connecting to DVWA via backend:', error);
          setDvwaStatus('offline');
          toast({
            title: "DVWA Connection Error",
            description: "Error connecting to DVWA via backend",
            variant: "destructive",
          });
        } finally {
          setConnecting(false);
        }
      }
    };
    
    if (backendStatus === 'online') {
      connectToDVWA();
    }
  }, [isConnected, setIsConnected, setDvwaUrl, setSessionCookie, backendStatus]);

  // Handle scan events
  useEffect(() => {
    const handleScanStart = (event: CustomEvent) => {
      console.log('Fuzzer: Scan started event received', event.detail);
      setIsScanning(true);
      setProgress(0);
      setSessionId(event.detail?.sessionId || null);
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Scan started: ${event.detail?.sessionId}`]);
    };
    
    const handleScanComplete = (event: CustomEvent) => {
      console.log('Fuzzer: Scan completed event received', event.detail);
      setIsScanning(false);
      setProgress(100);
      setSessionId(null);
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Scan completed: ${event.detail?.vulnerabilities} vulnerabilities found`]);
    };

    const handleFuzzingProgress = (event: CustomEvent) => {
      const progressValue = event.detail?.progress || 0;
      setProgress(progressValue);
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Progress: ${progressValue}%`]);
    };

    const handleThreatDetected = (event: CustomEvent) => {
      console.log('Fuzzer: Threat detected', event.detail);
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ALERT: Threat detected - ${event.detail?.type || 'Unknown'}`]);
      
      setStatsData(prev => {
        const newVulns = prev.vulnerabilitiesFound + 1;
        return {
          ...prev,
          vulnerabilitiesFound: newVulns,
          successRate: Math.max(70, 100 - (newVulns / prev.requestsSent * 100))
        };
      });
    };
    
    // Add event listeners
    window.addEventListener('scanStart', handleScanStart as EventListener);
    window.addEventListener('fuzzingStarted', handleScanStart as EventListener);
    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    window.addEventListener('fuzzingComplete', handleScanComplete as EventListener);
    window.addEventListener('fuzzing_progress', handleFuzzingProgress as EventListener);
    window.addEventListener('threatDetected', handleThreatDetected as EventListener);
    window.addEventListener('globalThreatDetected', handleThreatDetected as EventListener);
    
    return () => {
      window.removeEventListener('scanStart', handleScanStart as EventListener);
      window.removeEventListener('fuzzingStarted', handleScanStart as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
      window.removeEventListener('fuzzingComplete', handleScanComplete as EventListener);
      window.removeEventListener('fuzzing_progress', handleFuzzingProgress as EventListener);
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
      window.removeEventListener('globalThreatDetected', handleThreatDetected as EventListener);
    };
  }, []);

  const handleProgressUpdate = (newProgress: number) => {
    setProgress(newProgress);
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-4 space-y-6">
        <div className="mb-4 flex gap-2">
          {socketConnected && (
            <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
              Socket.IO Connected
            </Badge>
          )}
          {backendStatus === 'online' && (
            <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
              Backend Connected
            </Badge>
          )}
          {backendStatus === 'offline' && (
            <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
              Backend Offline
            </Badge>
          )}
          {dvwaStatus === 'online' && (
            <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
              DVWA Connected
            </Badge>
          )}
          {dvwaStatus === 'offline' && (
            <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
              DVWA Offline
            </Badge>
          )}
        </div>

        {backendStatus === 'offline' && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
            <h3 className="font-medium text-red-400 mb-2">Backend Server Required</h3>
            <p className="text-sm text-gray-400 mb-2">
              The Python backend server is required for real fuzzing operations.
            </p>
            <p className="text-sm text-gray-400">
              Please start the server by running: <code className="bg-gray-800 px-2 py-1 rounded">python server/app.py</code>
            </p>
          </div>
        )}
        
        <Grid cols={1} gap={6} className="mb-6">
          <GridItem className="w-full">
            <FuzzerStats data={statsData} />
          </GridItem>
        </Grid>
        
        <div className="mb-6">
          <ScanningStatus 
            isScanning={isScanning} 
            progress={progress} 
            onProgressUpdate={handleProgressUpdate}
          />
        </div>
        
        <EnhancedRealTimeFuzzing />
        
        <LiveLogs logs={logs} isActive={isScanning} />
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
