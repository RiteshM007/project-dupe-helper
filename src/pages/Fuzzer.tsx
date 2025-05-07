
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';
import { Grid, GridItem } from '@/components/ui/grid';
import { FuzzerStats } from '@/components/fuzzer/FuzzerStats';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';
import { checkDVWAConnection, loginToDVWA } from '@/utils/dvwaFuzzer';
import { toast } from '@/hooks/use-toast';
import { Badge } from '@/components/ui/badge';
import { useNavigate } from 'react-router-dom';
import { useSocket } from '@/hooks/use-socket';
import { ScanningStatus } from '@/components/fuzzer/ScanningStatus';
import { fuzzerApi, systemApi } from '@/services/api';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertCircle } from 'lucide-react';

const Fuzzer = () => {
  const { isConnected, setIsConnected, setDvwaUrl, setSessionCookie } = useDVWAConnection();
  const [statsData, setStatsData] = useState({
    requestsSent: 0,
    vulnerabilitiesFound: 0,
    successRate: 100
  });
  const [connecting, setConnecting] = useState(false);
  const [dvwaStatus, setDvwaStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [serverStatus, setServerStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const navigate = useNavigate();
  const { addEventListener, isConnected: socketConnected } = useSocket();
  const [progress, setProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  
  // Check if we're in a deployed environment
  const isDeployed = window.location.hostname.includes('lovable.app');

  // Log component mount and current state
  useEffect(() => {
    console.log('Fuzzer page component mounted');
    console.log('Current state:', {
      isConnected,
      dvwaStatus,
      serverStatus,
      socketConnected,
      isScanning,
      sessionId,
      progress,
      isDeployed
    });
    
    // Clean up on unmount
    return () => {
      console.log('Fuzzer page component unmounted');
      
      // If there's still an active session when component unmounts, stop it
      if (sessionId && isScanning) {
        console.log('Stopping fuzzing session on page unmount:', sessionId);
        fuzzerApi.stopFuzzing(sessionId).catch(err => {
          console.error('Error stopping fuzzing on unmount:', err);
        });
      }
    };
  }, []);

  // Check system server status
  useEffect(() => {
    const checkServerStatus = async () => {
      if (isDeployed) {
        // In deployed environment, we use mock APIs so server is always "online"
        setServerStatus('online');
        return;
      }
      
      setServerStatus('checking');
      try {
        const status = await systemApi.getStatus();
        setServerStatus('online');
        console.log('API server is online:', status);
      } catch (error) {
        console.error('API server is offline:', error);
        setServerStatus('offline');
        toast({
          title: "Server Unavailable",
          description: "The API server is not reachable. Using demo mode.",
          variant: "destructive",
        });
      }
    };
    
    checkServerStatus();
  }, [isDeployed]);

  // Auto-connect to DVWA when the page loads
  useEffect(() => {
    const connectToDVWA = async () => {
      if (!isConnected && !connecting) {
        setConnecting(true);
        setDvwaStatus('checking');
        
        // In deployed mode, or if server is offline, use demo mode
        if (isDeployed || serverStatus === 'offline') {
          console.log('Using demo mode for DVWA connection');
          setDvwaStatus('online');
          setIsConnected(true);
          setDvwaUrl('http://demo-dvwa.example.com');
          setSessionCookie('demo-cookie');
          toast({
            title: "Demo Mode Active",
            description: "Connected to demo DVWA environment",
          });
          setConnecting(false);
          return;
        }
        
        const dvwaServerUrl = 'http://localhost:8080';
        
        try {
          console.log('Attempting to connect to DVWA server at:', dvwaServerUrl);
          
          // Check if DVWA is reachable
          const isReachable = await checkDVWAConnection(dvwaServerUrl);
          
          if (!isReachable) {
            console.log('DVWA server not reachable');
            setDvwaStatus('offline');
            toast({
              title: "Connection Failed",
              description: "DVWA server not reachable at http://localhost:8080. Using demo mode.",
              variant: "destructive",
            });
            
            // Fall back to demo mode
            setDvwaStatus('online');
            setIsConnected(true);
            setDvwaUrl('http://demo-dvwa.example.com');
            setSessionCookie('demo-cookie');
            setConnecting(false);
            return;
          }
          
          setDvwaStatus('online');
          
          // Try to login with default credentials
          const loginResult = await loginToDVWA(dvwaServerUrl, 'admin', 'password');
          
          if (loginResult.success && loginResult.cookie) {
            setIsConnected(true);
            setDvwaUrl(dvwaServerUrl);
            setSessionCookie(loginResult.cookie);
            console.log('Successfully connected to DVWA');
            toast({
              title: "Connected to DVWA",
              description: "Successfully connected to DVWA server at http://localhost:8080",
            });
          } else {
            console.error('Failed to authenticate with DVWA');
            toast({
              title: "Login Failed",
              description: "Could not authenticate with DVWA using default credentials. Using demo mode.",
              variant: "destructive",
            });
            
            // Fall back to demo mode
            setIsConnected(true);
            setDvwaUrl('http://demo-dvwa.example.com');
            setSessionCookie('demo-cookie');
          }
        } catch (error) {
          console.error('Error connecting to DVWA:', error);
          setDvwaStatus('offline');
          toast({
            title: "Connection Error",
            description: "An error occurred while connecting to DVWA. Using demo mode.",
            variant: "destructive",
          });
          
          // Fall back to demo mode
          setIsConnected(true);
          setDvwaUrl('http://demo-dvwa.example.com');
          setSessionCookie('demo-cookie');
        } finally {
          setConnecting(false);
        }
      }
    };
    
    connectToDVWA();
  }, [isConnected, setIsConnected, setDvwaUrl, setSessionCookie, serverStatus, isDeployed]);

  // Handle fuzzing progress updates from Socket.IO
  useEffect(() => {
    if (!socketConnected) {
      console.log('Socket not connected, not setting up fuzzing progress listener');
      return;
    }
    
    console.log('Setting up fuzzing progress listener');
    
    const removeProgressListener = addEventListener<{ progress: number }>('fuzzing_progress', (data) => {
      console.log('Received fuzzing progress update from Socket.IO:', data);
      if (typeof data.progress === 'number') {
        setProgress(data.progress);
      }
    });

    // Handle fuzzing completion from Socket.IO
    const removeCompleteListener = addEventListener<{ sessionId: string, vulnerabilities: number }>('fuzzing_complete', (data) => {
      console.log('Fuzzing complete from Socket.IO:', data);
      setIsScanning(false);
      setProgress(100);
      
      // Update stats with final data
      setStatsData(prev => ({
        ...prev,
        vulnerabilitiesFound: data.vulnerabilities || prev.vulnerabilitiesFound
      }));
      
      toast({
        title: "Fuzzing Complete",
        description: "Transitioning to ML Analysis",
      });
      
      // Navigate to ML Analysis after short delay
      setTimeout(() => {
        navigate('/ml-analysis');
      }, 1500);
    });

    // Handle fuzzing errors from Socket.IO
    const removeErrorListener = addEventListener<{ message: string }>('fuzzing_error', (data) => {
      console.error('Fuzzing error from Socket.IO:', data);
      setIsScanning(false);
      
      toast({
        title: "Fuzzing Error",
        description: data.message || "An error occurred during fuzzing",
        variant: "destructive",
      });
    });
    
    return () => {
      removeProgressListener();
      removeCompleteListener();
      removeErrorListener();
    };
  }, [addEventListener, navigate, socketConnected]);

  // Handle external start/stop events (from RealTimeFuzzing component)
  useEffect(() => {
    const handleScanStart = (event: CustomEvent) => {
      console.log('Scan started event received', event.detail);
      setIsScanning(true);
      setProgress(0);
      setSessionId(event.detail?.sessionId || null);
      
      // Reset stats 
      setStatsData({
        requestsSent: 0,
        vulnerabilitiesFound: 0,
        successRate: 100
      });
    };
    
    const handleScanComplete = (event: CustomEvent) => {
      console.log('Scan completed event received', event.detail);
      setIsScanning(false);
      setProgress(100);
      setSessionId(null);
      
      // Update stats with final values
      const { vulnerabilities = 0, payloadsTested = 0 } = event.detail || {};
      setStatsData({
        requestsSent: payloadsTested,
        vulnerabilitiesFound: vulnerabilities,
        successRate: payloadsTested > 0 
          ? Math.round((1 - (vulnerabilities / payloadsTested)) * 100)
          : 100
      });
    };
    
    const handleScanStop = () => {
      console.log('Scan stopped event received');
      setIsScanning(false);
      
      // If we have an active session, attempt to stop it on the backend
      if (sessionId) {
        fuzzerApi.stopFuzzing(sessionId)
          .then(() => {
            console.log('Fuzzing stopped on server');
          })
          .catch(err => {
            console.error('Error stopping fuzzing on server:', err);
          })
          .finally(() => {
            setSessionId(null);
          });
      }
    };
    
    const handlePayloadSent = () => {
      setStatsData(prev => ({
        ...prev,
        requestsSent: prev.requestsSent + 1
      }));
    };
    
    const handleThreatDetected = () => {
      setStatsData(prev => {
        const newVulns = prev.vulnerabilitiesFound + 1;
        return {
          ...prev,
          vulnerabilitiesFound: newVulns,
          successRate: Math.max(70, 100 - (newVulns / prev.requestsSent * 100))
        };
      });
    };
    
    // Add event listeners with proper type casting
    window.addEventListener('scanStart', handleScanStart as EventListener);
    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    window.addEventListener('scanStop', handleScanStop);
    window.addEventListener('payloadSent', handlePayloadSent);
    window.addEventListener('threatDetected', handleThreatDetected as EventListener);
    
    return () => {
      // Clean up event listeners
      window.removeEventListener('scanStart', handleScanStart as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
      window.removeEventListener('scanStop', handleScanStop);
      window.removeEventListener('payloadSent', handlePayloadSent);
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
    };
  }, [sessionId]);

  // Function to handle progress updates from child components
  const handleProgressUpdate = (newProgress: number) => {
    console.log('Progress update received:', newProgress);
    setProgress(newProgress);
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-6">Web Application Fuzzer</h1>
        
        {isDeployed && (
          <Alert className="mb-4 bg-blue-500/10 text-blue-500 border-blue-500/20">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              Running in demo mode. No actual server connections will be made. All results are simulated.
            </AlertDescription>
          </Alert>
        )}
        
        {!isDeployed && serverStatus === 'offline' && (
          <Alert className="mb-4 bg-amber-500/10 text-amber-500 border-amber-500/20">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              API server is offline. Running in demo mode with simulated results.
            </AlertDescription>
          </Alert>
        )}
        
        <div className="mb-4 flex flex-wrap gap-2">
          {dvwaStatus === 'online' ? (
            <Badge className="bg-green-500 text-white">DVWA Connected</Badge>
          ) : dvwaStatus === 'offline' ? (
            <Badge className="bg-red-500 text-white">DVWA Offline</Badge>
          ) : (
            <Badge className="bg-yellow-500 text-white">Checking DVWA...</Badge>
          )}
          
          {socketConnected ? (
            <Badge className="bg-blue-500 text-white">Socket.IO Connected</Badge>
          ) : (
            <Badge className="bg-red-500 text-white">Socket.IO Offline</Badge>
          )}
          
          {serverStatus === 'online' ? (
            <Badge className="bg-green-500 text-white">API Server Online</Badge>
          ) : serverStatus === 'offline' ? (
            <Badge className="bg-red-500 text-white">API Server Offline</Badge>
          ) : (
            <Badge className="bg-yellow-500 text-white">Checking API Server...</Badge>
          )}
          
          {isDeployed && (
            <Badge className="bg-purple-500 text-white">Demo Mode</Badge>
          )}
        </div>
        
        <Grid cols={1} gap={6} className="mb-6">
          <GridItem className="w-full">
            <FuzzerStats data={statsData} />
          </GridItem>
        </Grid>
        
        {/* Display scanning status component */}
        <div className="mb-6">
          <ScanningStatus 
            isScanning={isScanning} 
            progress={progress} 
            onProgressUpdate={(newProgress) => setProgress(newProgress)}
          />
        </div>
        
        <RealTimeFuzzing />
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
