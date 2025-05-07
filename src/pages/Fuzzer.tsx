
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
import { fuzzerApi } from '@/services/api';

const Fuzzer = () => {
  const { isConnected, setIsConnected, setDvwaUrl, setSessionCookie } = useDVWAConnection();
  const [statsData, setStatsData] = useState({
    requestsSent: 0,
    vulnerabilitiesFound: 0,
    successRate: 100
  });
  const [connecting, setConnecting] = useState(false);
  const [dvwaStatus, setDvwaStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const navigate = useNavigate();
  const { addEventListener, isConnected: socketConnected } = useSocket();
  const [progress, setProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [pollingInterval, setPollingInterval] = useState<number | null>(null);

  // Log component mount and current state
  useEffect(() => {
    console.log('Fuzzer page component mounted');
    console.log('Current state:', {
      isConnected,
      dvwaStatus,
      socketConnected,
      isScanning,
      sessionId,
      progress
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

      // Clear any polling interval
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, []);

  // Auto-connect to DVWA when the page loads
  useEffect(() => {
    const connectToDVWA = async () => {
      if (!isConnected && !connecting) {
        setConnecting(true);
        setDvwaStatus('checking');
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
              description: "DVWA server not reachable at http://localhost:8080. Please ensure DVWA is running.",
              variant: "destructive",
            });
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
              description: "Could not authenticate with DVWA using default credentials",
              variant: "destructive",
            });
          }
        } catch (error) {
          console.error('Error connecting to DVWA:', error);
          setDvwaStatus('offline');
          toast({
            title: "Connection Error",
            description: "An error occurred while connecting to DVWA",
            variant: "destructive",
          });
        } finally {
          setConnecting(false);
        }
      }
    };
    
    connectToDVWA();
  }, [isConnected, setIsConnected, setDvwaUrl, setSessionCookie]);

  // Set up polling for fuzzing status updates when scanning is active
  useEffect(() => {
    if (isScanning && sessionId) {
      // Start polling for status updates
      const intervalId = window.setInterval(async () => {
        try {
          const status = await fuzzerApi.getFuzzerStatus(sessionId);
          
          if (status && status.success) {
            // Update progress
            setProgress(status.progress);
            
            // Dispatch progress event for other components
            const progressEvent = new CustomEvent('fuzzing_progress', { 
              detail: { 
                progress: status.progress,
                sessionId: sessionId
              }
            });
            window.dispatchEvent(progressEvent);
            
            // Handle fuzzing completion
            if (status.progress === 100 && !status.active) {
              // Get dataset to count vulnerabilities
              const datasetResponse = await fuzzerApi.getDataset(sessionId);
              const vulnerabilitiesFound = datasetResponse?.dataset?.filter(
                (item: any) => item.is_vulnerability
              ).length || 0;
              
              // Dispatch completion event
              const completeEvent = new CustomEvent('fuzzing_complete', {
                detail: {
                  sessionId,
                  vulnerabilities: vulnerabilitiesFound
                }
              });
              window.dispatchEvent(completeEvent);
              
              // Clean up polling
              clearInterval(intervalId);
              setPollingInterval(null);
            }
          }
        } catch (error) {
          console.error('Error polling fuzzer status:', error);
          
          // Dispatch error event
          const errorEvent = new CustomEvent('fuzzing_error', {
            detail: {
              message: 'Failed to poll fuzzer status',
              sessionId
            }
          });
          window.dispatchEvent(errorEvent);
        }
      }, 1000); // Poll every second
      
      setPollingInterval(intervalId);
      
      // Clean up on unmount or when scanning stops
      return () => {
        clearInterval(intervalId);
        setPollingInterval(null);
      };
    }
  }, [isScanning, sessionId]);

  // Handle fuzzing progress updates from custom events
  useEffect(() => {
    const handleFuzzingProgress = (event: CustomEvent) => {
      console.log('Received fuzzing progress update:', event.detail);
      if (typeof event.detail?.progress === 'number') {
        setProgress(event.detail.progress);
      }
    };

    // Handle fuzzing completion
    const handleFuzzingComplete = (event: CustomEvent) => {
      console.log('Fuzzing complete:', event.detail);
      setIsScanning(false);
      setProgress(100);
      
      // Update stats with final data
      setStatsData(prev => ({
        ...prev,
        vulnerabilitiesFound: event.detail?.vulnerabilities || prev.vulnerabilitiesFound
      }));
      
      toast({
        title: "Fuzzing Complete",
        description: "Transitioning to ML Analysis",
      });
      
      // Navigate to ML Analysis after short delay
      setTimeout(() => {
        navigate('/ml-analysis');
      }, 1500);
    };

    // Handle fuzzing errors
    const handleFuzzingError = (event: CustomEvent) => {
      console.error('Fuzzing error:', event.detail);
      setIsScanning(false);
      
      toast({
        title: "Fuzzing Error",
        description: event.detail?.message || "An error occurred during fuzzing",
        variant: "destructive",
      });
    };
    
    // Add event listeners
    window.addEventListener('fuzzing_progress', handleFuzzingProgress as EventListener);
    window.addEventListener('fuzzing_complete', handleFuzzingComplete as EventListener);
    window.addEventListener('fuzzing_error', handleFuzzingError as EventListener);
    
    return () => {
      window.removeEventListener('fuzzing_progress', handleFuzzingProgress as EventListener);
      window.removeEventListener('fuzzing_complete', handleFuzzingComplete as EventListener);
      window.removeEventListener('fuzzing_error', handleFuzzingError as EventListener);
    };
  }, [navigate]);

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
        
        <div className="mb-4">
          {dvwaStatus === 'online' ? (
            <Badge className="bg-green-500 text-white">DVWA Connected</Badge>
          ) : dvwaStatus === 'offline' ? (
            <Badge className="bg-red-500 text-white">DVWA Offline</Badge>
          ) : (
            <Badge className="bg-yellow-500 text-white">Checking DVWA...</Badge>
          )}
          
          <Badge className="bg-blue-500 text-white ml-2">API Connected</Badge>
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
            onProgressUpdate={handleProgressUpdate}
          />
        </div>
        
        <RealTimeFuzzing />
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
