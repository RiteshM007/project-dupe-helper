
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Grid, GridItem } from '@/components/ui/grid';
import { FuzzerStats } from '@/components/fuzzer/FuzzerStats';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';
import { checkDVWAConnection, loginToDVWA } from '@/utils/dvwaFuzzer';
import { toast } from '@/hooks/use-toast';
import { Badge } from '@/components/ui/badge';

const Fuzzer = () => {
  const { isConnected, setIsConnected, setDvwaUrl, setSessionCookie } = useDVWAConnection();
  const [statsData, setStatsData] = useState({
    requestsSent: 0,
    vulnerabilitiesFound: 0,
    successRate: 100
  });
  const [connecting, setConnecting] = useState(false);
  const [dvwaStatus, setDvwaStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  // Auto-connect to DVWA when the page loads
  useEffect(() => {
    const connectToDVWA = async () => {
      if (!isConnected && !connecting) {
        setConnecting(true);
        setDvwaStatus('checking');
        const dvwaServerUrl = 'http://localhost:8080';
        
        try {
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
            toast({
              title: "Connected to DVWA",
              description: "Successfully connected to DVWA server at http://localhost:8080",
            });
          } else {
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

  useEffect(() => {
    // Define a polling interval to update stats
    let requestsInterval: ReturnType<typeof setInterval>;
    
    // Handle scan start
    const handleScanStart = () => {
      // Reset stats
      setStatsData({
        requestsSent: 0,
        vulnerabilitiesFound: 0,
        successRate: 100
      });
      
      // Start polling for updates during scanning
      let requests = 0;
      let vulnerabilities = 0;
      
      requestsInterval = setInterval(() => {
        // Simulate increases in requests and occasionally vulnerabilities
        const newRequests = Math.floor(Math.random() * 5) + 1;
        requests += newRequests;
        
        // Occasionally find a vulnerability
        if (Math.random() > 0.85) {
          vulnerabilities += 1;
        }
        
        // Calculate success rate (inverse of vulnerability ratio)
        const successRate = requests > 0 
          ? Math.max(70, 100 - (vulnerabilities / requests * 100)) 
          : 100;
        
        setStatsData({
          requestsSent: requests,
          vulnerabilitiesFound: vulnerabilities,
          successRate: Math.round(successRate * 10) / 10
        });
      }, 1000);
    };
    
    // Handle scan complete
    const handleScanComplete = (event: CustomEvent) => {
      // Stop the polling interval
      if (requestsInterval) {
        clearInterval(requestsInterval);
      }
      
      // Get vulnerabilities from the event if available
      const { vulnerabilities } = event.detail || { vulnerabilities: 0 };
      
      // Update with final statistics including any reported vulnerabilities
      setStatsData(prev => ({
        ...prev,
        vulnerabilitiesFound: prev.vulnerabilitiesFound + (vulnerabilities || 0),
        successRate: Math.round((1 - (prev.vulnerabilitiesFound + (vulnerabilities || 0)) / prev.requestsSent) * 1000) / 10
      }));
    };
    
    // Handle scan stop
    const handleScanStop = () => {
      // Stop the polling interval
      if (requestsInterval) {
        clearInterval(requestsInterval);
      }
    };
    
    // Add event listeners
    window.addEventListener('scanStart', handleScanStart);
    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    window.addEventListener('scanStop', handleScanStop);
    
    return () => {
      // Clean up event listeners
      window.removeEventListener('scanStart', handleScanStart);
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
      window.removeEventListener('scanStop', handleScanStop);
      
      // Clear the interval if it exists
      if (requestsInterval) {
        clearInterval(requestsInterval);
      }
    };
  }, []);

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
        </div>
        
        <Grid cols={1} gap={6} className="mb-6">
          <GridItem className="w-full">
            <FuzzerStats data={statsData} />
          </GridItem>
        </Grid>
        
        <RealTimeFuzzing />
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
