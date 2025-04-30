
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Grid, GridItem } from '@/components/ui/grid';
import { FuzzerStats } from '@/components/fuzzer/FuzzerStats';

const Fuzzer = () => {
  const [statsData, setStatsData] = useState({
    requestsSent: 0,
    vulnerabilitiesFound: 0,
    successRate: 100
  });

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
