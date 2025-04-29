
import React from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';
import { Grid, GridItem } from '@/components/ui/grid';
import { LiveThreats } from '@/components/dashboard/LiveThreats';
import { ScanningStatus } from '@/components/fuzzer/ScanningStatus';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const Fuzzer = () => {
  const [isScanning, setIsScanning] = React.useState(false);
  const [scanProgress, setScanProgress] = React.useState(0);

  // Listen for scan status changes
  React.useEffect(() => {
    const handleScanStart = () => {
      setIsScanning(true);
      setScanProgress(0);
    };
    
    const handleScanUpdate = (e: Event) => {
      const event = e as CustomEvent;
      if (event.detail && event.detail.progress) {
        setScanProgress(event.detail.progress);
      }
    };
    
    const handleScanComplete = () => {
      setIsScanning(false);
      setScanProgress(100);
      
      // Reset progress after a few seconds
      setTimeout(() => {
        setScanProgress(0);
      }, 5000);
    };
    
    const handleScanStop = () => {
      setIsScanning(false);
    };

    // Add event listeners
    window.addEventListener('scanStart', handleScanStart);
    window.addEventListener('scanProgress', handleScanUpdate);
    window.addEventListener('scanComplete', handleScanComplete);
    window.addEventListener('scanStop', handleScanStop);

    return () => {
      // Remove event listeners
      window.removeEventListener('scanStart', handleScanStart);
      window.removeEventListener('scanProgress', handleScanUpdate);
      window.removeEventListener('scanComplete', handleScanComplete);
      window.removeEventListener('scanStop', handleScanStop);
    };
  }, []);

  return (
    <DashboardLayout>
      <div className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-6">Web Application Fuzzer</h1>
        
        <Grid cols={1} colsMd={3} gap={6} className="mb-6">
          <GridItem span={2}>
            <Card>
              <CardHeader>
                <CardTitle>Fuzzing Status</CardTitle>
              </CardHeader>
              <CardContent>
                <ScanningStatus isScanning={isScanning} progress={scanProgress} />
              </CardContent>
            </Card>
          </GridItem>
          <GridItem span={1}>
            <LiveThreats />
          </GridItem>
        </Grid>
        
        <RealTimeFuzzing />
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
