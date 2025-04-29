
import React, { useState } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';
import { DVWAConnection } from '@/components/dashboard/DVWAConnection';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Grid, GridItem } from '@/components/ui/grid';
import { LiveThreats } from '@/components/dashboard/LiveThreats';

const Fuzzer = () => {
  const [activeScans, setActiveScans] = useState<{id: string, status: string}[]>([]);
  
  // Handler for scan status updates
  const handleScanUpdate = (scanId: string, status: string) => {
    setActiveScans(prev => {
      const existing = prev.findIndex(scan => scan.id === scanId);
      if (existing >= 0) {
        const updated = [...prev];
        updated[existing] = { ...updated[existing], status };
        return updated;
      } else if (status === 'in-progress') {
        return [...prev, { id: scanId, status }];
      }
      return prev;
    });
  };

  // Listen for scan updates
  React.useEffect(() => {
    const handleScanEvent = (event: CustomEvent) => {
      const { scanId, status } = event.detail;
      handleScanUpdate(scanId, status);
    };

    window.addEventListener('scanUpdate', handleScanEvent as EventListener);
    
    return () => {
      window.removeEventListener('scanUpdate', handleScanEvent as EventListener);
    };
  }, []);
  
  return (
    <DashboardLayout>
      <div className="container mx-auto p-4 space-y-6">
        <h1 className="text-2xl font-bold mb-2">Web Application Fuzzer</h1>
        
        <Grid cols={1} colsMd={3} gap={6} className="w-full">
          <GridItem span={1}>
            <DVWAConnection />
          </GridItem>
          <GridItem span={2}>
            <Card className="bg-card/50 backdrop-blur-sm border-emerald-900/20">
              <CardHeader>
                <CardTitle>Fuzzing Dashboard</CardTitle>
                <CardDescription>Monitor and control your fuzzing operations</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-sm text-muted-foreground mb-4">
                  Connect to DVWA and upload payloads to start fuzzing your target application.
                </div>
              </CardContent>
            </Card>
          </GridItem>
        </Grid>
        
        <Grid cols={1} colsMd={2} gap={6} className="w-full">
          <GridItem span={1}>
            <LiveThreats />
          </GridItem>
          <GridItem span={1}>
            <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5 h-full">
              <CardHeader>
                <CardTitle className="text-xl font-bold">Scan Status</CardTitle>
              </CardHeader>
              <CardContent>
                {activeScans.length > 0 ? (
                  <div className="space-y-3">
                    {activeScans.map(scan => (
                      <div key={scan.id} className="flex items-center justify-between p-2 bg-background/50 rounded-md">
                        <div>Scan #{scan.id}</div>
                        <div className={`text-sm px-2 py-1 rounded ${
                          scan.status === 'in-progress' 
                            ? 'bg-blue-500/20 text-blue-500' 
                            : scan.status === 'completed'
                            ? 'bg-green-500/20 text-green-500'
                            : 'bg-red-500/20 text-red-500'
                        }`}>
                          {scan.status}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground">
                    No active scans in progress.
                  </div>
                )}
              </CardContent>
            </Card>
          </GridItem>
        </Grid>
        
        <RealTimeFuzzing />
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
