
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { format } from 'date-fns';

interface ScanEntry {
  id: string;
  timestamp: Date;
  status: 'completed' | 'in-progress' | 'failed';
  vulnerabilities?: number;
}

export const LiveScans = () => {
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [pendingScan, setPendingScan] = useState<ScanEntry | null>(null);

  useEffect(() => {
    // Initialize with existing scans from storage if available
    const storedScans = localStorage.getItem('recent_scans');
    if (storedScans) {
      try {
        const parsedScans = JSON.parse(storedScans).map((scan: any) => ({
          ...scan,
          timestamp: new Date(scan.timestamp)
        }));
        setScans(parsedScans);
      } catch (error) {
        console.error("Error parsing stored scans:", error);
      }
    }

    // Handle scan updates - but only display completed scans
    const handleScanStart = (event: CustomEvent) => {
      const { scanId } = event.detail;
      setPendingScan({
        id: scanId || Math.random().toString(36).substr(2, 9),
        timestamp: new Date(),
        status: 'in-progress',
      });
    };

    const handleScanProgress = (event: CustomEvent) => {
      // Don't update UI for progress events
    };

    const handleScanComplete = (event: CustomEvent) => {
      const { scanId, vulnerabilities = 0 } = event.detail;

      // Update the scan list with the completed scan
      if (pendingScan && pendingScan.id === scanId) {
        const completedScan = {
          ...pendingScan,
          status: 'completed',
          vulnerabilities
        };
        
        setScans(prev => {
          const updated = [completedScan, ...prev].slice(0, 10);
          localStorage.setItem('recent_scans', JSON.stringify(updated));
          return updated;
        });
        
        setPendingScan(null);
      } else if (scanId) {
        // Handle case where we don't have a pending scan but received a complete event
        const newScan = {
          id: scanId,
          timestamp: new Date(),
          status: 'completed' as const,
          vulnerabilities
        };
        
        setScans(prev => {
          const updated = [newScan, ...prev].slice(0, 10);
          localStorage.setItem('recent_scans', JSON.stringify(updated));
          return updated;
        });
      }
    };
    
    const handleScanStop = () => {
      if (pendingScan) {
        const failedScan = {
          ...pendingScan,
          status: 'failed' as const
        };
        
        setScans(prev => {
          const updated = [failedScan, ...prev].slice(0, 10);
          localStorage.setItem('recent_scans', JSON.stringify(updated));
          return updated;
        });
        
        setPendingScan(null);
      }
    };

    window.addEventListener('scanStart', handleScanStart as EventListener);
    window.addEventListener('scanProgress', handleScanProgress as EventListener);
    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    window.addEventListener('scanStop', handleScanStop as EventListener);
    
    return () => {
      window.removeEventListener('scanStart', handleScanStart as EventListener);
      window.removeEventListener('scanProgress', handleScanProgress as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
      window.removeEventListener('scanStop', handleScanStop as EventListener);
    };
  }, [pendingScan]);

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-emerald-900/30 shadow-lg shadow-emerald-500/5">
      <CardHeader>
        <CardTitle className="text-xl font-bold">Recent Scans</CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[200px] w-full rounded-md">
          {pendingScan && (
            <div
              className="flex items-center justify-between p-4 border-b border-border/50 animate-pulse"
            >
              <div className="flex items-center space-x-4">
                <div className="flex flex-col">
                  <span className="font-medium">
                    Scan #{pendingScan.id}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    {format(pendingScan.timestamp, 'MMM dd, yyyy HH:mm:ss')}
                  </span>
                </div>
              </div>
              <div className="text-right">
                <span className="text-sm font-medium text-blue-500">
                  in-progress
                </span>
              </div>
            </div>
          )}
          
          {scans.length === 0 && !pendingScan ? (
            <div className="flex h-full items-center justify-center text-muted-foreground">
              No recent scans
            </div>
          ) : (
            scans.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between p-4 border-b border-border/50 animate-in slide-in-from-right duration-300"
              >
                <div className="flex items-center space-x-4">
                  <div className="flex flex-col">
                    <span className="font-medium">
                      Scan #{scan.id}
                    </span>
                    <span className="text-sm text-muted-foreground">
                      {format(scan.timestamp, 'MMM dd, yyyy HH:mm:ss')}
                    </span>
                  </div>
                </div>
                <div className="text-right">
                  <span className={`text-sm font-medium ${
                    scan.status === 'completed' ? 'text-emerald-500' :
                    scan.status === 'in-progress' ? 'text-blue-500' :
                    'text-destructive'
                  }`}>
                    {scan.status}
                  </span>
                  {scan.vulnerabilities !== undefined && scan.status === 'completed' && (
                    <p className="text-xs text-muted-foreground">
                      {scan.vulnerabilities} vulnerabilities found
                    </p>
                  )}
                </div>
              </div>
            ))
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
