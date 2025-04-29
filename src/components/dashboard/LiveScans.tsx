
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

    // Handle scan updates - but only trigger UI updates on status changes
    const handleScanUpdate = (event: CustomEvent) => {
      console.log('Scan update received:', event.detail);
      
      const { scanId, status, vulnerabilities } = event.detail;
      
      setScans(prev => {
        // Check if there is already a scan with this ID
        const existingScanIndex = prev.findIndex(s => s.id === scanId);
        
        if (existingScanIndex >= 0) {
          // Only update if status has changed
          if (prev[existingScanIndex].status !== status) {
            const updatedScans = [...prev];
            updatedScans[existingScanIndex] = { 
              ...updatedScans[existingScanIndex], 
              status, 
              vulnerabilities: status === 'completed' ? vulnerabilities : prev[existingScanIndex].vulnerabilities 
            };
            
            // Store in localStorage
            localStorage.setItem('recent_scans', JSON.stringify(updatedScans));
            return updatedScans;
          }
          return prev;
        } else if (status === 'in-progress') {
          // Add new scan
          const newScan = {
            id: scanId,
            timestamp: new Date(),
            status,
            vulnerabilities: 0
          };
          const updated = [newScan, ...prev].slice(0, 10);
          localStorage.setItem('recent_scans', JSON.stringify(updated));
          return updated;
        }
        
        return prev;
      });
    };

    window.addEventListener('scanUpdate', handleScanUpdate as EventListener);
    
    // Add a manual scan update event after component mounts
    setTimeout(() => {
      const scanId = Math.random().toString(36).substr(2, 9);
      
      // Start scan
      const startEvent = new CustomEvent('scanUpdate', {
        detail: {
          scanId,
          status: 'in-progress'
        }
      });
      window.dispatchEvent(startEvent);
      
      // Complete scan after a delay
      setTimeout(() => {
        const completeEvent = new CustomEvent('scanUpdate', {
          detail: {
            scanId,
            status: 'completed',
            vulnerabilities: Math.floor(Math.random() * 5) + 1
          }
        });
        window.dispatchEvent(completeEvent);
      }, 3000);
    }, 1000);
    
    return () => window.removeEventListener('scanUpdate', handleScanUpdate as EventListener);
  }, []);

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-emerald-900/30 shadow-lg shadow-emerald-500/5">
      <CardHeader>
        <CardTitle className="text-xl font-bold">Recent Scans</CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[200px] w-full rounded-md">
          {scans.length === 0 ? (
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
