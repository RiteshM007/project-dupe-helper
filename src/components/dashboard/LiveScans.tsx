
import React, { useState, useEffect, useRef } from 'react';
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
  const processedScanIds = useRef<Set<string>>(new Set());

  useEffect(() => {
    // Load existing scans from localStorage on component mount
    const loadStoredScans = () => {
      try {
        const storedScans = localStorage.getItem('recent_scans');
        if (storedScans) {
          const parsedScans = JSON.parse(storedScans).map((scan: any) => ({
            ...scan,
            timestamp: new Date(scan.timestamp)
          }));
          setScans(parsedScans);
          
          // Initialize processed scan IDs
          parsedScans.forEach((scan: ScanEntry) => {
            processedScanIds.current.add(`${scan.id}-${scan.status}`);
          });
        }
      } catch (error) {
        console.error('Error loading stored scans:', error);
      }
    };
    
    loadStoredScans();

    // Handle scan updates without duplicating entries
    const handleScanUpdate = (event: CustomEvent) => {
      const { scanId, status, vulnerabilities } = event.detail;
      
      // Create a unique key for this scan update
      const scanUpdateKey = `${scanId}-${status}`;
      
      // Check if we've already processed this exact update
      if (processedScanIds.current.has(scanUpdateKey)) {
        return; // Skip duplicate updates
      }
      
      setScans(prev => {
        // Check if scan exists
        const scanIndex = prev.findIndex(s => s.id === scanId);
        
        let newScans;
        if (scanIndex >= 0) {
          // Update existing scan
          newScans = [...prev];
          newScans[scanIndex] = {
            ...newScans[scanIndex],
            status,
            ...(vulnerabilities !== undefined && { vulnerabilities })
          };
        } else if (status === 'in-progress') {
          // Add new scan if it's starting
          const newScan = {
            id: scanId,
            timestamp: new Date(),
            status,
            vulnerabilities: 0
          };
          newScans = [newScan, ...prev].slice(0, 10); // Limit to 10 entries
        } else {
          // Don't add completed or failed scans that we didn't track from start
          return prev;
        }
        
        // Save to localStorage for persistence
        try {
          localStorage.setItem('recent_scans', JSON.stringify(newScans));
        } catch (error) {
          console.error('Error saving scans to localStorage:', error);
        }
        
        // Record that we've processed this update
        processedScanIds.current.add(scanUpdateKey);
        
        return newScans;
      });
    };

    // Listen for scan status updates
    window.addEventListener('scanUpdate', handleScanUpdate as EventListener);
    
    return () => {
      window.removeEventListener('scanUpdate', handleScanUpdate as EventListener);
    };
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
                className="flex items-center justify-between p-4 border-b border-border/50"
              >
                <div className="flex flex-col">
                  <span className="font-medium">
                    Scan #{scan.id}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    {format(scan.timestamp, 'MMM dd, yyyy HH:mm:ss')}
                  </span>
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
