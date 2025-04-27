
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { format } from 'date-fns';

interface ScanEntry {
  id: string;
  timestamp: Date;
  status: 'completed' | 'in-progress' | 'failed';
}

export const LiveScans = () => {
  const [scans, setScans] = useState<ScanEntry[]>([]);

  useEffect(() => {
    // Simulate initial scans
    setScans([
      { id: '1', timestamp: new Date(), status: 'completed' },
      { id: '2', timestamp: new Date(Date.now() - 1000 * 60 * 5), status: 'completed' },
    ]);

    // Simulate new scans being added
    const interval = setInterval(() => {
      const newScan: ScanEntry = {
        id: Math.random().toString(36).substr(2, 9),
        timestamp: new Date(),
        status: 'completed'
      };
      setScans(prev => [newScan, ...prev].slice(0, 10)); // Keep last 10 scans
    }, 45000);

    return () => clearInterval(interval);
  }, []);

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-emerald-900/30 shadow-lg shadow-emerald-500/5">
      <CardHeader>
        <CardTitle className="text-xl font-bold">Live Scans</CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[200px] w-full rounded-md">
          {scans.map((scan) => (
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
              <span className="text-sm font-medium text-emerald-500">
                {scan.status}
              </span>
            </div>
          ))}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
