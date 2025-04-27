
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';

interface Scan {
  id: string;
  timestamp: Date;
  target: string;
}

interface RecentScansListProps {
  scans: Scan[];
}

export const RecentScansList: React.FC<RecentScansListProps> = ({ scans }) => {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Scans</CardTitle>
        <CardDescription>Latest security scans performed</CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[200px]">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="flex justify-between items-center p-3 border-b last:border-0"
            >
              <div className="flex flex-col">
                <span className="font-medium">{scan.target}</span>
                <span className="text-sm text-muted-foreground">
                  {scan.timestamp.toLocaleString()}
                </span>
              </div>
            </div>
          ))}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
