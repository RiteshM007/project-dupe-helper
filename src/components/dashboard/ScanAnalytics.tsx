
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { format, subDays } from 'date-fns';

interface ScanData {
  date: string;
  count: number;
}

export const ScanAnalytics = () => {
  const [scanData, setScanData] = useState<ScanData[]>([]);

  useEffect(() => {
    // Initialize with last 7 days of data
    const initialData = Array.from({ length: 7 }).map((_, index) => ({
      date: format(subDays(new Date(), 6 - index), 'MMM dd'),
      count: Math.floor(Math.random() * 10)
    }));
    setScanData(initialData);

    // Simulate real-time updates
    const interval = setInterval(() => {
      setScanData(prev => {
        const newData = [...prev];
        newData[6].count += 1;
        return newData;
      });
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  return (
    <Card className="w-full bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
      <CardHeader>
        <CardTitle className="text-xl font-bold">Recent Scans Analysis</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={scanData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted/20" />
              <XAxis 
                dataKey="date" 
                tick={{ fill: 'currentColor' }}
                stroke="currentColor" 
              />
              <YAxis 
                tick={{ fill: 'currentColor' }}
                stroke="currentColor"
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'hsl(var(--card))', 
                  border: '1px solid hsl(var(--border))' 
                }}
              />
              <Bar 
                dataKey="count" 
                fill="hsl(var(--primary))"
                radius={[4, 4, 0, 0]}
                className="animate-in fade-in duration-300"
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
};
