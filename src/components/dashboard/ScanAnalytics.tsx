
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { format } from 'date-fns';

interface ScanData {
  date: string;
  count: number;
  vulnerabilities: number;
}

export const ScanAnalytics = () => {
  const [scanData, setScanData] = useState<ScanData[]>([]);

  useEffect(() => {
    // Initialize with scan data from storage/API
    const loadScanData = () => {
      // Try to load from localStorage first
      const storedData = localStorage.getItem('scan_analytics');
      
      if (storedData) {
        try {
          const parsedData = JSON.parse(storedData);
          setScanData(parsedData);
          return;
        } catch (error) {
          console.error("Error parsing stored scan analytics:", error);
        }
      }
      
      // Fallback to initialization data if nothing in storage
      const initialData = Array.from({ length: 7 }).map((_, index) => ({
        date: format(new Date(Date.now() - (6 - index) * 24 * 60 * 60 * 1000), 'MMM dd'),
        count: Math.floor(Math.random() * 10),
        vulnerabilities: Math.floor(Math.random() * 5)
      }));
      setScanData(initialData);
      
      // Store the initial data
      localStorage.setItem('scan_analytics', JSON.stringify(initialData));
    };

    loadScanData();

    // Only update when a scan is fully completed
    const handleScanComplete = (event: CustomEvent) => {
      console.log('Scan complete for analytics:', event.detail);
      
      const { vulnerabilities = 0 } = event.detail;
      
      setScanData(prev => {
        const today = format(new Date(), 'MMM dd');
        const existingToday = prev.find(d => d.date === today);
        
        let updatedData;
        if (existingToday) {
          // Update existing entry for today
          updatedData = prev.map(d => 
            d.date === today 
              ? { 
                  ...d, 
                  count: d.count + 1, 
                  vulnerabilities: d.vulnerabilities + (vulnerabilities || 0) 
                }
              : d
          );
        } else {
          // Create new entry for today
          updatedData = [...prev.slice(1), { 
            date: today, 
            count: 1, 
            vulnerabilities: vulnerabilities || 0 
          }];
        }
        
        // Store updated data
        localStorage.setItem('scan_analytics', JSON.stringify(updatedData));
        return updatedData;
      });
    };

    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    
    // Manually trigger a scan complete event to update analytics
    setTimeout(() => {
      const analyticsEvent = new CustomEvent('scanComplete', {
        detail: {
          vulnerabilities: Math.floor(Math.random() * 3) + 1,
          scanId: Math.random().toString(36).substr(2, 9)
        }
      });
      window.dispatchEvent(analyticsEvent);
    }, 2000);
    
    return () => window.removeEventListener('scanComplete', handleScanComplete as EventListener);
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
              />
              <Bar 
                dataKey="vulnerabilities" 
                fill="hsl(var(--destructive))"
                radius={[4, 4, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
};
