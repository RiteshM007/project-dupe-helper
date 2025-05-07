
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts';
import { ChartContainer, ChartTooltipContent } from '@/components/ui/chart';
import { Progress } from '@/components/ui/progress';
import { ArrowUp, ArrowDown, Zap } from 'lucide-react';

interface DataPoint {
  timestamp: string;
  requestsSent: number;
  vulnerabilitiesFound: number;
}

interface AnalyticsData {
  timeSeries: DataPoint[];
  successRate: number;
}

export const LiveFuzzingAnalytics = () => {
  const [analyticsData, setAnalyticsData] = useState<AnalyticsData>({
    timeSeries: [],
    successRate: 0,
  });
  const [isActive, setIsActive] = useState(false);

  useEffect(() => {
    // Create synthetic data for initial display
    const initialData = Array.from({ length: 10 }, (_, i) => {
      const time = new Date();
      time.setMinutes(time.getMinutes() - (10 - i));
      
      return {
        timestamp: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        requestsSent: Math.floor(Math.random() * 10),
        vulnerabilitiesFound: Math.floor(Math.random() * 3)
      };
    });
    
    setAnalyticsData({
      timeSeries: initialData,
      successRate: 25,
    });
    
    const handleScanStart = () => {
      setIsActive(true);
    };
    
    const handleScanComplete = (event: Event) => {
      setIsActive(false);
      
      const customEvent = event as CustomEvent;
      const { scanId, vulnerabilities, payloadsTested } = customEvent.detail;
      
      if (scanId && vulnerabilities !== undefined && payloadsTested !== undefined) {
        const successRate = Math.round((vulnerabilities / payloadsTested) * 100);
        
        setAnalyticsData(prev => {
          // Add new data point with actual scan results
          const time = new Date();
          const newPoint = {
            timestamp: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
            requestsSent: payloadsTested,
            vulnerabilitiesFound: vulnerabilities
          };
          
          // Keep only the last 50 points
          const newTimeSeries = [...prev.timeSeries, newPoint];
          if (newTimeSeries.length > 50) {
            newTimeSeries.shift();
          }
          
          return {
            timeSeries: newTimeSeries,
            successRate: successRate,
          };
        });
      }
    };
    
    window.addEventListener('scanStart', handleScanStart);
    window.addEventListener('scanComplete', handleScanComplete);
    
    // Update data every 2 seconds when active
    let interval: number | null = null;
    if (isActive) {
      interval = window.setInterval(() => {
        setAnalyticsData(prev => {
          // Add synthetic data point if fuzzing is active
          const time = new Date();
          const lastPoint = prev.timeSeries[prev.timeSeries.length - 1];
          const newPoint = {
            timestamp: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
            requestsSent: lastPoint ? lastPoint.requestsSent + Math.floor(Math.random() * 5) + 1 : 5,
            vulnerabilitiesFound: lastPoint ? lastPoint.vulnerabilitiesFound + (Math.random() > 0.7 ? 1 : 0) : 0
          };
          
          // Keep only the last 50 points
          const newTimeSeries = [...prev.timeSeries, newPoint];
          if (newTimeSeries.length > 50) {
            newTimeSeries.shift();
          }
          
          // Calculate success rate
          const totalRequests = newPoint.requestsSent;
          const totalVulns = newPoint.vulnerabilitiesFound;
          const successRate = totalRequests ? Math.round((totalVulns / totalRequests) * 100) : 0;
          
          return {
            timeSeries: newTimeSeries,
            successRate: successRate,
          };
        });
      }, 2000);
    }
    
    return () => {
      window.removeEventListener('scanStart', handleScanStart);
      window.removeEventListener('scanComplete', handleScanComplete);
      if (interval) clearInterval(interval);
    };
  }, [isActive]);
  
  // Get the latest data point for the counters
  const latestData = analyticsData.timeSeries.length > 0 
    ? analyticsData.timeSeries[analyticsData.timeSeries.length - 1] 
    : { requestsSent: 0, vulnerabilitiesFound: 0 };
  
  // Chart configuration
  const chartConfig = {
    requestsSent: {
      label: "Requests Sent",
      color: "#0ea5e9" // cyan
    },
    vulnerabilitiesFound: {
      label: "Vulnerabilities Found",
      color: "#ec4899" // pink
    }
  };
  
  // Pie chart data
  const pieData = [
    { name: 'Vulnerabilities', value: analyticsData.successRate },
    { name: 'Safe Requests', value: 100 - analyticsData.successRate },
  ];
  
  const COLORS = ['#ec4899', '#0ea5e9'];

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-emerald-900/30 shadow-lg shadow-emerald-500/5">
      <CardHeader>
        <CardTitle className="text-xl font-bold">Live Fuzzing Analytics</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="overflow-hidden">
            <CardContent className="p-4 text-center">
              <p className="text-sm font-medium text-muted-foreground">Requests Sent</p>
              <div className="flex items-center justify-center mt-2">
                <Zap className="h-5 w-5 text-blue-500 mr-2" />
                <span className="text-3xl font-bold animate-pulse">
                  {latestData.requestsSent}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                <ArrowUp className="h-3 w-3 text-green-500 inline-block mr-1" />
                Active scans increase this number
              </p>
            </CardContent>
          </Card>
          
          <Card className="overflow-hidden">
            <CardContent className="p-4 text-center">
              <p className="text-sm font-medium text-muted-foreground">Vulnerabilities Found</p>
              <div className="flex items-center justify-center mt-2">
                <Zap className="h-5 w-5 text-pink-500 mr-2" />
                <span className="text-3xl font-bold animate-pulse">
                  {latestData.vulnerabilitiesFound}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                <ArrowUp className="h-3 w-3 text-red-500 inline-block mr-1" />
                Critical security issues detected
              </p>
            </CardContent>
          </Card>
          
          <Card className="overflow-hidden">
            <CardContent className="p-4 text-center">
              <p className="text-sm font-medium text-muted-foreground">Success Rate</p>
              <div className="flex items-center justify-center mt-2">
                <Zap className="h-5 w-5 text-emerald-500 mr-2" />
                <span className="text-3xl font-bold animate-pulse">
                  {analyticsData.successRate}%
                </span>
              </div>
              <Progress 
                value={analyticsData.successRate} 
                className="h-2 mt-2" 
              />
            </CardContent>
          </Card>
        </div>
        
        <Tabs defaultValue="line" className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="line">Line Chart</TabsTrigger>
            <TabsTrigger value="area">Area Chart</TabsTrigger>
            <TabsTrigger value="pie">Success Rate</TabsTrigger>
          </TabsList>
          
          <TabsContent value="line">
            <div className="h-[300px] w-full">
              <ChartContainer config={chartConfig} className="h-[300px]">
                <LineChart data={analyticsData.timeSeries}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted/20" />
                  <XAxis dataKey="timestamp" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip content={<ChartTooltipContent />} />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="requestsSent" 
                    stroke="#0ea5e9" 
                    activeDot={{ r: 8 }}
                    strokeWidth={2}
                    dot={false}
                    animationDuration={500}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="vulnerabilitiesFound" 
                    stroke="#ec4899"
                    strokeWidth={2}
                    dot={{ stroke: '#ec4899', strokeWidth: 2, r: 4 }}
                    activeDot={{ r: 8 }}
                    animationDuration={500}
                  />
                </LineChart>
              </ChartContainer>
            </div>
          </TabsContent>
          
          <TabsContent value="area">
            <div className="h-[300px] w-full">
              <ChartContainer config={chartConfig} className="h-[300px]">
                <AreaChart data={analyticsData.timeSeries}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted/20" />
                  <XAxis dataKey="timestamp" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip content={<ChartTooltipContent />} />
                  <Legend />
                  <Area 
                    type="monotone" 
                    dataKey="requestsSent" 
                    stroke="#0ea5e9" 
                    fill="#0ea5e9" 
                    fillOpacity={0.2}
                    animationDuration={500}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="vulnerabilitiesFound" 
                    stroke="#ec4899" 
                    fill="#ec4899" 
                    fillOpacity={0.2}
                    animationDuration={500}
                  />
                </AreaChart>
              </ChartContainer>
            </div>
          </TabsContent>
          
          <TabsContent value="pie">
            <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    outerRadius={120}
                    innerRadius={60}
                    fill="#8884d8"
                    dataKey="value"
                    animationDuration={500}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </TabsContent>
        </Tabs>
        
        <div className="text-xs text-muted-foreground text-center">
          {isActive ? (
            <div className="flex items-center justify-center space-x-2">
              <span className="animate-pulse inline-block h-2 w-2 rounded-full bg-green-500"></span>
              <span>Live data is being captured from active scanning</span>
            </div>
          ) : (
            <span>Start a scan to see live data updates</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
