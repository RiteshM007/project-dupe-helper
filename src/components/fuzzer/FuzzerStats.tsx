
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  AreaChart,
  Area,
} from 'recharts';
import { ChartContainer, ChartTooltipContent } from '@/components/ui/chart';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

interface StatsDataPoint {
  time: string;
  requests: number;
  vulnerabilities: number;
  successRate: number;
}

interface FuzzerStatsProps {
  data: {
    requestsSent: number;
    vulnerabilitiesFound: number;
    successRate: number;
  };
}

export const FuzzerStats = ({ data }: FuzzerStatsProps) => {
  const [chartData, setChartData] = useState<StatsDataPoint[]>([]);
  
  useEffect(() => {
    // Every time we get new data, add a data point to the chart
    const time = new Date().toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    
    setChartData(prev => {
      // Keep only the last 20 data points
      const newData = [...prev, {
        time,
        requests: data.requestsSent,
        vulnerabilities: data.vulnerabilitiesFound,
        successRate: data.successRate
      }];
      
      if (newData.length > 20) {
        return newData.slice(newData.length - 20);
      }
      return newData;
    });
  }, [data]);
  
  const chartConfig = {
    requests: {
      label: "Requests",
      color: "hsl(var(--primary))"
    },
    vulnerabilities: {
      label: "Vulnerabilities",
      color: "hsl(var(--destructive))"
    },
    successRate: {
      label: "Success Rate (%)",
      color: "hsl(var(--success))"
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">Real-Time Fuzzing Statistics</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <Card>
            <CardContent className="p-6">
              <div className="text-sm text-muted-foreground">Requests Sent</div>
              <div className="text-3xl font-bold mt-2">{data.requestsSent}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="text-sm text-muted-foreground">Vulnerabilities Found</div>
              <div className="text-3xl font-bold mt-2 text-destructive">{data.vulnerabilitiesFound}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-6">
              <div className="text-sm text-muted-foreground">Success Rate</div>
              <div className="text-3xl font-bold mt-2">{data.successRate}%</div>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="line" className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="line">Line Chart</TabsTrigger>
            <TabsTrigger value="area">Area Chart</TabsTrigger>
            <TabsTrigger value="bar">Bar Chart</TabsTrigger>
          </TabsList>
          
          <TabsContent value="line">
            <div className="h-80 w-full">
              <ChartContainer config={chartConfig} className="h-80">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted/20" />
                  <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                  <YAxis yAxisId="left" tick={{ fontSize: 12 }} />
                  <YAxis 
                    yAxisId="right" 
                    orientation="right" 
                    domain={[0, 100]} 
                    tick={{ fontSize: 12 }} 
                  />
                  <Tooltip content={<ChartTooltipContent />} />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="requests" 
                    stroke="hsl(var(--primary))" 
                    yAxisId="left" 
                    activeDot={{ r: 6 }} 
                  />
                  <Line 
                    type="monotone" 
                    dataKey="vulnerabilities" 
                    stroke="hsl(var(--destructive))" 
                    yAxisId="left" 
                  />
                  <Line 
                    type="monotone" 
                    dataKey="successRate" 
                    stroke="hsl(var(--success))" 
                    yAxisId="right" 
                  />
                </LineChart>
              </ChartContainer>
            </div>
          </TabsContent>
          
          <TabsContent value="area">
            <div className="h-80 w-full">
              <ChartContainer config={chartConfig} className="h-80">
                <AreaChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted/20" />
                  <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip content={<ChartTooltipContent />} />
                  <Legend />
                  <Area 
                    type="monotone" 
                    dataKey="requests" 
                    stroke="hsl(var(--primary))" 
                    fill="hsl(var(--primary)/30)" 
                    stackId="1" 
                  />
                  <Area 
                    type="monotone" 
                    dataKey="vulnerabilities" 
                    stroke="hsl(var(--destructive))" 
                    fill="hsl(var(--destructive)/30)" 
                    stackId="2" 
                  />
                </AreaChart>
              </ChartContainer>
            </div>
          </TabsContent>
          
          <TabsContent value="bar">
            <div className="h-80 w-full">
              <ChartContainer config={chartConfig} className="h-80">
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted/20" />
                  <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip content={<ChartTooltipContent />} />
                  <Legend />
                  <Bar 
                    dataKey="requests" 
                    fill="hsl(var(--primary))" 
                    radius={[4, 4, 0, 0]} 
                  />
                  <Bar 
                    dataKey="vulnerabilities" 
                    fill="hsl(var(--destructive))" 
                    radius={[4, 4, 0, 0]} 
                  />
                </BarChart>
              </ChartContainer>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};
