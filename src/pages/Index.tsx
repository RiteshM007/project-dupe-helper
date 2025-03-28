
import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX, 
  AlertTriangle, 
  Cpu, 
  Clock,
  Zap
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '@/components/ui/chart';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line, Area, AreaChart } from 'recharts';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { AdvancedScannerAnimation } from '@/components/dashboard/AdvancedScannerAnimation';
import { StatCard } from '@/components/dashboard/StatCard';
import { ThreatLevelIndicator } from '@/components/dashboard/ThreatLevelIndicator';
import { RecentScansTable } from '@/components/dashboard/RecentScansTable';
import { ResourceUsage } from '@/components/dashboard/ResourceUsage';
import { Button } from '@/components/ui/button';

// Mock data for charts
const vulnerabilityData = [
  { name: 'SQL Injection', count: 5, color: '#ff4d6d' },
  { name: 'XSS', count: 12, color: '#f77f00' },
  { name: 'CSRF', count: 3, color: '#fcbf49' },
  { name: 'File Inclusion', count: 2, color: '#90be6d' },
  { name: 'Authentication', count: 7, color: '#43aa8b' },
  { name: 'Authorization', count: 4, color: '#4361ee' }
];

const performanceData = [
  { time: '00:00', requests: 230, responseTime: 120 },
  { time: '01:00', requests: 280, responseTime: 130 },
  { time: '02:00', requests: 250, responseTime: 140 },
  { time: '03:00', requests: 300, responseTime: 100 },
  { time: '04:00', requests: 320, responseTime: 90 },
  { time: '05:00', requests: 350, responseTime: 85 },
  { time: '06:00', requests: 370, responseTime: 70 },
];

// Chart configuration
const chartConfig = {
  vulnerabilities: {
    red: { color: '#ff4d6d', label: 'Critical' },
    orange: { color: '#f77f00', label: 'High' },
    yellow: { color: '#fcbf49', label: 'Medium' },
    green: { color: '#90be6d', label: 'Low' },
    blue: { color: '#4361ee', label: 'Info' }
  },
  performance: {
    requests: { color: '#7c3aed', label: 'Requests' },
    responseTime: { color: '#60a5fa', label: 'Response Time' }
  }
};

const Dashboard = () => {
  const [scanProgress, setScanProgress] = useState(0);
  const [scanActive, setScanActive] = useState(false);
  const [cpuUsage, setCpuUsage] = useState(35);
  const [memoryUsage, setMemoryUsage] = useState(42);
  const [threatStats, setThreatStats] = useState({
    critical: 5,
    high: 12,
    medium: 8,
    low: 23
  });
  
  // Simulate progress and resource usage changes
  useEffect(() => {
    if (scanActive) {
      const interval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 100) {
            setScanActive(false);
            return 100;
          }
          return prev + 1;
        });
        
        // Simulate fluctuating resource usage
        setCpuUsage(Math.min(95, Math.max(25, cpuUsage + (Math.random() * 10 - 5))));
        setMemoryUsage(Math.min(95, Math.max(30, memoryUsage + (Math.random() * 8 - 4))));
      }, 300);
      
      return () => clearInterval(interval);
    }
  }, [scanActive, cpuUsage, memoryUsage]);
  
  const toggleScan = () => {
    if (!scanActive) {
      setScanProgress(0);
      setScanActive(true);
    } else {
      setScanActive(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Top row */}
        <Card className="md:col-span-2 bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="text-xl font-bold">Active Scan Status</CardTitle>
              <CardDescription>Real-time vulnerability detection</CardDescription>
            </div>
            <Button 
              onClick={toggleScan}
              className={`px-4 py-2 font-medium rounded-md transition-all duration-300 ${
                scanActive 
                  ? 'bg-red-500/80 hover:bg-red-600/80 text-white' 
                  : 'bg-emerald-500/80 hover:bg-emerald-600/80 text-white'
              }`}
            >
              {scanActive ? 'Stop Scan' : 'Start Scan'}
            </Button>
          </CardHeader>
          <CardContent>
            <div className="flex items-center mb-4">
              <Progress value={scanProgress} className="h-2 bg-gray-700/50" />
              <span className="ml-4 text-sm font-mono">{scanProgress}%</span>
            </div>
            
            <div className="h-48 w-full">
              <AdvancedScannerAnimation active={scanActive} />
            </div>
          </CardContent>
          <CardFooter className="text-sm text-muted-foreground">
            Target: https://example-vulnerable-site.com
          </CardFooter>
        </Card>

        <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5">
          <CardHeader>
            <CardTitle className="text-xl font-bold">Threat Detection</CardTitle>
            <CardDescription>Current vulnerability summary</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ThreatLevelIndicator 
              label="Critical" 
              count={threatStats.critical} 
              icon={ShieldX} 
              color="bg-red-500" 
            />
            <ThreatLevelIndicator 
              label="High" 
              count={threatStats.high} 
              icon={ShieldAlert} 
              color="bg-orange-500" 
            />
            <ThreatLevelIndicator 
              label="Medium" 
              count={threatStats.medium} 
              icon={AlertTriangle} 
              color="bg-yellow-500" 
            />
            <ThreatLevelIndicator 
              label="Low" 
              count={threatStats.low} 
              icon={ShieldCheck} 
              color="bg-green-500" 
            />
          </CardContent>
          <CardFooter className="text-sm text-muted-foreground">
            Last updated: {new Date().toLocaleTimeString()}
          </CardFooter>
        </Card>

        {/* Middle row - Fixed the overlapping by separating into two rows */}
        <Card className="md:col-span-3 bg-card/50 backdrop-blur-sm border-indigo-900/30 shadow-lg shadow-indigo-500/5">
          <CardHeader>
            <CardTitle className="text-xl font-bold">Vulnerability Distribution</CardTitle>
            <CardDescription>Attack vectors detected during scans</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ChartContainer config={chartConfig.vulnerabilities}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={vulnerabilityData} barGap={8}>
                    <XAxis 
                      dataKey="name" 
                      tick={{ fill: 'currentColor', fontSize: 12 }}
                      axisLine={{ stroke: '#666' }}
                      tickLine={{ stroke: '#666' }}
                    />
                    <YAxis 
                      tick={{ fill: 'currentColor', fontSize: 12 }}
                      axisLine={{ stroke: '#666' }}
                      tickLine={{ stroke: '#666' }}
                    />
                    <ChartTooltip 
                      content={
                        <ChartTooltipContent className="text-xs" />
                      } 
                    />
                    <Bar 
                      dataKey="count" 
                      radius={[4, 4, 0, 0]} 
                      className="fill-current text-primary"
                      fill="var(--color-blue)"
                    />
                  </BarChart>
                </ResponsiveContainer>
              </ChartContainer>
            </div>
          </CardContent>
        </Card>

        {/* Resource usage card - moved to its own row */}
        <Card className="md:col-span-3 bg-card/50 backdrop-blur-sm border-cyan-900/30 shadow-lg shadow-cyan-500/5">
          <CardHeader>
            <CardTitle className="text-xl font-bold">Performance Metrics</CardTitle>
            <CardDescription>Request volume and response times</CardDescription>
          </CardHeader>
          <CardContent className="grid md:grid-cols-3 gap-6">
            <div className="md:col-span-2">
              <div className="h-64">
                <ChartContainer config={chartConfig.performance}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={performanceData}>
                      <defs>
                        <linearGradient id="requestsGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.8}/>
                          <stop offset="95%" stopColor="#7c3aed" stopOpacity={0.1}/>
                        </linearGradient>
                        <linearGradient id="responseTimeGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#60a5fa" stopOpacity={0.8}/>
                          <stop offset="95%" stopColor="#60a5fa" stopOpacity={0.1}/>
                        </linearGradient>
                      </defs>
                      <XAxis 
                        dataKey="time" 
                        tick={{ fill: 'currentColor', fontSize: 12 }}
                        axisLine={{ stroke: '#666' }}
                        tickLine={{ stroke: '#666' }}
                      />
                      <YAxis 
                        tick={{ fill: 'currentColor', fontSize: 12 }}
                        axisLine={{ stroke: '#666' }}
                        tickLine={{ stroke: '#666' }}
                      />
                      <ChartTooltip 
                        content={
                          <ChartTooltipContent className="text-xs" />
                        } 
                      />
                      <Area 
                        type="monotone" 
                        dataKey="requests" 
                        stroke="#7c3aed" 
                        fillOpacity={1}
                        fill="url(#requestsGradient)" 
                      />
                      <Area 
                        type="monotone" 
                        dataKey="responseTime" 
                        stroke="#60a5fa" 
                        fillOpacity={1}
                        fill="url(#responseTimeGradient)" 
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
              
              <div className="space-y-4">
                <ResourceUsage 
                  label="CPU Usage" 
                  value={cpuUsage} 
                  icon={Cpu} 
                  max={100} 
                  unit="%" 
                  color="from-blue-500 to-purple-500" 
                />
                <ResourceUsage 
                  label="Memory Usage" 
                  value={memoryUsage} 
                  icon={Zap} 
                  max={100} 
                  unit="%" 
                  color="from-purple-500 to-pink-500" 
                />
              </div>
            </CardContent>
        </Card>

        {/* Bottom row */}
        <Card className="md:col-span-3 bg-card/50 backdrop-blur-sm border-emerald-900/30 shadow-lg shadow-emerald-500/5">
          <CardHeader>
            <CardTitle className="text-xl font-bold">Recent Scans</CardTitle>
            <CardDescription>Latest scan activities</CardDescription>
          </CardHeader>
          <CardContent>
            <RecentScansTable />
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
