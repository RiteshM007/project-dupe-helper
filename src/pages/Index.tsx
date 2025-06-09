
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Grid, GridItem } from '@/components/ui/grid';
import { ScanAnalytics } from '@/components/dashboard/ScanAnalytics';
import { LiveScans } from '@/components/dashboard/LiveScans';
import { LiveThreats } from '@/components/dashboard/LiveThreats';
import { ResourceUsage } from '@/components/dashboard/ResourceUsage';
import { Cpu, Zap, Download, FileBarChart } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { toast } from '@/hooks/use-toast';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';
import { downloadScanReport } from '@/utils/reportGenerator';
import { VulnerabilityHeatmap } from '@/components/dashboard/VulnerabilityHeatmap';
import { LiveFuzzingAnalytics } from '@/components/dashboard/LiveFuzzingAnalytics';
import { useSocket } from '@/context/SocketContext';
import { useGlobalEvents } from '@/hooks/use-global-events';

const Dashboard = () => {
  const [cpuUsage, setCpuUsage] = useState(35);
  const [memoryUsage, setMemoryUsage] = useState(42);
  const [isDownloading, setIsDownloading] = useState(false);
  const [activeTab, setActiveTab] = useState("dashboard");
  const { isConnected } = useSocket();

  // Global event handlers
  useGlobalEvents({
    onFuzzingComplete: (data) => {
      console.log('Dashboard: Fuzzing completed', data);
      toast({
        title: "Fuzzing Complete",
        description: `Scan completed with ${data.vulnerabilities || 0} vulnerabilities found`,
      });
    },
    onMLAnalysisComplete: (data) => {
      console.log('Dashboard: ML analysis completed', data);
      toast({
        title: "ML Analysis Complete",
        description: "Machine learning analysis has finished processing",
      });
      // Optionally switch to ML results tab
      setActiveTab("real-time");
    },
    onThreatDetected: (data) => {
      console.log('Dashboard: Threat detected', data);
      toast({
        title: "Security Threat Detected",
        description: `${data.type || 'Unknown threat'} detected with ${data.severity || 'medium'} severity`,
        variant: "destructive",
      });
    },
    onScanComplete: (data) => {
      console.log('Dashboard: Scan completed', data);
      // Update scan analytics
      const analyticsEvent = new CustomEvent('scanComplete', {
        detail: {
          scanId: data.scanId || Math.random().toString(36).substr(2, 9),
          vulnerabilities: data.vulnerabilities || Math.floor(Math.random() * 3) + 1
        }
      });
      window.dispatchEvent(analyticsEvent);
    },
    onReportGenerated: (data) => {
      console.log('Dashboard: Report generated', data);
      toast({
        title: "Report Generated",
        description: "Security analysis report is ready for download",
      });
    }
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setCpuUsage(Math.min(95, Math.max(25, cpuUsage + (Math.random() * 10 - 5))));
      setMemoryUsage(Math.min(95, Math.max(30, memoryUsage + (Math.random() * 8 - 4))));
    }, 2000);
    
    // Initialize dashboard with data - this ensures initial data is displayed without depending on external events
    const initDashboard = () => {
      // Add initial scan data if needed
      const scanEvent = new CustomEvent('scanUpdate', {
        detail: {
          scanId: Math.random().toString(36).substr(2, 9),
          status: 'completed',
          vulnerabilities: 3
        }
      });
      window.dispatchEvent(scanEvent);
      
      // Add initial threat detection example
      const threatEvent = new CustomEvent('threatDetected', {
        detail: {
          vulnerabilityType: 'xss',
          payload: "<script>alert(1)</script>",
          severity: 'medium'
        }
      });
      window.dispatchEvent(threatEvent);
      
      // Update scan analytics
      const analyticsEvent = new CustomEvent('scanComplete', {
        detail: {
          scanId: Math.random().toString(36).substr(2, 9),
          vulnerabilities: Math.floor(Math.random() * 3) + 1
        }
      });
      window.dispatchEvent(analyticsEvent);
    };
    
    // Only initialize dashboard if there's no data already
    if (!localStorage.getItem('recent_scans')) {
      // Delay to ensure components are mounted
      setTimeout(initDashboard, 1000);
    }
    
    return () => clearInterval(interval);
  }, [cpuUsage, memoryUsage]);

  const handleDownloadReport = async () => {
    setIsDownloading(true);
    try {
      await downloadScanReport();
      toast({
        title: "Report Ready",
        description: "Scan report and analysis downloaded successfully ✅",
      });
    } catch (error) {
      toast({
        title: "Download Failed",
        description: "An error occurred while generating the report",
        variant: "destructive",
      });
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="flex flex-col w-full gap-6 pb-6">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-4">
          <div>
            <h1 className="text-2xl font-bold">Security Dashboard</h1>
            <div className="flex items-center gap-2 mt-1">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm text-gray-400">
                {isConnected ? 'Real-time connected' : 'Real-time disconnected'}
              </span>
            </div>
          </div>
          <Button 
            onClick={handleDownloadReport} 
            disabled={isDownloading} 
            className="mt-2 sm:mt-0"
          >
            {isDownloading ? 'Preparing Download...' : 'Download Report'}
            <Download className="ml-2 h-4 w-4" />
          </Button>
        </div>
      
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
            <TabsTrigger value="real-time">Real-Time Fuzzing</TabsTrigger>
          </TabsList>
          
          <TabsContent value="dashboard" className="space-y-6">
            <Grid cols={1} colsMd={2} gap={6} className="w-full">
              <GridItem className="w-full">
                <ScanAnalytics />
              </GridItem>
              <GridItem className="w-full">
                <VulnerabilityHeatmap />
              </GridItem>
            </Grid>

            <Grid cols={1} colsMd={2} gap={6} className="w-full">
              <GridItem className="w-full">
                <LiveScans />
              </GridItem>
              <GridItem className="w-full">
                <LiveThreats />
              </GridItem>
            </Grid>
            
            <Grid cols={1} gap={6} className="w-full">
              <GridItem className="w-full">
                <LiveFuzzingAnalytics />
              </GridItem>
            </Grid>

            <Grid cols={1} colsMd={2} gap={6} className="w-full">
              <GridItem className="w-full">
                <ResourceUsage 
                  label="System Resources" 
                  items={[
                    {
                      label: "CPU Usage",
                      value: cpuUsage,
                      icon: Cpu,
                      color: "from-blue-500 to-purple-500"
                    },
                    {
                      label: "Memory Usage",
                      value: memoryUsage,
                      icon: Zap,
                      color: "from-purple-500 to-pink-500"
                    }
                  ]}
                />
              </GridItem>
            </Grid>
          </TabsContent>
          
          <TabsContent value="real-time">
            <RealTimeFuzzing />
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
