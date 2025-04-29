
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

const Dashboard = () => {
  const [cpuUsage, setCpuUsage] = useState(35);
  const [memoryUsage, setMemoryUsage] = useState(42);
  const [isDownloading, setIsDownloading] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      setCpuUsage(Math.min(95, Math.max(25, cpuUsage + (Math.random() * 10 - 5))));
      setMemoryUsage(Math.min(95, Math.max(30, memoryUsage + (Math.random() * 8 - 4))));
    }, 2000);
    
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
        <Tabs defaultValue="dashboard" className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
            <TabsTrigger value="real-time">Real-Time Fuzzing</TabsTrigger>
          </TabsList>
          
          <TabsContent value="dashboard" className="space-y-6">
            <Grid cols={1} colsMd={2} gap={6} className="w-full">
              <GridItem span={1} className="w-full">
                <ScanAnalytics />
              </GridItem>
              <GridItem span={1} className="w-full">
                <LiveThreats />
              </GridItem>
            </Grid>

            <Card className="w-full bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5">
              <CardHeader className="flex flex-row items-center justify-between">
                <div>
                  <CardTitle className="text-xl font-bold">Download Scan Report & Analysis</CardTitle>
                  <CardDescription>Get a comprehensive report of all your scan data</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col space-y-4">
                  <p>Download a complete package containing scan reports, vulnerability analysis, and machine learning datasets.</p>
                  <Button 
                    onClick={handleDownloadReport} 
                    disabled={isDownloading} 
                    className="w-full md:w-auto"
                  >
                    {isDownloading ? 'Preparing Download...' : 'Download Full Report'}
                    <Download className="ml-2 h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Grid cols={1} colsMd={2} gap={6} className="w-full">
              <GridItem span={1} className="w-full">
                <LiveScans />
              </GridItem>
              <GridItem span={1} className="w-full">
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
