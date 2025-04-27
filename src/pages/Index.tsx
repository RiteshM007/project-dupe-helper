
import React from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Grid, GridItem } from '@/components/ui/grid';
import { ScanAnalytics } from '@/components/dashboard/ScanAnalytics';
import { LiveScans } from '@/components/dashboard/LiveScans';
import { LiveThreats } from '@/components/dashboard/LiveThreats';
import { ResourceUsage } from '@/components/dashboard/ResourceUsage';
import { Cpu, Zap } from 'lucide-react';

const Dashboard = () => {
  const [cpuUsage, setCpuUsage] = React.useState(35);
  const [memoryUsage, setMemoryUsage] = React.useState(42);

  React.useEffect(() => {
    const interval = setInterval(() => {
      setCpuUsage(Math.min(95, Math.max(25, cpuUsage + (Math.random() * 10 - 5))));
      setMemoryUsage(Math.min(95, Math.max(30, memoryUsage + (Math.random() * 8 - 4))));
    }, 2000);
    
    return () => clearInterval(interval);
  }, [cpuUsage, memoryUsage]);

  return (
    <DashboardLayout>
      <div className="flex flex-col w-full gap-6 pb-6">
        <Grid cols={1} colsMd={2} gap={6} className="w-full">
          <GridItem className="w-full">
            <ScanAnalytics />
          </GridItem>
          <GridItem className="w-full">
            <LiveThreats />
          </GridItem>
        </Grid>

        <Grid cols={1} colsMd={2} gap={6} className="w-full">
          <GridItem className="w-full">
            <LiveScans />
          </GridItem>
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
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
