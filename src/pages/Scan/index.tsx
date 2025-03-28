
import React, { useState } from 'react';
import { Grid } from '@/components/ui/grid';
import { DVWAConnection, DVWAConfig } from '@/components/dashboard/DVWAConnection';
import { CyberpunkScannerAnimation } from '@/components/dashboard/CyberpunkScannerAnimation';
import DashboardLayout from '@/components/layout/DashboardLayout';
import ScanControl from "../ScanControl";

const ScanPage = () => {
  const [isDVWAConnected, setIsDVWAConnected] = useState(false);
  const [dvwaConfig, setDvwaConfig] = useState<DVWAConfig | null>(null);
  
  const handleConnect = (config: DVWAConfig) => {
    setDvwaConfig(config);
    setIsDVWAConnected(true);
  };
  
  const handleDisconnect = () => {
    setIsDVWAConnected(false);
    setDvwaConfig(null);
  };
  
  return (
    <DashboardLayout>
      <div className="space-y-6">
        <Grid className="grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2">
            <ScanControl />
          </div>
          <div>
            <DVWAConnection 
              isConnected={isDVWAConnected}
              onConnect={handleConnect}
              onDisconnect={handleDisconnect}
            />
          </div>
        </Grid>
      </div>
    </DashboardLayout>
  );
};

export default ScanPage;
