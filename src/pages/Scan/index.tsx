
import React from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { DVWAConnection } from '@/components/dashboard/DVWAConnection';
import { CyberpunkScannerAnimation } from '@/components/dashboard/CyberpunkScannerAnimation';
import ScanControl from '../ScanControl';

const ScanPage = () => {
  return (
    <DashboardLayout>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="md:col-span-2">
          <ScanControl />
        </div>
        
        <div className="md:col-span-1 space-y-6">
          <DVWAConnection />
        </div>
        
        <div className="md:col-span-1 bg-card border rounded-lg p-4 h-[400px]">
          <h2 className="text-xl font-bold mb-4">Live Scanner</h2>
          <div className="h-[320px] w-full">
            <CyberpunkScannerAnimation 
              active={true} 
              threatLevel="medium" 
              detectedThreats={8}
              dvwaConnected={true}
              dvwaUrl="http://localhost/dvwa"
              currentVulnerability="SQL Injection"
              exploitPayload="' OR 1=1 --"
            />
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default ScanPage;
