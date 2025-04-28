
import React from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';
import { DVWAConnectionProvider } from '@/context/DVWAConnectionContext';

const Fuzzer = () => {
  return (
    <DashboardLayout>
      <DVWAConnectionProvider>
        <div className="container mx-auto p-4">
          <h1 className="text-2xl font-bold mb-6">Web Application Fuzzer</h1>
          <RealTimeFuzzing />
        </div>
      </DVWAConnectionProvider>
    </DashboardLayout>
  );
};

export default Fuzzer;
