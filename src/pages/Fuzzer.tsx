
import React from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';

const Fuzzer = () => {
  return (
    <DashboardLayout>
      <div className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-6">Web Application Fuzzer</h1>
        <RealTimeFuzzing />
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
