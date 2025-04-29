
import React from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { RealTimeFuzzing } from '@/components/dashboard/RealTimeFuzzing';
import { DVWAConnection } from '@/components/dashboard/DVWAConnection';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Grid, GridItem } from '@/components/ui/grid';

const Fuzzer = () => {
  return (
    <DashboardLayout>
      <div className="container mx-auto p-4 space-y-6">
        <h1 className="text-2xl font-bold mb-2">Web Application Fuzzer</h1>
        
        <Grid cols={1} colsMd={3} gap={6} className="w-full">
          <GridItem colSpan={1}>
            <DVWAConnection />
          </GridItem>
          <GridItem colSpan={2}>
            <Card className="bg-card/50 backdrop-blur-sm border-emerald-900/20">
              <CardHeader>
                <CardTitle>Fuzzing Dashboard</CardTitle>
                <CardDescription>Monitor and control your fuzzing operations</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-sm text-muted-foreground mb-4">
                  Connect to DVWA and upload payloads to start fuzzing your target application.
                </div>
              </CardContent>
            </Card>
          </GridItem>
        </Grid>
        
        <RealTimeFuzzing />
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
