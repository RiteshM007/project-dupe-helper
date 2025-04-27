
import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

const recentScansData = [
  { day: 'Mon', scans: 4 },
  { day: 'Tue', scans: 6 },
  { day: 'Wed', scans: 3 },
  { day: 'Thu', scans: 8 },
  { day: 'Fri', scans: 5 },
  { day: 'Sat', scans: 2 },
  { day: 'Sun', scans: 7 },
];

const vulnerabilityData = [
  { level: 'Low', count: 12 },
  { level: 'Medium', count: 8 },
  { level: 'High', count: 5 },
  { level: 'Critical', count: 2 },
];

export const ScanAnalytics = () => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
          <CardDescription>Number of scans in the last 7 days</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={recentScansData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="day" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="scans" fill="#8884d8" animationDuration={1000} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Vulnerability Analysis</CardTitle>
          <CardDescription>Vulnerabilities by severity level</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={vulnerabilityData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="level" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#82ca9d" animationDuration={1000} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
