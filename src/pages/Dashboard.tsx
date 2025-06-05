
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { FuzzerStats } from '@/components/fuzzer/FuzzerStats';
import { LiveThreats } from '@/components/dashboard/LiveThreats';
import { Grid, GridItem } from '@/components/ui/grid';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';
import { Activity, Shield, Bug, Clock, Play, BarChart3 } from 'lucide-react';

interface RecentScan {
  id: string;
  timestamp: Date;
  vulnerabilities: number;
  payloads: number;
  status: 'completed' | 'failed';
  duration: string;
}

const Dashboard = () => {
  const navigate = useNavigate();
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [statsData, setStatsData] = useState({
    requestsSent: 0,
    vulnerabilitiesFound: 0,
    successRate: 100
  });
  const [totalScans, setTotalScans] = useState(0);
  const [activeScans, setActiveScans] = useState(0);

  useEffect(() => {
    // Listen for scan completion
    const handleScanComplete = (event: CustomEvent) => {
      const { sessionId, vulnerabilities = 0, payloadsTested = 0 } = event.detail || {};
      
      const newScan: RecentScan = {
        id: sessionId || `scan-${Date.now()}`,
        timestamp: new Date(),
        vulnerabilities,
        payloads: payloadsTested,
        status: 'completed',
        duration: `${Math.floor(Math.random() * 5) + 1}m ${Math.floor(Math.random() * 60)}s`
      };

      setRecentScans(prev => [newScan, ...prev].slice(0, 5));
      setTotalScans(prev => prev + 1);
      setActiveScans(0);
      
      // Update overall stats
      setStatsData(prev => ({
        requestsSent: prev.requestsSent + payloadsTested,
        vulnerabilitiesFound: prev.vulnerabilitiesFound + vulnerabilities,
        successRate: payloadsTested > 0 
          ? Math.round((1 - (vulnerabilities / payloadsTested)) * 100)
          : prev.successRate
      }));
    };

    // Listen for scan start
    const handleScanStart = () => {
      setActiveScans(1);
    };

    // Listen for scan stop
    const handleScanStop = () => {
      setActiveScans(0);
    };

    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    window.addEventListener('scanStart', handleScanStart as EventListener);
    window.addEventListener('scanStop', handleScanStop as EventListener);

    return () => {
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
      window.removeEventListener('scanStart', handleScanStart as EventListener);
      window.removeEventListener('scanStop', handleScanStop as EventListener);
    };
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500/10 text-green-500';
      case 'failed': return 'bg-red-500/10 text-red-500';
      default: return 'bg-gray-500/10 text-gray-500';
    }
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-4">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">Security Dashboard</h1>
            <p className="text-muted-foreground">Monitor your web application security testing</p>
          </div>
          <div className="flex space-x-2">
            <Button onClick={() => navigate('/fuzzer')}>
              <Play className="h-4 w-4 mr-2" />
              Start Fuzzing
            </Button>
            <Button variant="outline" onClick={() => navigate('/reports')}>
              <BarChart3 className="h-4 w-4 mr-2" />
              View Reports
            </Button>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Activity className="h-8 w-8 text-blue-500" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-muted-foreground">Total Scans</p>
                  <p className="text-2xl font-bold">{totalScans}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Clock className="h-8 w-8 text-green-500" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-muted-foreground">Active Scans</p>
                  <p className="text-2xl font-bold">{activeScans}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Bug className="h-8 w-8 text-red-500" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-muted-foreground">Vulnerabilities</p>
                  <p className="text-2xl font-bold">{statsData.vulnerabilitiesFound}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Shield className="h-8 w-8 text-purple-500" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-muted-foreground">Success Rate</p>
                  <p className="text-2xl font-bold">{statsData.successRate}%</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Grid cols={1} md={2} gap={6} className="mb-6">
          {/* Fuzzer Statistics */}
          <GridItem>
            <FuzzerStats data={statsData} />
          </GridItem>
          
          {/* Live Threats */}
          <GridItem>
            <LiveThreats />
          </GridItem>
        </Grid>

        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              Recent Scans
              <Button variant="outline" size="sm" onClick={() => navigate('/reports')}>
                View All
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {recentScans.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No recent scans</p>
                <p className="text-sm">Start fuzzing to see scan history</p>
              </div>
            ) : (
              <div className="space-y-3">
                {recentScans.map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-4">
                      <Badge variant="outline" className={getStatusColor(scan.status)}>
                        {scan.status}
                      </Badge>
                      <div>
                        <p className="font-medium">Scan {scan.id.substring(0, 8)}</p>
                        <p className="text-xs text-muted-foreground">
                          {scan.timestamp.toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="flex items-center space-x-4 text-sm">
                        <span>{scan.vulnerabilities} vulnerabilities</span>
                        <span>{scan.payloads} payloads</span>
                        <span>{scan.duration}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
