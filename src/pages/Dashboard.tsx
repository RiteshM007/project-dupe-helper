import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { 
  Shield, 
  AlertTriangle, 
  Bug, 
  Activity, 
  BarChart2, 
  Database,
  Zap,
  Brain,
  FileText,
  Clock,
  CheckCircle2,
  ArrowUp,
  ArrowDown
} from 'lucide-react';
import { LiveThreats } from '@/components/dashboard/LiveThreats';
import { MachineLearningScanner } from '@/components/dashboard/MachineLearningScanner';
import { ScannerAnimation } from '@/components/dashboard/ScannerAnimation';

interface DashboardStats {
  totalScans: number;
  vulnerabilitiesFound: number;
  criticalThreats: number;
  lastScanTime: string;
  systemHealth: number;
  activeConnections: number;
}

interface RecentScan {
  id: string;
  target: string;
  timestamp: string;
  status: 'completed' | 'running' | 'failed';
  vulnerabilities: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  type?: string;
}

const Dashboard = () => {
  const [stats, setStats] = useState<DashboardStats>({
    totalScans: 0,
    vulnerabilitiesFound: 0,
    criticalThreats: 0,
    lastScanTime: 'Never',
    systemHealth: 98,
    activeConnections: 0
  });

  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [scanActive, setScanActive] = useState(false);
  const [threatLevel, setThreatLevel] = useState<'none' | 'low' | 'medium' | 'high' | 'critical'>('none');

  useEffect(() => {
    const handleScanStart = (event: CustomEvent) => {
      console.log('Dashboard: Scan started', event.detail);
      setScanActive(true);
    };

    const handleScanComplete = (event: CustomEvent) => {
      console.log('Dashboard: Scan completed', event.detail);
      setScanActive(false);
      const results = event.detail;
      
      if (!results) {
        console.warn('Dashboard: No results in scan complete event');
        return;
      }
      
      setStats(prev => ({
        ...prev,
        totalScans: prev.totalScans + 1,
        vulnerabilitiesFound: prev.vulnerabilitiesFound + (results.vulnerabilities || 0),
        criticalThreats: prev.criticalThreats + (results.severity === 'critical' ? 1 : 0),
        lastScanTime: new Date().toLocaleString()
      }));

      const newScan: RecentScan = {
        id: results.sessionId || Date.now().toString(),
        target: results.target || results.targetUrl || 'Unknown Target',
        timestamp: new Date().toLocaleString(),
        status: 'completed',
        vulnerabilities: results.vulnerabilities || 0,
        riskLevel: results.severity || 'low',
        type: results.type || 'fuzzing'
      };

      console.log('Dashboard: Adding new scan to recent scans:', newScan);
      setRecentScans(prev => [newScan, ...prev.slice(0, 4)]);
      
      // Update threat level based on results
      if (results.severity === 'critical') {
        setThreatLevel('critical');
      } else if (results.vulnerabilities > 3) {
        setThreatLevel('high');
      } else if (results.vulnerabilities > 0) {
        setThreatLevel('medium');
      } else {
        setThreatLevel('low');
      }
    };

    const handleThreatDetected = (event: CustomEvent) => {
      const threat = event.detail;
      setStats(prev => ({
        ...prev,
        criticalThreats: prev.criticalThreats + 1
      }));
      
      if (threat.severity === 'critical') {
        setThreatLevel('critical');
      }
      
      console.log('Dashboard: Threat detected', threat);
    };

    // Listen to all relevant events
    window.addEventListener('scanStart', handleScanStart as EventListener);
    window.addEventListener('scanStarted', handleScanStart as EventListener);
    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    window.addEventListener('globalScanComplete', handleScanComplete as EventListener);
    window.addEventListener('mlAnalysisComplete', handleScanComplete as EventListener);
    window.addEventListener('threatDetected', handleThreatDetected as EventListener);
    window.addEventListener('globalThreatDetected', handleThreatDetected as EventListener);

    return () => {
      window.removeEventListener('scanStart', handleScanStart as EventListener);
      window.removeEventListener('scanStarted', handleScanStart as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
      window.removeEventListener('globalScanComplete', handleScanComplete as EventListener);
      window.removeEventListener('mlAnalysisComplete', handleScanComplete as EventListener);
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
      window.removeEventListener('globalThreatDetected', handleThreatDetected as EventListener);
    };
  }, []);

  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case 'low': return 'text-green-500 bg-green-500/10 border-green-500/20';
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-500';
      case 'running': return 'text-blue-500';
      case 'failed': return 'text-red-500';
      default: return 'text-gray-500';
    }
  };

  const getScanTypeIcon = (type: string) => {
    switch (type) {
      case 'machine-learning':
        return <Brain className="h-4 w-4" />;
      case 'fuzzing':
      default:
        return <Zap className="h-4 w-4" />;
    }
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto px-4 py-8 space-y-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white mb-2">Security Dashboard</h1>
          <p className="text-gray-400">Real-time monitoring and threat analysis</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
              <BarChart2 className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.totalScans}</div>
              <p className="text-xs text-muted-foreground">
                <ArrowUp className="h-3 w-3 inline mr-1 text-green-500" />
                {scanActive ? 'Scanning...' : 'Ready'}
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card/50 backdrop-blur-sm border-orange-900/30">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
              <Bug className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.vulnerabilitiesFound}</div>
              <p className="text-xs text-muted-foreground">
                Found in all scans
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card/50 backdrop-blur-sm border-red-900/30">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Critical Threats</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.criticalThreats}</div>
              <p className="text-xs text-muted-foreground">
                High priority issues
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card/50 backdrop-blur-sm border-green-900/30">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">System Health</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.systemHealth}%</div>
              <Progress value={stats.systemHealth} className="mt-2" />
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <LiveThreats />
          <MachineLearningScanner 
            scanActive={scanActive}
            scanCompleted={!scanActive && stats.totalScans > 0}
            dataset={[]}
            threatLevel={threatLevel}
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="lg:col-span-2 bg-card/50 backdrop-blur-sm border-gray-700/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Recent Scans
              </CardTitle>
              <CardDescription>Latest security scanning activity</CardDescription>
            </CardHeader>
            <CardContent>
              {recentScans.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">
                  <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No scans performed yet</p>
                  <p className="text-sm">Start a fuzzing scan to see results here</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {recentScans.map((scan) => (
                    <div key={scan.id} className="flex items-center justify-between p-3 bg-black/20 rounded-lg border border-gray-700/50">
                      <div className="flex items-center space-x-3">
                        <div className={`w-2 h-2 rounded-full ${getStatusColor(scan.status)}`} />
                        <div className="flex items-center space-x-2">
                          {getScanTypeIcon(scan.type || 'fuzzing')}
                          <div>
                            <p className="text-sm font-medium text-white">{scan.target}</p>
                            <p className="text-xs text-gray-400">{scan.timestamp}</p>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge className={getRiskLevelColor(scan.riskLevel)}>
                          {scan.riskLevel}
                        </Badge>
                        <span className="text-sm text-gray-300">{scan.vulnerabilities} issues</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-card/50 backdrop-blur-sm border-purple-900/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                Scanner Status
              </CardTitle>
              <CardDescription>Real-time scanning visualization</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-48 mb-4">
                <ScannerAnimation active={scanActive} threatLevel={threatLevel} />
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Status:</span>
                <Badge variant={scanActive ? "default" : "secondary"}>
                  {scanActive ? "Scanning" : "Ready"}
                </Badge>
              </div>
            </CardContent>
          </Card>
        </div>

        <Card className="bg-card/50 backdrop-blur-sm border-gray-700/30">
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Common security operations</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white">
                <Zap className="h-4 w-4 mr-2" />
                Start Fuzzing Scan
              </Button>
              <Button variant="outline" className="border-purple-600 text-purple-400 hover:bg-purple-600/10">
                <Brain className="h-4 w-4 mr-2" />
                ML Analysis
              </Button>
              <Button variant="outline" className="border-green-600 text-green-400 hover:bg-green-600/10">
                <FileText className="h-4 w-4 mr-2" />
                Generate Report
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
