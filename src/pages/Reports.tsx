
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { CalendarDays, Download, Shield, Bug, AlertTriangle } from 'lucide-react';

interface ScanReport {
  id: string;
  timestamp: Date;
  targetUrl: string;
  vulnerabilitiesFound: number;
  payloadsTested: number;
  duration: string;
  status: 'completed' | 'failed' | 'in-progress';
  severity: 'low' | 'medium' | 'high' | 'critical';
}

interface ThreatReport {
  id: string;
  timestamp: Date;
  threatType: string;
  payload: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  target: string;
}

const Reports = () => {
  const [scanReports, setScanReports] = useState<ScanReport[]>([]);
  const [threatReports, setThreatReports] = useState<ThreatReport[]>([]);
  const [totalScans, setTotalScans] = useState(0);
  const [totalVulnerabilities, setTotalVulnerabilities] = useState(0);

  useEffect(() => {
    // Listen for scan completion to generate reports
    const handleScanComplete = (event: CustomEvent) => {
      const { sessionId, vulnerabilities = 0, payloadsTested = 0 } = event.detail || {};
      
      const newReport: ScanReport = {
        id: sessionId || `scan-${Date.now()}`,
        timestamp: new Date(),
        targetUrl: 'http://localhost:8080',
        vulnerabilitiesFound: vulnerabilities,
        payloadsTested,
        duration: `${Math.floor(Math.random() * 5) + 1}m ${Math.floor(Math.random() * 60)}s`,
        status: 'completed',
        severity: vulnerabilities > 3 ? 'critical' : vulnerabilities > 1 ? 'high' : vulnerabilities > 0 ? 'medium' : 'low'
      };

      setScanReports(prev => [newReport, ...prev].slice(0, 20));
      setTotalScans(prev => prev + 1);
      setTotalVulnerabilities(prev => prev + vulnerabilities);
    };

    // Listen for threat detection to generate threat reports
    const handleThreatDetected = (event: CustomEvent) => {
      const { payload, vulnerabilityType, severity = 'medium', field } = event.detail;

      const newThreatReport: ThreatReport = {
        id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        timestamp: new Date(),
        threatType: vulnerabilityType || 'Unknown',
        payload: payload || 'N/A',
        severity: severity.toLowerCase(),
        target: field || 'General'
      };

      setThreatReports(prev => [newThreatReport, ...prev].slice(0, 50));
    };

    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    window.addEventListener('threatDetected', handleThreatDetected as EventListener);

    return () => {
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
    };
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-purple-500/10 text-purple-500 border-purple-500/20';
      case 'high': return 'bg-red-500/10 text-red-500 border-red-500/20';
      case 'medium': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      case 'low': return 'bg-green-500/10 text-green-500 border-green-500/20';
      default: return 'bg-gray-500/10 text-gray-500 border-gray-500/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500/10 text-green-500';
      case 'failed': return 'bg-red-500/10 text-red-500';
      case 'in-progress': return 'bg-blue-500/10 text-blue-500';
      default: return 'bg-gray-500/10 text-gray-500';
    }
  };

  const exportReport = (reportId: string) => {
    // Simulate report export
    const report = scanReports.find(r => r.id === reportId);
    if (report) {
      const reportData = {
        report,
        threats: threatReports.filter(t => 
          Math.abs(t.timestamp.getTime() - report.timestamp.getTime()) < 60000 // Within 1 minute
        )
      };
      
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `fuzzer-report-${reportId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-6">Security Reports</h1>
        
        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Shield className="h-8 w-8 text-blue-500" />
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
                <Bug className="h-8 w-8 text-red-500" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-muted-foreground">Vulnerabilities Found</p>
                  <p className="text-2xl font-bold">{totalVulnerabilities}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <AlertTriangle className="h-8 w-8 text-yellow-500" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-muted-foreground">Threat Reports</p>
                  <p className="text-2xl font-bold">{threatReports.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="scans" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="scans">Scan Reports</TabsTrigger>
            <TabsTrigger value="threats">Threat Reports</TabsTrigger>
          </TabsList>
          
          <TabsContent value="scans" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Recent Fuzzing Scans</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  {scanReports.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No scan reports available</p>
                      <p className="text-sm">Run fuzzing scans to generate reports</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {scanReports.map((report) => (
                        <div key={report.id} className="border rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center space-x-2">
                              <CalendarDays className="h-4 w-4 text-muted-foreground" />
                              <span className="text-sm text-muted-foreground">
                                {report.timestamp.toLocaleString()}
                              </span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge variant="outline" className={getSeverityColor(report.severity)}>
                                {report.severity}
                              </Badge>
                              <Badge variant="outline" className={getStatusColor(report.status)}>
                                {report.status}
                              </Badge>
                            </div>
                          </div>
                          
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-3">
                            <div>
                              <p className="text-xs text-muted-foreground">Target</p>
                              <p className="text-sm font-medium">{report.targetUrl}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground">Vulnerabilities</p>
                              <p className="text-sm font-medium">{report.vulnerabilitiesFound}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground">Payloads Tested</p>
                              <p className="text-sm font-medium">{report.payloadsTested}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground">Duration</p>
                              <p className="text-sm font-medium">{report.duration}</p>
                            </div>
                          </div>
                          
                          <div className="flex justify-end">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => exportReport(report.id)}
                            >
                              <Download className="h-4 w-4 mr-2" />
                              Export
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="threats" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Detected Threats</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  {threatReports.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Bug className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No threat reports available</p>
                      <p className="text-sm">Threats will appear here when detected during scans</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {threatReports.map((threat) => (
                        <div key={threat.id} className="border rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center space-x-2">
                              <span className="font-medium">{threat.threatType.toUpperCase()}</span>
                              <Badge variant="outline" className={getSeverityColor(threat.severity)}>
                                {threat.severity}
                              </Badge>
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {threat.timestamp.toLocaleString()}
                            </span>
                          </div>
                          
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <p className="text-xs text-muted-foreground">Target Field</p>
                              <p className="text-sm font-medium">{threat.target}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground">Payload</p>
                              <p className="text-sm font-mono bg-muted px-2 py-1 rounded truncate">
                                {threat.payload}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
};

export default Reports;
