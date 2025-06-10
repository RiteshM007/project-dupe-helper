
import React, { useEffect, useState } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { FileDown, Clock, Target, Bug, Shield, AlertTriangle } from 'lucide-react';
import { useFuzzing } from '@/context/FuzzingContext';
import { toast } from '@/hooks/use-toast';

const Reports = () => {
  const { fuzzingResult, threatReports, mlResults, lastUpdated } = useFuzzing();
  const [recentUpdates, setRecentUpdates] = useState<string[]>([]);

  useEffect(() => {
    console.log('Reports: Component mounted, fuzzing result:', fuzzingResult);
    console.log('Reports: Threat reports:', threatReports);
    console.log('Reports: ML results:', mlResults);
    console.log('Reports: Last updated:', lastUpdated);
  }, [fuzzingResult, threatReports, mlResults, lastUpdated]);

  // Track recent updates
  useEffect(() => {
    if (lastUpdated) {
      setRecentUpdates(prev => [
        `Data updated at ${new Date(lastUpdated).toLocaleString()}`,
        ...prev.slice(0, 4)
      ]);
    }
  }, [lastUpdated]);

  const handleExportReport = () => {
    if (!fuzzingResult) {
      toast({
        title: "No Data to Export",
        description: "Please run a fuzzing scan first",
        variant: "destructive",
      });
      return;
    }

    const reportData = {
      fuzzingResult,
      threatReports,
      mlResults,
      generatedAt: new Date().toISOString(),
      summary: {
        totalVulnerabilities: fuzzingResult.vulnerabilities,
        totalPayloadsTested: fuzzingResult.payloadsTested,
        threatReportsCount: threatReports.length,
        mlResultsCount: mlResults.length
      }
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: "Report Exported",
      description: "Security report has been downloaded successfully",
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-4 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Security Reports</h1>
            <p className="text-muted-foreground">Comprehensive security testing results and analysis</p>
          </div>
          <Button onClick={handleExportReport} disabled={!fuzzingResult}>
            <FileDown className="mr-2 h-4 w-4" />
            Export Report
          </Button>
        </div>

        {lastUpdated && (
          <div className="p-4 bg-blue-900/20 border border-blue-500/30 rounded-lg">
            <p className="text-blue-400 font-medium">
              <Clock className="inline-block h-4 w-4 mr-2" />
              Last Updated: {new Date(lastUpdated).toLocaleString()}
            </p>
          </div>
        )}

        {!fuzzingResult ? (
          <Card>
            <CardContent className="p-8 text-center">
              <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <h3 className="text-xl font-semibold mb-2">No Scan Results Available</h3>
              <p className="text-muted-foreground mb-4">
                Run a fuzzing scan to generate security reports and analysis
              </p>
              <Button onClick={() => window.location.href = '/fuzzer'}>
                Start Fuzzing Scan
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-6">
            {/* Main Fuzzing Results */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5" />
                  Fuzzing Scan Results
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-card rounded-lg border">
                    <div className="text-2xl font-bold">{fuzzingResult.vulnerabilities}</div>
                    <div className="text-sm text-muted-foreground">Vulnerabilities Found</div>
                  </div>
                  <div className="p-4 bg-card rounded-lg border">
                    <div className="text-2xl font-bold">{fuzzingResult.payloadsTested}</div>
                    <div className="text-sm text-muted-foreground">Payloads Tested</div>
                  </div>
                  <div className="p-4 bg-card rounded-lg border">
                    <div className="text-2xl font-bold">{fuzzingResult.duration}</div>
                    <div className="text-sm text-muted-foreground">Scan Duration</div>
                  </div>
                  <div className="p-4 bg-card rounded-lg border">
                    <Badge className={getSeverityColor(fuzzingResult.severity)}>
                      {fuzzingResult.severity.toUpperCase()}
                    </Badge>
                    <div className="text-sm text-muted-foreground mt-1">Risk Level</div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="font-semibold">Scan Details</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium">Session ID:</span>
                      <span className="ml-2 font-mono text-muted-foreground">{fuzzingResult.sessionId}</span>
                    </div>
                    <div>
                      <span className="font-medium">Target URL:</span>
                      <span className="ml-2 text-muted-foreground">{fuzzingResult.targetUrl}</span>
                    </div>
                    <div>
                      <span className="font-medium">Scan Type:</span>
                      <span className="ml-2 text-muted-foreground">{fuzzingResult.type}</span>
                    </div>
                    <div>
                      <span className="font-medium">Timestamp:</span>
                      <span className="ml-2 text-muted-foreground">
                        {new Date(fuzzingResult.timestamp).toLocaleString()}
                      </span>
                    </div>
                    {fuzzingResult.payloadSet && (
                      <div>
                        <span className="font-medium">Payload Set:</span>
                        <span className="ml-2 text-muted-foreground">{fuzzingResult.payloadSet}</span>
                      </div>
                    )}
                    {fuzzingResult.fuzzingMode && (
                      <div>
                        <span className="font-medium">Fuzzing Mode:</span>
                        <span className="ml-2 text-muted-foreground">{fuzzingResult.fuzzingMode}</span>
                      </div>
                    )}
                  </div>
                </div>

                {fuzzingResult.findings && fuzzingResult.findings.length > 0 && (
                  <div className="space-y-2">
                    <h4 className="font-semibold">Detailed Findings</h4>
                    <div className="space-y-2 max-h-60 overflow-y-auto">
                      {fuzzingResult.findings.map((finding, index) => (
                        <div key={index} className="p-3 bg-muted rounded-md">
                          <div className="flex items-center justify-between">
                            <span className="font-medium">{finding.type || 'Unknown Vulnerability'}</span>
                            <Badge className={getSeverityColor(finding.severity || 'medium')}>
                              {(finding.severity || 'medium').toUpperCase()}
                            </Badge>
                          </div>
                          {finding.payload && (
                            <div className="mt-1 text-sm text-muted-foreground font-mono">
                              Payload: {finding.payload}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Threat Reports */}
            {threatReports.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5" />
                    Real-time Threat Detection ({threatReports.length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {threatReports.slice(0, 10).map((threat) => (
                      <div key={threat.id} className="p-3 bg-muted rounded-md">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">{threat.threatType}</span>
                          <div className="flex items-center gap-2">
                            <Badge className={getSeverityColor(threat.severity)}>
                              {threat.severity.toUpperCase()}
                            </Badge>
                            <span className="text-sm text-muted-foreground">
                              {new Date(threat.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                        <div className="mt-1 text-sm text-muted-foreground">
                          Target: {threat.target} | Payload: {threat.payload}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* ML Results */}
            {mlResults.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bug className="h-5 w-5" />
                    Machine Learning Analysis ({mlResults.length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {mlResults.slice(0, 5).map((result, index) => (
                      <div key={index} className="p-3 bg-muted rounded-md">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">ML Analysis Result #{index + 1}</span>
                          <span className="text-sm text-muted-foreground">
                            {new Date(result.timestamp || Date.now()).toLocaleString()}
                          </span>
                        </div>
                        <div className="mt-1 text-sm text-muted-foreground">
                          <pre className="whitespace-pre-wrap">{JSON.stringify(result, null, 2)}</pre>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Recent Updates */}
            {recentUpdates.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Clock className="h-5 w-5" />
                    Recent Updates
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-1">
                    {recentUpdates.map((update, index) => (
                      <div key={index} className="text-sm text-muted-foreground">
                        • {update}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default Reports;
