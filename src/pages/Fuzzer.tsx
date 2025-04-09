
import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Play, Pause, StopCircle, AlertTriangle, FileText, Upload, PieChartIcon, BarChartIcon, ActivityIcon, Globe, Target, List } from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Checkbox } from "@/components/ui/checkbox";
import { PieChart, Pie, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';
import DashboardLayout from "@/components/layout/DashboardLayout";
import { ThreatLevelIndicator } from "@/components/dashboard/ThreatLevelIndicator";
import { EnhancedScannerAnimation } from "@/components/dashboard/EnhancedScannerAnimation";
import { Grid, GridItem } from "@/components/ui/grid";
import { WebFuzzer } from '@/backend/WebFuzzer';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";

// Colors for charts
const CHART_COLORS = {
  critical: '#ff2d55',
  high: '#ff9500',
  medium: '#ffcc00',
  low: '#34c759',
  info: '#0a84ff'
};

const RADIAN = Math.PI / 180;
const renderCustomizedLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, index, name }: any) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text x={x} y={y} fill="white" textAnchor={x > cx ? 'start' : 'end'} dominantBaseline="central">
      {`${name}: ${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

// Define vulnerability types for selection
const vulnerabilityTypes = [
  { id: 'xss', name: 'XSS (Cross-Site Scripting)', description: 'Tests for cross-site scripting vulnerabilities' },
  { id: 'sqli', name: 'SQL Injection', description: 'Tests for SQL injection vulnerabilities' },
  { id: 'lfi', name: 'Local File Inclusion', description: 'Tests for path traversal and file inclusion' },
  { id: 'rce', name: 'Remote Code Execution', description: 'Tests for command injection vulnerabilities' },
  { id: 'csrf', name: 'CSRF (Cross-Site Request Forgery)', description: 'Tests for CSRF vulnerabilities' },
  { id: 'auth', name: 'Authentication Bypass', description: 'Tests for authentication bypass methods' },
  { id: 'all', name: 'All Vulnerabilities', description: 'Tests for all vulnerability types' }
];

const Fuzzer = () => {
  // State for DVWA connection
  const [isDVWAConnected, setIsDVWAConnected] = useState(false);
  const [dvwaUrl, setDvwaUrl] = useState("");
  const [dvwaUsername, setDvwaUsername] = useState("admin");
  const [dvwaPassword, setDvwaPassword] = useState("password");
  const [isConnecting, setIsConnecting] = useState(false);
  
  // State for fuzzing process
  const [targetUrl, setTargetUrl] = useState('http://localhost/dvwa/vulnerabilities/xss_r/');
  const [wordlistFile, setWordlistFile] = useState('wordlists/xss-payloads.txt');
  const [selectedVulnerabilities, setSelectedVulnerabilities] = useState<string[]>(['xss']);
  const [scanActive, setScanActive] = useState(false);
  const [scanPaused, setScanPaused] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [payloadsProcessed, setPayloadsProcessed] = useState(0);
  const [totalPayloads, setTotalPayloads] = useState(0);
  
  // State for results
  const [logs, setLogs] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const [dataset, setDataset] = useState<any[]>([]);
  const [fuzzer, setFuzzer] = useState<WebFuzzer | null>(null);
  const [activeTab, setActiveTab] = useState("logs");
  const [securityLevel, setSecurityLevel] = useState("low");
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [exportFormat, setExportFormat] = useState("json");
  const [exportContent, setExportContent] = useState("");
  
  // Initialize fuzzer
  useEffect(() => {
    const newFuzzer = new WebFuzzer(targetUrl, wordlistFile);
    setFuzzer(newFuzzer);
  }, [targetUrl, wordlistFile]);

  // Connect to DVWA
  const handleDVWAConnect = async () => {
    if (!dvwaUrl) {
      toast.error("DVWA URL is required");
      return;
    }

    setIsConnecting(true);

    try {
      if (fuzzer) {
        const result = await fuzzer.connectToDVWA(
          dvwaUrl,
          dvwaUsername,
          dvwaPassword,
          securityLevel
        );

        if (result.success) {
          setIsDVWAConnected(true);
          toast.success("Connected to DVWA successfully");
          setTargetUrl(`${dvwaUrl}/vulnerabilities/xss_r/`);
        } else {
          toast.error("Failed to connect to DVWA");
        }
      }
    } catch (error) {
      toast.error(`Connection error: ${error}`);
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDVWADisconnect = () => {
    setIsDVWAConnected(false);
    toast.info("Disconnected from DVWA");
  };

  // Handle start fuzzing
  const handleStartFuzzing = async () => {
    if (!fuzzer) return;
    
    setScanActive(true);
    setScanPaused(false);
    
    try {
      await fuzzer.startFuzzing(
        selectedVulnerabilities,
        (progress, processed, total) => {
          setScanProgress(progress);
          setPayloadsProcessed(processed);
          setTotalPayloads(total);
        },
        (dataset, logs, reports) => {
          setDataset(dataset);
          setLogs(logs);
          setReports(reports);
          toast.success("Fuzzing completed successfully");
          setScanActive(false);
        }
      );
    } catch (error) {
      toast.error(`Fuzzing error: ${error}`);
      setScanActive(false);
    }
  };

  // Handle pause fuzzing
  const handlePauseFuzzing = () => {
    if (!fuzzer) return;
    
    if (scanActive && !scanPaused) {
      fuzzer.pauseScan();
      setScanPaused(true);
      toast.info("Fuzzing paused");
    } else if (scanPaused) {
      fuzzer.resumeScan();
      setScanPaused(false);
      toast.info("Fuzzing resumed");
    }
  };

  // Handle stop fuzzing
  const handleStopFuzzing = () => {
    if (!fuzzer) return;
    
    fuzzer.stopScan();
    setScanActive(false);
    setScanPaused(false);
    toast.info("Fuzzing stopped");
  };

  // Handle vulnerability type selection
  const handleVulnerabilityChange = (vulnerabilityId: string) => {
    if (vulnerabilityId === 'all') {
      setSelectedVulnerabilities(['all']);
    } else {
      // Remove 'all' if it's selected and add the new vulnerability
      const newSelection = selectedVulnerabilities.filter(v => v !== 'all');
      
      if (newSelection.includes(vulnerabilityId)) {
        setSelectedVulnerabilities(newSelection.filter(v => v !== vulnerabilityId));
      } else {
        setSelectedVulnerabilities([...newSelection, vulnerabilityId]);
      }
    }
  };

  // Calculate statistics for charts
  const calculateSeverityCounts = () => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    dataset.forEach(item => {
      if (item.severity) {
        counts[item.severity as keyof typeof counts]++;
      }
    });
    
    return Object.entries(counts).map(([key, value]) => ({
      name: key.charAt(0).toUpperCase() + key.slice(1),
      value
    }));
  };

  const calculateVulnerabilityTypeCounts = () => {
    const counts: Record<string, number> = {};
    
    dataset.forEach(item => {
      if (item.vulnerability_type) {
        counts[item.vulnerability_type] = (counts[item.vulnerability_type] || 0) + 1;
      }
    });
    
    return Object.entries(counts).map(([key, value]) => ({
      name: key.toUpperCase(),
      count: value
    }));
  };

  // Generate export content
  const generateExportContent = () => {
    switch (activeTab) {
      case "logs":
        return exportFormat === "json" 
          ? JSON.stringify(logs, null, 2) 
          : logs.map(log => `[${log.timestamp}] ${log.message}`).join('\n');
      case "reports":
        return exportFormat === "json" 
          ? JSON.stringify(reports, null, 2) 
          : reports.map(report => report.data).join('\n\n');
      case "results":
        return exportFormat === "json" 
          ? JSON.stringify(dataset, null, 2) 
          : dataset.map(item => {
              return `Payload: ${item.payload}\nSeverity: ${item.severity}\nLabel: ${item.label}\nTimestamp: ${item.timestamp}`;
            }).join('\n\n');
      default:
        return "";
    }
  };

  // Handle export dialog
  const handleShowExportDialog = () => {
    const content = generateExportContent();
    setExportContent(content);
    setShowExportDialog(true);
  };

  const handleExportData = () => {
    const content = exportContent;
    const blob = new Blob([content], { type: exportFormat === "json" ? "application/json" : "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fuzzer-${activeTab}.${exportFormat === "json" ? "json" : "txt"}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setShowExportDialog(false);
    toast.success(`${activeTab.charAt(0).toUpperCase() + activeTab.slice(1)} exported successfully`);
  };

  // Chart data
  const severityData = calculateSeverityCounts();
  const vulnerabilityTypeData = calculateVulnerabilityTypeCounts();

  // Filter logs by type
  const activityLogs = logs.filter(log => log.type === "activity");
  
  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Web Fuzzer</h1>
            <p className="text-muted-foreground">
              Test web applications for security vulnerabilities through fuzzing.
            </p>
          </div>
          
          {/* DVWA Connection Status */}
          <Card className="w-full md:w-auto bg-card/50 backdrop-blur-sm border-indigo-900/30">
            <CardHeader className="py-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium">DVWA Connection</CardTitle>
                {isDVWAConnected && (
                  <Badge className="bg-green-500/80 text-white px-2 py-0.5 text-xs flex items-center gap-1">
                    <div className="h-2 w-2 rounded-full bg-green-200 animate-pulse"></div>
                    Connected
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="py-2 px-4">
              {!isDVWAConnected ? (
                <div className="flex gap-2">
                  <Input 
                    placeholder="DVWA URL" 
                    value={dvwaUrl}
                    onChange={(e) => setDvwaUrl(e.target.value)}
                    className="h-8 text-xs"
                  />
                  <Button 
                    size="sm" 
                    onClick={handleDVWAConnect}
                    disabled={isConnecting}
                    className="h-8"
                  >
                    {isConnecting ? "Connecting..." : "Connect"}
                  </Button>
                </div>
              ) : (
                <div className="flex items-center justify-between">
                  <div className="text-xs font-mono truncate max-w-[150px]">{dvwaUrl}</div>
                  <Button 
                    size="sm" 
                    variant="destructive"
                    onClick={handleDVWADisconnect}
                    className="h-7 text-xs"
                  >
                    Disconnect
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Configuration and Results Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-7 gap-6">
          {/* Configuration Panel */}
          <Card className="lg:col-span-2 bg-card/50 backdrop-blur-sm border-indigo-900/30">
            <CardHeader>
              <CardTitle>Fuzzing Configuration</CardTitle>
              <CardDescription>Configure target and fuzzing options</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Target URL */}
              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="targetUrl">
                  Target URL
                </label>
                <Input
                  id="targetUrl"
                  placeholder="http://example.com/vulnerable-page"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>
              
              {/* Security Level (for DVWA) */}
              {isDVWAConnected && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">
                    DVWA Security Level
                  </label>
                  <Select 
                    value={securityLevel}
                    onValueChange={setSecurityLevel}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Security Level" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="impossible">Impossible</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
              
              {/* Vulnerability Type Selection */}
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  Vulnerability Types to Test
                </label>
                <div className="space-y-2 border p-2 rounded-md max-h-60 overflow-auto">
                  {vulnerabilityTypes.map((type) => (
                    <div key={type.id} className="flex items-start space-x-2">
                      <Checkbox 
                        id={`vuln-${type.id}`} 
                        checked={selectedVulnerabilities.includes(type.id)}
                        onCheckedChange={() => handleVulnerabilityChange(type.id)}
                      />
                      <div className="space-y-0.5">
                        <label htmlFor={`vuln-${type.id}`} className="text-sm font-medium cursor-pointer">
                          {type.name}
                        </label>
                        <p className="text-xs text-muted-foreground">
                          {type.description}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
            <CardFooter className="flex flex-col gap-2">
              {/* Control Buttons */}
              <div className="flex gap-2 w-full">
                <Button 
                  className="flex-1" 
                  onClick={handleStartFuzzing}
                  disabled={scanActive || !fuzzer}
                >
                  <Play className="mr-1 h-4 w-4" /> Start
                </Button>
                
                <Button 
                  className="flex-1" 
                  variant="outline" 
                  onClick={handlePauseFuzzing}
                  disabled={!scanActive || !fuzzer}
                >
                  {scanPaused ? (
                    <>
                      <Play className="mr-1 h-4 w-4" /> Resume
                    </>
                  ) : (
                    <>
                      <Pause className="mr-1 h-4 w-4" /> Pause
                    </>
                  )}
                </Button>
                
                <Button 
                  className="flex-1" 
                  variant="destructive" 
                  onClick={handleStopFuzzing}
                  disabled={!scanActive || !fuzzer}
                >
                  <StopCircle className="mr-1 h-4 w-4" /> Stop
                </Button>
              </div>
              
              {/* Progress */}
              {scanActive && (
                <div className="w-full space-y-1 mt-2">
                  <div className="flex justify-between text-xs">
                    <span>Progress</span>
                    <span>{scanProgress.toFixed(1)}%</span>
                  </div>
                  <Progress value={scanProgress} className="h-2" />
                  <div className="text-xs text-right text-muted-foreground">
                    {payloadsProcessed} / {totalPayloads} payloads processed
                  </div>
                </div>
              )}
            </CardFooter>
          </Card>
          
          {/* Results Panel */}
          <Card className="lg:col-span-5 bg-card/50 backdrop-blur-sm border-indigo-900/30 flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex justify-between items-center">
                <CardTitle>Fuzzing Results</CardTitle>
                <div className="flex gap-2">
                  <Button 
                    variant="outline" 
                    size="sm" 
                    disabled={dataset.length === 0}
                    onClick={handleShowExportDialog}
                  >
                    <FileText className="h-4 w-4 mr-1" /> Export
                  </Button>
                </div>
              </div>
              
              <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                <TabsList className="grid grid-cols-4 mb-2">
                  <TabsTrigger value="logs">Activity Logs</TabsTrigger>
                  <TabsTrigger value="reports">Reports</TabsTrigger>
                  <TabsTrigger value="results">Results</TabsTrigger>
                  <TabsTrigger value="analytics">Analytics</TabsTrigger>
                </TabsList>
              </Tabs>
            </CardHeader>
            
            <CardContent className="flex-1 pb-1 overflow-hidden flex flex-col">
              <TabsContent value="logs" className="flex-1 overflow-hidden flex flex-col h-full mt-0">
                <ScrollArea className="flex-1 border rounded-md h-[40vh]">
                  <div className="p-4 space-y-2 font-mono text-sm">
                    {activityLogs.length > 0 ? (
                      activityLogs.map((log, index) => (
                        <div key={index} className="flex">
                          <span className="text-muted-foreground mr-2">
                            [{new Date(log.timestamp).toLocaleTimeString()}]
                          </span>
                          <span>{log.message}</span>
                        </div>
                      ))
                    ) : (
                      <div className="text-muted-foreground text-center py-8">
                        No logs to display. Start the fuzzer to generate logs.
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>
              
              <TabsContent value="reports" className="flex-1 overflow-hidden flex flex-col h-full mt-0">
                <ScrollArea className="flex-1 border rounded-md h-[40vh]">
                  <div className="p-4 space-y-4">
                    {reports.length > 0 ? (
                      reports.map((report, index) => (
                        <div key={index} className="bg-muted p-3 rounded-md font-mono text-xs whitespace-pre-wrap">
                          {report.data}
                        </div>
                      ))
                    ) : (
                      <div className="text-muted-foreground text-center py-8">
                        No reports to display. Start the fuzzer to generate reports.
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>
              
              <TabsContent value="results" className="flex-1 overflow-hidden flex flex-col h-full mt-0">
                <ScrollArea className="flex-1 border rounded-md h-[40vh]">
                  <div className="p-4">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b">
                          <th className="text-left py-2">Payload</th>
                          <th className="text-left py-2">Type</th>
                          <th className="text-left py-2">Severity</th>
                          <th className="text-left py-2">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {dataset.length > 0 ? (
                          dataset.map((item, index) => (
                            <tr key={index} className="border-b hover:bg-muted/50">
                              <td className="py-2 font-mono text-xs truncate max-w-[200px]">
                                {item.payload}
                              </td>
                              <td className="py-2">
                                {item.vulnerability_type || "unknown"}
                              </td>
                              <td className="py-2">
                                <Badge 
                                  variant="outline" 
                                  className={`
                                    ${item.severity === 'critical' && 'border-red-500 text-red-500'}
                                    ${item.severity === 'high' && 'border-orange-500 text-orange-500'}
                                    ${item.severity === 'medium' && 'border-yellow-500 text-yellow-500'}
                                    ${item.severity === 'low' && 'border-green-500 text-green-500'}
                                    ${item.severity === 'info' && 'border-blue-500 text-blue-500'}
                                  `}
                                >
                                  {item.severity || "unknown"}
                                </Badge>
                              </td>
                              <td className="py-2">
                                <Badge 
                                  variant="outline" 
                                  className={`
                                    ${item.label === 'malicious' && 'border-red-500 bg-red-500/10'}
                                    ${item.label === 'suspicious' && 'border-yellow-500 bg-yellow-500/10'}
                                    ${item.label === 'safe' && 'border-green-500 bg-green-500/10'}
                                  `}
                                >
                                  {item.label}
                                </Badge>
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan={4} className="text-center text-muted-foreground py-8">
                              No results to display. Start the fuzzer to generate results.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </ScrollArea>
              </TabsContent>
              
              <TabsContent value="analytics" className="flex-1 overflow-hidden h-full mt-0">
                {dataset.length > 0 ? (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 h-[40vh]">
                    <div className="border rounded-md p-4">
                      <h3 className="text-sm font-medium mb-2">Severity Distribution</h3>
                      <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                          <Pie
                            data={severityData}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={renderCustomizedLabel}
                            outerRadius={80}
                            fill="#8884d8"
                            dataKey="value"
                          >
                            {severityData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={CHART_COLORS[entry.name.toLowerCase() as keyof typeof CHART_COLORS]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="border rounded-md p-4">
                      <h3 className="text-sm font-medium mb-2">Vulnerability Types</h3>
                      <ResponsiveContainer width="100%" height={250}>
                        <BarChart
                          data={vulnerabilityTypeData}
                          margin={{
                            top: 5,
                            right: 30,
                            left: 20,
                            bottom: 5,
                          }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" />
                          <YAxis />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="count" fill="#8884d8">
                            {vulnerabilityTypeData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={Object.values(CHART_COLORS)[index % Object.values(CHART_COLORS).length]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                ) : (
                  <div className="text-muted-foreground text-center py-8">
                    No data available for analysis. Start the fuzzer to generate data.
                  </div>
                )}
              </TabsContent>
            </CardContent>
          </Card>
        </div>

        {/* Visualization */}
        <Card className="bg-card/50 backdrop-blur-sm border-indigo-900/30">
          <CardHeader>
            <CardTitle>Real-time Scanning Visualization</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] rounded-md overflow-hidden border border-muted">
              <EnhancedScannerAnimation 
                active={scanActive} 
                threatLevel={
                  dataset.some(item => item.severity === 'critical') ? 'critical' :
                  dataset.some(item => item.severity === 'high') ? 'high' :
                  dataset.some(item => item.severity === 'medium') ? 'medium' :
                  dataset.some(item => item.severity === 'low') ? 'low' : 
                  'none'
                }
              />
            </div>
          </CardContent>
        </Card>

        {/* Export Dialog */}
        <Dialog open={showExportDialog} onOpenChange={setShowExportDialog}>
          <DialogContent className="sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>Export {activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}</DialogTitle>
              <DialogDescription>
                Export your fuzzing data in the selected format.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <div className="grid grid-cols-2 gap-2">
                  <label className="flex items-center space-x-2">
                    <input 
                      type="radio" 
                      checked={exportFormat === "json"} 
                      onChange={() => setExportFormat("json")}
                      className="h-4 w-4"
                    />
                    <span>JSON</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input 
                      type="radio" 
                      checked={exportFormat === "text"} 
                      onChange={() => setExportFormat("text")}
                      className="h-4 w-4"
                    />
                    <span>Text</span>
                  </label>
                </div>
              </div>
              
              <ScrollArea className="h-[300px] border rounded-md p-2">
                <pre className="text-xs font-mono whitespace-pre-wrap">{exportContent}</pre>
              </ScrollArea>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowExportDialog(false)}>Cancel</Button>
              <Button onClick={handleExportData}>Export</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
