
import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Play, Pause, StopCircle, AlertTriangle, FileText, Upload, PieChart as PieChartIcon, BarChart as BarChartIcon, ActivityIcon } from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PieChart, Pie, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';
import DashboardLayout from "@/components/layout/DashboardLayout";
import { ThreatLevelIndicator } from "@/components/dashboard/ThreatLevelIndicator";
import { CyberpunkScannerAnimation } from "@/components/dashboard/CyberpunkScannerAnimation";

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

const Fuzzer = () => {
  const [targetUrl, setTargetUrl] = useState('http://localhost/dvwa');
  const [scanMode, setScanMode] = useState('active');
  const [payloads, setPayloads] = useState<string[]>([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logMessages, setLogMessages] = useState<string[]>([]);
  const [threats, setThreats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  const [results, setResults] = useState<{id: string, payload: string, responseCode: number, alertDetected: boolean, errorDetected: boolean, bodyChanged: boolean, timestamp: number, severity: string}[]>([]);
  const [showAnalytics, setShowAnalytics] = useState(false);
  const [scanCompleted, setScanCompleted] = useState(false);
  const [threatLevel, setThreatLevel] = useState<'none' | 'low' | 'medium' | 'high' | 'critical'>('none');

  // Simulate uploading a wordlist file
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        const lines = content.split('\n').filter(line => line.trim());
        setPayloads(lines);
        addLogMessage(`Loaded ${lines.length} payloads from wordlist.`);
        toast.success(`Wordlist loaded: ${lines.length} payloads`);
      };
      reader.readAsText(file);
    }
  };

  // Add a log message
  const addLogMessage = (message: string) => {
    const timestamp = new Date().toISOString();
    setLogMessages(prev => [`${timestamp} - ${message}`, ...prev]);
  };

  // Start the fuzzing process
  const startFuzzing = () => {
    if (payloads.length === 0) {
      toast.error("No payloads loaded. Please upload a wordlist first.");
      return;
    }

    setScanning(true);
    setProgress(0);
    setShowAnalytics(false);
    setScanCompleted(false);
    setThreats({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    });
    setResults([]);
    setThreatLevel('none');
    
    addLogMessage(`Started fuzzing target: ${targetUrl}`);
    addLogMessage(`Scan mode: ${scanMode}`);
    
    // Simulate the fuzzing process
    simulateFuzzing();
  };

  // Pause the fuzzing process
  const pauseFuzzing = () => {
    setScanning(false);
    addLogMessage("Fuzzing paused.");
    toast.info("Scan paused");
  };

  // Stop the fuzzing process
  const stopFuzzing = () => {
    setScanning(false);
    setProgress(0);
    addLogMessage("Fuzzing stopped.");
    toast.info("Scan stopped");
    setThreatLevel('none');
  };

  // Simulate the fuzzing process
  const simulateFuzzing = () => {
    let currentProgress = 0;
    let currentThreats = { critical: 0, high: 0, medium: 0, low: 0 };
    const newResults: typeof results = [];
    
    const interval = setInterval(() => {
      if (currentProgress >= 100) {
        clearInterval(interval);
        setScanning(false);
        setScanCompleted(true);
        setShowAnalytics(true);
        
        // Set final threat level based on findings
        if (currentThreats.critical > 0) {
          setThreatLevel('critical');
        } else if (currentThreats.high > 0) {
          setThreatLevel('high');
        } else if (currentThreats.medium > 0) {
          setThreatLevel('medium');
        } else if (currentThreats.low > 0) {
          setThreatLevel('low');
        }
        
        addLogMessage("Fuzzing process completed.");
        toast.success("Scan completed!");
        return;
      }

      // Increment progress
      currentProgress += Math.random() * 5;
      setProgress(Math.min(currentProgress, 100));

      // Simulate finding vulnerabilities
      if (Math.random() > 0.85) {
        const randomPayload = payloads[Math.floor(Math.random() * payloads.length)];
        const threatType = Math.random();
        let severity = "";
        
        if (threatType > 0.9) {
          currentThreats.critical += 1;
          severity = "Critical";
          if (currentProgress > 50 && threatLevel !== 'critical') {
            setThreatLevel('critical');
          }
        } else if (threatType > 0.7) {
          currentThreats.high += 1;
          severity = "High";
          if (currentProgress > 50 && threatLevel !== 'critical' && threatLevel !== 'high') {
            setThreatLevel('high');
          }
        } else if (threatType > 0.4) {
          currentThreats.medium += 1;
          severity = "Medium";
          if (currentProgress > 50 && threatLevel === 'none' || threatLevel === 'low') {
            setThreatLevel('medium');
          }
        } else {
          currentThreats.low += 1;
          severity = "Low";
          if (currentProgress > 30 && threatLevel === 'none') {
            setThreatLevel('low');
          }
        }

        setThreats({ ...currentThreats });
        
        // Generate a random result
        const newResult = {
          id: Math.random().toString(36).substring(2, 15),
          payload: randomPayload,
          responseCode: Math.random() > 0.7 ? 500 : 200,
          alertDetected: Math.random() > 0.7,
          errorDetected: Math.random() > 0.8,
          bodyChanged: Math.random() > 0.5,
          timestamp: Date.now(),
          severity: severity.toLowerCase()
        };
        
        newResults.push(newResult);
        setResults(prev => [newResult, ...prev]);
        
        addLogMessage(`${severity} threat detected with payload: ${randomPayload}`);
      }
    }, 300);

    return () => clearInterval(interval);
  };

  // Export results
  const exportResults = (format: string) => {
    toast.success(`Results exported in ${format.toUpperCase()} format`);
    addLogMessage(`Exported results to ${format.toUpperCase()} file.`);
  };

  // Prepare data for pie chart
  const getPieChartData = () => {
    return [
      { name: 'Critical', value: threats.critical, color: CHART_COLORS.critical },
      { name: 'High', value: threats.high, color: CHART_COLORS.high },
      { name: 'Medium', value: threats.medium, color: CHART_COLORS.medium },
      { name: 'Low', value: threats.low, color: CHART_COLORS.low }
    ].filter(item => item.value > 0); // Only show categories with values
  };

  // Prepare data for bar chart
  const getVulnerabilityTypeData = () => {
    const vulnTypes: Record<string, number> = {};
    
    results.forEach(result => {
      let type = 'Other';
      
      if (result.payload.includes('<script')) type = 'XSS';
      else if (result.payload.includes('UNION') || result.payload.includes("'")) type = 'SQL Injection';
      else if (result.payload.includes('../')) type = 'Path Traversal';
      else if (result.payload.includes(';')) type = 'Command Injection';
      
      vulnTypes[type] = (vulnTypes[type] || 0) + 1;
    });
    
    return Object.entries(vulnTypes).map(([name, value]) => ({ name, value }));
  };

  // Prepare data for response code distribution
  const getResponseCodeData = () => {
    const codeCounts: Record<string, number> = {};
    
    results.forEach(result => {
      const codeRange = result.responseCode < 300 ? '2xx' : 
                       result.responseCode < 400 ? '3xx' : 
                       result.responseCode < 500 ? '4xx' : '5xx';
      
      codeCounts[codeRange] = (codeCounts[codeRange] || 0) + 1;
    });
    
    return Object.entries(codeCounts).map(([name, value]) => ({ name, value }));
  };

  // Prepare data for timeline chart
  const getTimelineData = () => {
    // Group results by 5% intervals of the scan progress
    const intervals = Array.from({ length: 20 }, (_, i) => i * 5);
    const timelineData = intervals.map(interval => ({
      progress: `${interval}%`,
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    }));
    
    // Simulate distribution based on current results
    const totalThreats = threats.critical + threats.high + threats.medium + threats.low;
    if (totalThreats > 0) {
      // Distribute threats across the timeline with higher concentration in later stages
      for (let i = 0; i < timelineData.length; i++) {
        const weight = i < 5 ? 0.2 : i < 10 ? 0.5 : i < 15 ? 0.8 : 1;
        timelineData[i].Critical = Math.floor((threats.critical / totalThreats) * weight * 10 * Math.random());
        timelineData[i].High = Math.floor((threats.high / totalThreats) * weight * 10 * Math.random());
        timelineData[i].Medium = Math.floor((threats.medium / totalThreats) * weight * 10 * Math.random());
        timelineData[i].Low = Math.floor((threats.low / totalThreats) * weight * 10 * Math.random());
      }
    }
    
    return timelineData;
  };

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">Web Application Fuzzer</h1>
          <div className="flex items-center space-x-2">
            {scanning ? (
              <>
                <Button variant="outline" size="sm" onClick={pauseFuzzing} className="group">
                  <Pause className="mr-2 h-4 w-4 text-yellow-400 group-hover:animate-pulse" />
                  Pause Scan
                </Button>
                <Button variant="destructive" size="sm" onClick={stopFuzzing} className="group">
                  <StopCircle className="mr-2 h-4 w-4 group-hover:animate-pulse" />
                  Stop Scan
                </Button>
              </>
            ) : (
              <Button variant="default" size="sm" onClick={startFuzzing} className="bg-green-600 hover:bg-green-700 group">
                <Play className="mr-2 h-4 w-4 group-hover:animate-pulse" />
                Start Scan
              </Button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Left Column - Control Panel */}
          <div className="md:col-span-8 space-y-6">
            <Card className="border-white/5 bg-white/5 text-white shadow-lg hover:shadow-xl transition-all duration-300">
              <CardHeader className="border-b border-white/10 pb-3">
                <CardTitle className="flex items-center text-xl font-medium">
                  Scan Control Panel
                  <Badge className="ml-2" variant="secondary">Beta</Badge>
                </CardTitle>
                <CardDescription className="text-white/70">
                  Configure and control your fuzzing scan
                </CardDescription>
              </CardHeader>
              <CardContent className="pt-6 space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-white/80">Target URL</label>
                  <Input 
                    type="url" 
                    value={targetUrl} 
                    onChange={(e) => setTargetUrl(e.target.value)}
                    className="border-white/10 bg-white/5 text-white focus:border-blue-500"
                    placeholder="https://example.com/form" 
                  />
                </div>
                
                <div className="flex flex-col md:flex-row gap-4">
                  <div className="space-y-2 flex-1">
                    <label className="text-sm font-medium text-white/80">Scan Mode</label>
                    <Select value={scanMode} onValueChange={setScanMode}>
                      <SelectTrigger className="border-white/10 bg-white/5 text-white focus:border-blue-500">
                        <SelectValue placeholder="Select scan mode" />
                      </SelectTrigger>
                      <SelectContent className="bg-gray-900 border-white/10 text-white">
                        <SelectItem value="active">Active Fuzzing</SelectItem>
                        <SelectItem value="passive">Passive Scanning</SelectItem>
                        <SelectItem value="mutation">Mutation-Based</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="space-y-2 flex-1">
                    <label className="text-sm font-medium text-white/80">Wordlist</label>
                    <div className="relative">
                      <Button 
                        variant="outline" 
                        className="w-full border-white/10 bg-white/5 text-white focus:border-blue-500 flex items-center justify-center"
                        onClick={() => document.getElementById('wordlist-upload')?.click()}
                      >
                        <Upload className="mr-2 h-4 w-4" />
                        {payloads.length > 0 ? `${payloads.length} payloads loaded` : "Upload Wordlist"}
                      </Button>
                      <input 
                        id="wordlist-upload" 
                        type="file" 
                        accept=".txt" 
                        className="hidden" 
                        onChange={handleFileUpload} 
                      />
                    </div>
                  </div>
                </div>

                {(scanning || scanCompleted) && (
                  <div className="space-y-2 mt-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-white/80">Scan Progress</span>
                      <span className="text-sm font-mono text-white/80">{Math.round(progress)}%</span>
                    </div>
                    <Progress value={progress} className="h-2 bg-white/10" />
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-white/5 bg-white/5 text-white shadow-lg hover:shadow-xl transition-all duration-300">
              <CardHeader className="border-b border-white/10 pb-3">
                <CardTitle className="text-xl font-medium">Results & Analytics</CardTitle>
                <CardDescription className="text-white/70">
                  View detailed scan results and analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="pt-6">
                <Tabs defaultValue="results">
                  <TabsList className="bg-white/5 text-white">
                    <TabsTrigger value="results">Results</TabsTrigger>
                    <TabsTrigger value="logs">Activity Logs</TabsTrigger>
                    <TabsTrigger value="analytics">Analytics</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="results" className="border-none p-0 mt-4">
                    <div className="bg-white/5 rounded-md p-2">
                      <div className="flex justify-between items-center mb-2">
                        <h3 className="text-sm font-medium text-white/80">Found Vulnerabilities</h3>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm" onClick={() => exportResults('json')} className="h-7 px-2 py-1 text-xs border-white/10 bg-white/5">
                            <FileText className="h-3 w-3 mr-1" /> JSON
                          </Button>
                          <Button variant="outline" size="sm" onClick={() => exportResults('csv')} className="h-7 px-2 py-1 text-xs border-white/10 bg-white/5">
                            <FileText className="h-3 w-3 mr-1" /> CSV
                          </Button>
                        </div>
                      </div>
                      <ScrollArea className="h-[300px] rounded-md border border-white/10">
                        <div className="p-2">
                          {results.length === 0 ? (
                            <div className="text-center py-10 text-white/50">
                              No results yet. Start a scan to find vulnerabilities.
                            </div>
                          ) : (
                            <div className="space-y-3">
                              {results.map(result => (
                                <div key={result.id} className="bg-white/5 rounded-md p-3 border border-white/10">
                                  <div className="flex justify-between items-start">
                                    <div className="font-mono text-sm text-green-400 break-all">{result.payload}</div>
                                    <Badge variant={result.responseCode >= 500 ? "destructive" : "outline"}>
                                      {result.responseCode}
                                    </Badge>
                                  </div>
                                  <div className="flex gap-2 mt-2 flex-wrap">
                                    {result.alertDetected && (
                                      <Badge variant="secondary" className="bg-yellow-600 text-white">
                                        <AlertTriangle className="h-3 w-3 mr-1" /> Alert Detected
                                      </Badge>
                                    )}
                                    {result.errorDetected && (
                                      <Badge variant="destructive">Error Detected</Badge>
                                    )}
                                    {result.bodyChanged && (
                                      <Badge variant="secondary">Body Changed</Badge>
                                    )}
                                    <Badge 
                                      variant="outline" 
                                      className={`
                                        ${result.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-700/30' : ''}
                                        ${result.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-700/30' : ''}
                                        ${result.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-700/30' : ''}
                                        ${result.severity === 'low' ? 'bg-green-500/20 text-green-400 border-green-700/30' : ''}
                                      `}
                                    >
                                      {result.severity.charAt(0).toUpperCase() + result.severity.slice(1)}
                                    </Badge>
                                  </div>
                                  <div className="text-xs text-white/50 mt-2">
                                    {new Date(result.timestamp).toLocaleString()}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </ScrollArea>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="logs" className="border-none p-0 mt-4">
                    <ScrollArea className="h-[300px] bg-black/50 rounded-md border border-white/10 font-mono text-sm">
                      <div className="p-4">
                        {logMessages.length === 0 ? (
                          <div className="text-center py-10 text-white/50">
                            No activity logs yet.
                          </div>
                        ) : (
                          <div className="space-y-1">
                            {logMessages.map((log, i) => (
                              <div key={i} className="text-white/80 text-xs">{log}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    </ScrollArea>
                  </TabsContent>
                  
                  <TabsContent value="analytics" className="border-none p-0 mt-4">
                    {!showAnalytics ? (
                      <div className="text-center py-10 text-white/50 bg-black/30 rounded-md border border-white/10">
                        {scanCompleted ? 
                          <Button onClick={() => setShowAnalytics(true)} variant="outline" className="bg-white/5 hover:bg-white/10 border-blue-500/30">
                            <ActivityIcon className="mr-2 h-4 w-4" />
                            Show Scan Analytics
                          </Button> : 
                          "Complete a scan to view analytics"
                        }
                      </div>
                    ) : (
                      <div className="space-y-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          {/* Vulnerability Distribution */}
                          <Card className="border-white/10 bg-white/5">
                            <CardHeader className="pb-2">
                              <CardTitle className="text-sm flex items-center">
                                <PieChartIcon className="h-4 w-4 mr-2" />
                                Severity Distribution
                              </CardTitle>
                            </CardHeader>
                            <CardContent>
                              {getPieChartData().length > 0 ? (
                                <div className="h-72">
                                  <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                      <Pie
                                        data={getPieChartData()}
                                        cx="50%"
                                        cy="50%"
                                        labelLine={false}
                                        label={renderCustomizedLabel}
                                        outerRadius={80}
                                        fill="#8884d8"
                                        dataKey="value"
                                      >
                                        {getPieChartData().map((entry, index) => (
                                          <Cell key={`cell-${index}`} fill={entry.color} />
                                        ))}
                                      </Pie>
                                      <Tooltip />
                                      <Legend />
                                    </PieChart>
                                  </ResponsiveContainer>
                                </div>
                              ) : (
                                <div className="h-72 flex items-center justify-center text-white/50">
                                  No vulnerabilities detected
                                </div>
                              )}
                            </CardContent>
                          </Card>
                          
                          {/* Vulnerability Types */}
                          <Card className="border-white/10 bg-white/5">
                            <CardHeader className="pb-2">
                              <CardTitle className="text-sm flex items-center">
                                <BarChartIcon className="h-4 w-4 mr-2" />
                                Vulnerability Types
                              </CardTitle>
                            </CardHeader>
                            <CardContent>
                              {getVulnerabilityTypeData().length > 0 ? (
                                <div className="h-72">
                                  <ResponsiveContainer width="100%" height="100%">
                                    <BarChart
                                      data={getVulnerabilityTypeData()}
                                      margin={{
                                        top: 5,
                                        right: 30,
                                        left: 20,
                                        bottom: 5,
                                      }}
                                    >
                                      <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                                      <XAxis dataKey="name" stroke="#aaa" />
                                      <YAxis stroke="#aaa" />
                                      <Tooltip 
                                        contentStyle={{ 
                                          backgroundColor: '#222', 
                                          border: '1px solid #444',
                                          borderRadius: '4px',
                                          color: '#eee'
                                        }} 
                                      />
                                      <Legend />
                                      <Bar dataKey="value" name="Count" fill={CHART_COLORS.high} />
                                    </BarChart>
                                  </ResponsiveContainer>
                                </div>
                              ) : (
                                <div className="h-72 flex items-center justify-center text-white/50">
                                  No vulnerability types data
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        </div>
                        
                        {/* Scan Performance Metrics */}
                        <Card className="border-white/10 bg-white/5">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center">
                              <ActivityIcon className="h-4 w-4 mr-2" />
                              Scan Timeline Analysis
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="h-72">
                              <ResponsiveContainer width="100%" height="100%">
                                <LineChart
                                  data={getTimelineData()}
                                  margin={{
                                    top: 5,
                                    right: 30,
                                    left: 20,
                                    bottom: 5,
                                  }}
                                >
                                  <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                                  <XAxis dataKey="progress" stroke="#aaa" />
                                  <YAxis stroke="#aaa" />
                                  <Tooltip 
                                    contentStyle={{ 
                                      backgroundColor: '#222', 
                                      border: '1px solid #444',
                                      borderRadius: '4px',
                                      color: '#eee'
                                    }} 
                                  />
                                  <Legend />
                                  <Line type="monotone" dataKey="Critical" stroke={CHART_COLORS.critical} activeDot={{ r: 8 }} />
                                  <Line type="monotone" dataKey="High" stroke={CHART_COLORS.high} />
                                  <Line type="monotone" dataKey="Medium" stroke={CHART_COLORS.medium} />
                                  <Line type="monotone" dataKey="Low" stroke={CHART_COLORS.low} />
                                </LineChart>
                              </ResponsiveContainer>
                            </div>
                          </CardContent>
                        </Card>
                        
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          {/* Response Code Distribution */}
                          <Card className="border-white/10 bg-white/5">
                            <CardHeader className="pb-2">
                              <CardTitle className="text-sm flex items-center">
                                <BarChartIcon className="h-4 w-4 mr-2" />
                                Response Code Distribution
                              </CardTitle>
                            </CardHeader>
                            <CardContent>
                              {getResponseCodeData().length > 0 ? (
                                <div className="h-60">
                                  <ResponsiveContainer width="100%" height="100%">
                                    <BarChart
                                      data={getResponseCodeData()}
                                      margin={{
                                        top: 5,
                                        right: 30,
                                        left: 20,
                                        bottom: 5,
                                      }}
                                    >
                                      <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                                      <XAxis dataKey="name" stroke="#aaa" />
                                      <YAxis stroke="#aaa" />
                                      <Tooltip 
                                        contentStyle={{ 
                                          backgroundColor: '#222', 
                                          border: '1px solid #444',
                                          borderRadius: '4px',
                                          color: '#eee'
                                        }} 
                                      />
                                      <Legend />
                                      <Bar dataKey="value" name="Count" fill={CHART_COLORS.info} />
                                    </BarChart>
                                  </ResponsiveContainer>
                                </div>
                              ) : (
                                <div className="h-60 flex items-center justify-center text-white/50">
                                  No response code data
                                </div>
                              )}
                            </CardContent>
                          </Card>
                          
                          {/* Live Scanner Visualization */}
                          <Card className="border-white/10 bg-white/5">
                            <CardHeader className="pb-2">
                              <CardTitle className="text-sm">Scan Visualization</CardTitle>
                            </CardHeader>
                            <CardContent>
                              <div className="h-60">
                                <CyberpunkScannerAnimation 
                                  active={scanning} 
                                  threatLevel={threatLevel}
                                  detectedThreats={threats.critical + threats.high + threats.medium + threats.low}
                                />
                              </div>
                            </CardContent>
                          </Card>
                        </div>
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>

          {/* Right Column - Status & Info */}
          <div className="md:col-span-4 space-y-6">
            <Card className="border-white/5 bg-white/5 text-white shadow-lg hover:shadow-xl transition-all duration-300">
              <CardHeader className="border-b border-white/10 pb-3">
                <CardTitle className="text-xl font-medium">Threat Summary</CardTitle>
                <CardDescription className="text-white/70">
                  Overview of detected threats
                </CardDescription>
              </CardHeader>
              <CardContent className="pt-6 space-y-2">
                <ThreatLevelIndicator 
                  label="Critical Threats" 
                  count={threats.critical} 
                  icon={AlertTriangle} 
                  color="bg-red-600" 
                />
                
                <ThreatLevelIndicator 
                  label="High Severity" 
                  count={threats.high} 
                  icon={AlertTriangle} 
                  color="bg-orange-600" 
                />
                
                <ThreatLevelIndicator 
                  label="Medium Severity" 
                  count={threats.medium} 
                  icon={AlertTriangle} 
                  color="bg-yellow-600" 
                />
                
                <ThreatLevelIndicator 
                  label="Low Severity" 
                  count={threats.low} 
                  icon={AlertTriangle} 
                  color="bg-blue-600" 
                />
              </CardContent>
            </Card>

            <Card className="border-white/5 bg-white/5 text-white shadow-lg hover:shadow-xl transition-all duration-300">
              <CardHeader className="border-b border-white/10 pb-3">
                <CardTitle className="text-xl font-medium">AI Analysis</CardTitle>
                <CardDescription className="text-white/70">
                  Intelligent threat assessment
                </CardDescription>
              </CardHeader>
              <CardContent className="pt-6">
                <div className="bg-white/5 rounded-md p-4 border border-white/10">
                  <h3 className="text-sm font-medium text-white/80 mb-2">Risk Assessment</h3>
                  <div className="space-y-3">
                    {results.length > 0 ? (
                      <>
                        <p className="text-sm text-white/70">
                          Based on the scan results, the following vulnerabilities were detected:
                        </p>
                        <ul className="list-disc list-inside text-sm text-white/70 space-y-1">
                          {threats.critical > 0 && (
                            <li className="text-red-400">
                              {threats.critical} critical XSS vulnerabilities that need immediate attention
                            </li>
                          )}
                          {threats.high > 0 && (
                            <li className="text-orange-400">
                              {threats.high} high severity input validation issues
                            </li>
                          )}
                          {threats.medium > 0 && (
                            <li className="text-yellow-400">
                              {threats.medium} potential SQL injection points
                            </li>
                          )}
                          {threats.low > 0 && (
                            <li className="text-blue-400">
                              {threats.low} minor security concerns
                            </li>
                          )}
                        </ul>
                        
                        <Separator className="bg-white/10 my-3" />
                        
                        <h3 className="text-sm font-medium text-white/80">Recommended Actions</h3>
                        <ul className="list-disc list-inside text-sm text-white/70 space-y-1">
                          <li>Implement input validation on all form fields</li>
                          <li>Sanitize user inputs before processing</li>
                          <li>Use prepared statements for database queries</li>
                          <li>Enable Content Security Policy headers</li>
                        </ul>
                      </>
                    ) : (
                      <div className="text-center py-6 text-white/50">
                        Start a scan to generate AI analysis
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
