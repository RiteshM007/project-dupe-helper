import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Play, Pause, StopCircle, AlertTriangle, FileText, Upload } from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import DashboardLayout from "@/components/layout/DashboardLayout";
import { ThreatLevelIndicator } from "@/components/dashboard/ThreatLevelIndicator";

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
  const [results, setResults] = useState<{id: string, payload: string, responseCode: number, alertDetected: boolean, errorDetected: boolean, bodyChanged: boolean, timestamp: number}[]>([]);

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
  };

  // Simulate the fuzzing process
  const simulateFuzzing = () => {
    let currentProgress = 0;
    let currentThreats = { ...threats };
    const newResults: typeof results = [];
    
    const interval = setInterval(() => {
      if (currentProgress >= 100) {
        clearInterval(interval);
        setScanning(false);
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
        let threatLevel = "";
        
        if (threatType > 0.9) {
          currentThreats.critical += 1;
          threatLevel = "Critical";
        } else if (threatType > 0.7) {
          currentThreats.high += 1;
          threatLevel = "High";
        } else if (threatType > 0.4) {
          currentThreats.medium += 1;
          threatLevel = "Medium";
        } else {
          currentThreats.low += 1;
          threatLevel = "Low";
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
          timestamp: Date.now()
        };
        
        newResults.push(newResult);
        setResults(prev => [newResult, ...prev]);
        
        addLogMessage(`${threatLevel} threat detected with payload: ${randomPayload}`);
      }
    }, 300);

    return () => clearInterval(interval);
  };

  // Export results
  const exportResults = (format: string) => {
    toast.success(`Results exported in ${format.toUpperCase()} format`);
    addLogMessage(`Exported results to ${format.toUpperCase()} file.`);
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

                {scanning && (
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
                    <div className="grid grid-cols-2 gap-4">
                      <Card className="border-white/10 bg-white/5">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Vulnerability Distribution</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center py-10 text-white/50">
                            Analytics visualization coming soon
                          </div>
                        </CardContent>
                      </Card>
                      <Card className="border-white/10 bg-white/5">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Scan Performance</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center py-10 text-white/50">
                            Performance metrics coming soon
                          </div>
                        </CardContent>
                      </Card>
                    </div>
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
