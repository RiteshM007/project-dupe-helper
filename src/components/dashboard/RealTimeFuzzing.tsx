
import React, { useState, useRef, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Loader, Link, Bug, Shield, Zap } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { fuzzerApi } from '@/services/api';
import { DVWAConnection, DVWAConfig } from './DVWAConnection';
import { DVWATargetedFuzzing } from './DVWATargetedFuzzing';

export const RealTimeFuzzing: React.FC = () => {
  const [url, setUrl] = useState("");
  const [payloadSet, setPayloadSet] = useState("default");
  const [fuzzingMode, setFuzzingMode] = useState("stealth");
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);
  const [scanStats, setScanStats] = useState({
    payloadsSent: 0,
    responsesReceived: 0,
    threatsDetected: 0,
  });
  const [isDvwaConnected, setIsDvwaConnected] = useState(false);
  const [dvwaConfig, setDvwaConfig] = useState<DVWAConfig | undefined>();
  
  const logContainerRef = useRef<HTMLDivElement>(null);
  
  // Auto-scroll logs to bottom when new logs are added
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);
  
  // Progress simulation
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    
    if (isFuzzing) {
      interval = setInterval(() => {
        setProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval);
            setIsFuzzing(false);
            addLog("Fuzzing process completed!");
            return 100;
          }
          
          // Update scan stats
          setScanStats(prev => ({
            payloadsSent: prev.payloadsSent + Math.floor(Math.random() * 3) + 1,
            responsesReceived: prev.responsesReceived + Math.floor(Math.random() * 3),
            threatsDetected: Math.random() > 0.9 
              ? prev.threatsDetected + 1 
              : prev.threatsDetected,
          }));
          
          const increment = Math.random() * 5 + 1;
          return Math.min(100, prev + increment);
        });
      }, 1000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isFuzzing]);
  
  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };
  
  const handleStartFuzzing = async () => {
    if (!url) {
      toast({
        title: "Missing URL",
        description: "Please enter a URL to fuzz",
        variant: "destructive",
      });
      return;
    }
    
    // Validate URL
    try {
      new URL(url);
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        throw new Error('URL must start with http:// or https://');
      }
    } catch (error) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid HTTP/HTTPS URL",
        variant: "destructive",
      });
      return;
    }
    
    setLogs([]);
    setProgress(0);
    setScanStats({
      payloadsSent: 0,
      responsesReceived: 0,
      threatsDetected: 0,
    });
    
    setIsFuzzing(true);
    addLog(`Starting ${fuzzingMode} fuzzing on ${url}`);
    addLog(`Using ${payloadSet} payload set`);
    
    // In a real implementation, this would call an API
    try {
      // Simulate API call
      addLog("Initializing fuzzer connection...");
      addLog("Scanning target for entry points...");
      
      // Wait 2 seconds to simulate setup
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      addLog("Beginning payload injection...");
      
      // Detection simulation - every so often we'll detect something
      const detectVulnerability = () => {
        if (Math.random() > 0.7) {
          const vulnTypes = ["XSS vulnerability", "SQL injection point", "CSRF vulnerability", "Remote file inclusion", "Authentication bypass"];
          const detectedVuln = vulnTypes[Math.floor(Math.random() * vulnTypes.length)];
          addLog(`⚠️ ALERT: Potential ${detectedVuln} detected!`);
          
          toast({
            title: "Vulnerability Detected!",
            description: `A potential ${detectedVuln} was found`,
            variant: "destructive",
          });
        }
      };
      
      // Set up periodic vulnerability detection
      const vulnDetectionInterval = setInterval(detectVulnerability, 3000);
      
      // Clean up when fuzzing is done
      setTimeout(() => {
        clearInterval(vulnDetectionInterval);
      }, 30000);
      
    } catch (error: any) {
      setIsFuzzing(false);
      toast({
        title: "Fuzzing Error",
        description: error.message || "An error occurred while fuzzing",
        variant: "destructive",
      });
    }
  };
  
  const handleStopFuzzing = () => {
    setIsFuzzing(false);
    addLog("Fuzzing process stopped by user.");
    toast({
      title: "Fuzzing Stopped",
      description: "The fuzzing process has been stopped",
    });
  };

  const handleDvwaConnect = (config: DVWAConfig) => {
    setDvwaConfig(config);
    setIsDvwaConnected(true);
    toast({
      title: "DVWA Connected",
      description: `Connected to DVWA at ${config.url}`,
    });
  };
  
  const handleDvwaDisconnect = () => {
    setIsDvwaConnected(false);
    setDvwaConfig(undefined);
    toast({
      title: "DVWA Disconnected",
      description: "Disconnected from DVWA",
    });
  };
  
  return (
    <div className="space-y-6">
      <Tabs defaultValue="general">
        <TabsList>
          <TabsTrigger value="general">General Fuzzing</TabsTrigger>
          <TabsTrigger value="dvwa">DVWA Targeted Fuzzing</TabsTrigger>
        </TabsList>
        
        <TabsContent value="general" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Fuzz Real Websites</CardTitle>
              <CardDescription>Configure and test fuzzing on actual websites</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target-url">Website URL</Label>
                <div className="flex items-center space-x-2">
                  <Link className="h-5 w-5 text-muted-foreground" />
                  <Input 
                    id="target-url" 
                    placeholder="https://example.com" 
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    disabled={isFuzzing}
                    className="flex-1"
                  />
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="payload-set">Payload Set</Label>
                  <Select 
                    value={payloadSet} 
                    onValueChange={setPayloadSet}
                    disabled={isFuzzing}
                  >
                    <SelectTrigger id="payload-set">
                      <SelectValue placeholder="Select payload set" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="default">Default Payloads</SelectItem>
                      <SelectItem value="xss">XSS Specialized</SelectItem>
                      <SelectItem value="sqli">SQL Injection</SelectItem>
                      <SelectItem value="custom">Custom Uploaded</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="fuzzing-mode">Fuzzing Mode</Label>
                  <Select 
                    value={fuzzingMode} 
                    onValueChange={setFuzzingMode}
                    disabled={isFuzzing}
                  >
                    <SelectTrigger id="fuzzing-mode">
                      <SelectValue placeholder="Select fuzzing mode" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="stealth">Stealth Mode</SelectItem>
                      <SelectItem value="aggressive">Aggressive</SelectItem>
                      <SelectItem value="thorough">Thorough Scan</SelectItem>
                      <SelectItem value="custom">Custom Settings</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              <div className="flex justify-between">
                <Button
                  onClick={isFuzzing ? handleStopFuzzing : handleStartFuzzing}
                  variant={isFuzzing ? "destructive" : "default"}
                  className="w-full"
                >
                  {isFuzzing ? (
                    <>Stop Fuzzing</>
                  ) : (
                    <>Start Fuzzing</>
                  )}
                </Button>
              </div>
              
              {isFuzzing && (
                <div className="space-y-2 mt-4">
                  <div className="flex justify-between text-xs">
                    <span>Fuzzing in Progress</span>
                    <span>{Math.round(progress)}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}
            </CardContent>
          </Card>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="col-span-1">
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center">
                  <Zap className="h-4 w-4 mr-2" />
                  Payloads Sent
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{scanStats.payloadsSent}</div>
              </CardContent>
            </Card>
            
            <Card className="col-span-1">
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center">
                  <Shield className="h-4 w-4 mr-2" />
                  Responses Received
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{scanStats.responsesReceived}</div>
              </CardContent>
            </Card>
            
            <Card className="col-span-1">
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center">
                  <Bug className="h-4 w-4 mr-2" />
                  Threats Detected
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-red-500">{scanStats.threatsDetected}</div>
              </CardContent>
            </Card>
          </div>
          
          <Card>
            <CardHeader>
              <CardTitle>Real-Time Logs</CardTitle>
              <CardDescription>Live fuzzing process output</CardDescription>
            </CardHeader>
            <CardContent>
              <div 
                ref={logContainerRef}
                className="bg-muted/50 rounded-md p-4 h-[400px] overflow-y-auto font-mono text-sm whitespace-pre-wrap"
              >
                {logs.length > 0 ? (
                  logs.map((log, index) => (
                    <div key={index} className="py-1 border-b border-border/20 last:border-0">
                      {log}
                    </div>
                  ))
                ) : (
                  <div className="text-muted-foreground h-full flex items-center justify-center">
                    {isFuzzing ? (
                      <div className="flex items-center">
                        <Loader className="animate-spin mr-2 h-4 w-4" />
                        Connecting to target...
                      </div>
                    ) : (
                      "Waiting for fuzzer to start..."
                    )}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="dvwa" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="col-span-1">
              <DVWAConnection 
                isConnected={isDvwaConnected}
                onConnect={handleDvwaConnect}
                onDisconnect={handleDvwaDisconnect} 
              />
            </div>
            
            <div className="col-span-1 md:col-span-2">
              <DVWATargetedFuzzing 
                isConnected={isDvwaConnected}
                dvwaConfig={dvwaConfig}
              />
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};
