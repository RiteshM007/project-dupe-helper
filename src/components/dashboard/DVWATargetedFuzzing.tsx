
import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Loader, Bug, Shield, Zap, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';
import { WebFuzzer } from '@/backend/WebFuzzer';
import { DVWAConfig } from './DVWAConnection';

interface DVWATargetedFuzzingProps {
  isConnected: boolean;
  dvwaConfig?: DVWAConfig;
}

interface VulnerabilityPageInfo {
  name: string;
  url: string;
  parameters: string[];
}

export const DVWATargetedFuzzing: React.FC<DVWATargetedFuzzingProps> = ({ 
  isConnected, 
  dvwaConfig 
}) => {
  const [fuzzer, setFuzzer] = useState<WebFuzzer | null>(null);
  const [currentPage, setCurrentPage] = useState<VulnerabilityPageInfo | null>(null);
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [payloadsSent, setPayloadsSent] = useState(0);
  const [responsesReceived, setResponsesReceived] = useState(0);
  const [threatsDetected, setThreatsDetected] = useState(0);
  const [isPageDetecting, setIsPageDetecting] = useState(false);
  
  const logContainerRef = useRef<HTMLDivElement>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  
  // Auto-scroll logs to bottom when new logs are added
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);
  
  // Initialize fuzzer when connection is established
  useEffect(() => {
    if (isConnected && dvwaConfig) {
      const newFuzzer = new WebFuzzer(dvwaConfig.url, 'dvwa_wordlist.txt');
      setFuzzer(newFuzzer);
      
      // Initialize fuzzer with DVWA connection
      const initFuzzer = async () => {
        try {
          addLog(`Connecting to DVWA at ${dvwaConfig.url}...`);
          
          await newFuzzer.connectToDVWA(
            dvwaConfig.url,
            dvwaConfig.username,
            dvwaConfig.password,
            'low' // Default to low security for testing
          );
          
          addLog('Successfully connected to DVWA');
          toast("DVWA Connection Established", {
            description: "Connected to DVWA successfully. Ready for targeted fuzzing.",
          });
        } catch (error) {
          addLog(`Error connecting to DVWA: ${error}`);
          toast("Connection Error", {
            description: "Failed to connect to DVWA. Please check your credentials.",
          });
        }
      };
      
      initFuzzer();
    }
    
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };
  }, [isConnected, dvwaConfig]);
  
  // Poll for page changes when fuzzer is connected but not actively fuzzing
  useEffect(() => {
    if (fuzzer && isConnected && !isFuzzing) {
      pollIntervalRef.current = setInterval(detectCurrentPage, 5000);
    }
    
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };
  }, [fuzzer, isConnected, isFuzzing]);
  
  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };
  
  const detectCurrentPage = async () => {
    if (!fuzzer || !isConnected) return;
    
    setIsPageDetecting(true);
    addLog("Detecting current DVWA vulnerability page...");
    
    // In a real implementation, this would use something like browser automation 
    // or a proxy to detect the current page. For this simulation, we'll use a mock.
    
    setTimeout(() => {
      // Simulate detection of a random vulnerability page
      const vulnerabilityPages = [
        { name: "SQL Injection", url: "/vulnerabilities/sqli/", parameters: ["id"] },
        { name: "XSS (Reflected)", url: "/vulnerabilities/xss_r/", parameters: ["name"] },
        { name: "XSS (Stored)", url: "/vulnerabilities/xss_s/", parameters: ["txtName", "mtxMessage"] },
        { name: "CSRF", url: "/vulnerabilities/csrf/", parameters: ["password_new", "password_conf"] },
        { name: "File Inclusion", url: "/vulnerabilities/fi/", parameters: ["page"] },
        { name: "Command Injection", url: "/vulnerabilities/exec/", parameters: ["ip"] },
        { name: "File Upload", url: "/vulnerabilities/upload/", parameters: ["uploaded"] },
      ];
      
      // Select a random page for simulation
      const detectedPage = vulnerabilityPages[Math.floor(Math.random() * vulnerabilityPages.length)];
      
      if (currentPage?.name !== detectedPage.name) {
        setCurrentPage(detectedPage);
        addLog(`Detected vulnerability page: ${detectedPage.name} (${detectedPage.url})`);
        addLog(`Vulnerable parameters: ${detectedPage.parameters.join(", ")}`);
        
        toast("Page Detected", {
          description: `Now targeting: ${detectedPage.name}`,
        });
      }
      
      setIsPageDetecting(false);
    }, 1500);
  };
  
  const startFuzzing = async () => {
    if (!fuzzer || !currentPage) {
      toast("Cannot Start Fuzzing", {
        description: "No vulnerability page detected to fuzz",
      });
      return;
    }
    
    setIsFuzzing(true);
    setProgress(0);
    setPayloadsSent(0);
    setResponsesReceived(0);
    setThreatsDetected(0);
    
    addLog(`Starting targeted fuzzing on ${currentPage.name} (${currentPage.url})`);
    addLog(`Targeting parameters: ${currentPage.parameters.join(", ")}`);
    
    // Determine vulnerability type from page name
    let vulnerabilityType = 'xss';
    if (currentPage.name.toLowerCase().includes('sql')) vulnerabilityType = 'sqli';
    if (currentPage.name.toLowerCase().includes('file')) vulnerabilityType = 'lfi';
    if (currentPage.name.toLowerCase().includes('command') || currentPage.name.toLowerCase().includes('exec')) vulnerabilityType = 'rce';
    if (currentPage.name.toLowerCase().includes('csrf')) vulnerabilityType = 'csrf';
    
    // In a real implementation, we would start actual fuzzing here.
    // For simulation, we'll use the WebFuzzer's methods but with UI updates.
    
    // Set up progress simulation
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(progressInterval);
          setIsFuzzing(false);
          addLog("Fuzzing process completed!");
          toast("Fuzzing Complete", {
            description: `Completed fuzzing ${currentPage.name}`,
          });
          return 100;
        }
        return prev + Math.random() * 5;
      });
      
      // Simulate payload sending and responses
      const newPayloads = Math.floor(Math.random() * 3) + 1;
      setPayloadsSent(prev => prev + newPayloads);
      
      setTimeout(() => {
        setResponsesReceived(prev => prev + newPayloads);
        
        // Simulate threat detection occasionally
        if (Math.random() > 0.8) {
          setThreatsDetected(prev => prev + 1);
          const threatType = vulnerabilityType.toUpperCase();
          addLog(`⚠️ ALERT: Potential ${threatType} vulnerability detected!`);
          
          toast("Threat Detected!", {
            description: `A potential ${threatType} vulnerability was found`,
          });
        }
      }, 300);
      
      // Add some fuzzing logs
      const paramName = currentPage.parameters[Math.floor(Math.random() * currentPage.parameters.length)];
      const payload = getRandomPayload(vulnerabilityType);
      addLog(`Sending payload to ${paramName}: ${payload}`);
      
    }, 1000);
    
    // Clean up when component unmounts
    return () => {
      clearInterval(progressInterval);
    };
  };
  
  const getRandomPayload = (type: string): string => {
    const payloads: Record<string, string[]> = {
      xss: [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert(1)>",
      ],
      sqli: [
        "' OR 1=1 -- -",
        "' UNION SELECT 1,2,3 -- -",
        "admin'#",
      ],
      lfi: [
        "../../../etc/passwd",
        "../../../../etc/hosts",
        "php://filter/convert.base64-encode/resource=index.php",
      ],
      rce: [
        "| cat /etc/passwd",
        "; ls -la",
        "$(whoami)",
      ],
      csrf: [
        "<img src='http://victim.com/api?action=delete'>",
        "<form action='http://victim.com/change' method='POST'>",
      ],
    };
    
    const typePayloads = payloads[type] || payloads.xss;
    return typePayloads[Math.floor(Math.random() * typePayloads.length)];
  };
  
  const stopFuzzing = () => {
    setIsFuzzing(false);
    addLog("Fuzzing process stopped by user");
    
    toast("Fuzzing Stopped", {
      description: "The fuzzing process has been stopped",
    });
  };
  
  if (!isConnected) {
    return (
      <Card>
        <CardContent className="pt-6">
          <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              Please connect to DVWA first to enable targeted fuzzing.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }
  
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex justify-between">
            <span>Targeted DVWA Vulnerability Fuzzing</span>
            {currentPage && (
              <Badge variant="outline" className="ml-2">
                {currentPage.name}
              </Badge>
            )}
          </CardTitle>
          <CardDescription>
            Automatically detect and fuzz the currently open vulnerability page in DVWA
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {currentPage ? (
            <div className="space-y-4">
              <div className="p-4 rounded-md bg-muted">
                <h3 className="font-medium mb-2">Current Target</h3>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="text-muted-foreground">Page:</div>
                  <div className="font-medium">{currentPage.name}</div>
                  <div className="text-muted-foreground">URL:</div>
                  <div className="font-mono text-xs">{dvwaConfig?.url}{currentPage.url}</div>
                  <div className="text-muted-foreground">Parameters:</div>
                  <div className="font-medium">{currentPage.parameters.join(", ")}</div>
                </div>
              </div>
              
              <div className="flex justify-between">
                <Button
                  onClick={isFuzzing ? stopFuzzing : startFuzzing}
                  variant={isFuzzing ? "destructive" : "default"}
                  className="w-full"
                >
                  {isFuzzing ? (
                    <>Stop Fuzzing</>
                  ) : (
                    <>Start Targeted Fuzzing</>
                  )}
                </Button>
              </div>
              
              {isFuzzing && (
                <div className="space-y-2">
                  <div className="flex justify-between text-xs">
                    <span>Fuzzing {currentPage.name}</span>
                    <span>{Math.round(progress)}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-6">
              {isPageDetecting ? (
                <div className="flex flex-col items-center space-y-2">
                  <Loader className="h-8 w-8 text-primary animate-spin" />
                  <p>Detecting current vulnerability page...</p>
                </div>
              ) : (
                <div className="space-y-4">
                  <p>No vulnerability page detected</p>
                  <Button onClick={detectCurrentPage}>
                    Detect Current Page
                  </Button>
                </div>
              )}
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
            <div className="text-3xl font-bold">{payloadsSent}</div>
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
            <div className="text-3xl font-bold">{responsesReceived}</div>
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
            <div className="text-3xl font-bold text-red-500">{threatsDetected}</div>
          </CardContent>
        </Card>
      </div>
      
      <Card>
        <CardHeader>
          <CardTitle>Fuzzing Logs</CardTitle>
          <CardDescription>Live targeted fuzzing output</CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[300px] w-full rounded-lg border bg-muted/50 p-4 font-mono text-sm">
            {logs.length === 0 ? (
              <div className="flex h-full items-center justify-center text-muted-foreground">
                Waiting for fuzzing activity...
              </div>
            ) : (
              <div 
                ref={logContainerRef}
                className="space-y-2"
              >
                {logs.map((log, index) => (
                  <div 
                    key={index}
                    className="py-1 border-b border-border/20 last:border-0"
                  >
                    {log}
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
};
