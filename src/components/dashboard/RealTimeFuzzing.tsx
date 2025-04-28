
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Link, Bug, Shield, Zap, Loader } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { PayloadUploader } from '@/components/fuzzer/PayloadUploader';
import { LiveLogs } from '@/components/fuzzer/LiveLogs';

export const RealTimeFuzzing: React.FC = () => {
  const [url, setUrl] = useState("");
  const [payloadSet, setPayloadSet] = useState("default");
  const [fuzzingMode, setFuzzingMode] = useState("stealth");
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);
  const [customPayloads, setCustomPayloads] = useState<string[]>([]);
  const [scanStats, setScanStats] = useState({
    payloadsSent: 0,
    responsesReceived: 0,
    threatsDetected: 0,
  });
  const [payloadsReady, setPayloadsReady] = useState(false);

  const handlePayloadsUploaded = (payloads: string[]) => {
    setCustomPayloads(payloads);
    setPayloadsReady(true);
    addLog(`Loaded ${payloads.length} custom payloads`);
  };

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

    if (customPayloads.length === 0) {
      toast({
        title: "No Payloads",
        description: "Please upload custom payloads first",
        variant: "destructive",
      });
      return;
    }

    const scanId = Math.random().toString(36).substr(2, 9);
    window.dispatchEvent(new CustomEvent('scanUpdate', {
      detail: { scanId, status: 'in-progress' }
    }));

    setLogs([]);
    setProgress(0);
    setScanStats({
      payloadsSent: 0,
      responsesReceived: 0,
      threatsDetected: 0,
    });

    setIsFuzzing(true);
    addLog(`Starting ${fuzzingMode} fuzzing on ${url}`);
    addLog(`Using custom payload set with ${customPayloads.length} payloads`);

    try {
      addLog("Initializing fuzzer connection...");
      addLog("Scanning target for entry points...");
      
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      addLog("Beginning payload injection...");
      
      const detectVulnerability = () => {
        if (Math.random() > 0.7) {
          const vulnTypes = ["XSS vulnerability", "SQL injection point", "CSRF vulnerability", "Remote file inclusion", "Authentication bypass"];
          const detectedVuln = vulnTypes[Math.floor(Math.random() * vulnTypes.length)];
          addLog(`⚠️ ALERT: Potential ${detectedVuln} detected!`);
          
          setScanStats(prev => ({
            ...prev,
            threatsDetected: prev.threatsDetected + 1
          }));
          
          toast({
            title: "Vulnerability Detected!",
            description: `A potential ${detectedVuln} was found`,
            variant: "destructive",
          });
        }
      };
      
      let interval = setInterval(() => {
        if (!isFuzzing) {
          clearInterval(interval);
          return;
        }
        
        setProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval);
            setIsFuzzing(false);
            addLog("Fuzzing process completed!");
            
            // Update scan status to completed
            window.dispatchEvent(new CustomEvent('scanUpdate', {
              detail: {
                scanId,
                status: 'completed',
                vulnerabilities: scanStats.threatsDetected
              }
            }));
            
            return 100;
          }
          
          setScanStats(prev => ({
            payloadsSent: prev.payloadsSent + Math.floor(Math.random() * 3) + 1,
            responsesReceived: prev.responsesReceived + Math.floor(Math.random() * 3),
            threatsDetected: prev.threatsDetected
          }));
          
          // Simulate processing payloads
          const payloadIndex = Math.floor(Math.random() * customPayloads.length);
          if (payloadIndex < customPayloads.length) {
            addLog(`Testing payload: ${customPayloads[payloadIndex]}`);
          }
          
          const increment = Math.random() * 5 + 1;
          return Math.min(100, prev + increment);
        });
        
        // Random chance to detect vulnerability
        if (Math.random() > 0.9) {
          detectVulnerability();
        }
      }, 1000);
      
      // Handle vulnerability detection at intervals
      const vulnDetectionInterval = setInterval(detectVulnerability, 3000);
      
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
  
  // Clean up on unmount
  useEffect(() => {
    return () => {
      if (isFuzzing) {
        setIsFuzzing(false);
      }
    };
  }, []);

  return (
    <div className="space-y-6">
      <Card className="overflow-hidden border-emerald-900/20 bg-card/60 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>Web Application Fuzzer</CardTitle>
          <CardDescription>Configure and test fuzzing on web applications</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target-url">Target URL</Label>
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
                  <SelectItem value="custom">Custom Payloads</SelectItem>
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
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex justify-between items-center gap-4">
            <PayloadUploader onPayloadsUploaded={handlePayloadsUploaded} />
            
            <Button
              onClick={isFuzzing ? handleStopFuzzing : handleStartFuzzing}
              variant={isFuzzing ? "destructive" : "default"}
              disabled={!payloadsReady || customPayloads.length === 0}
              className="w-full"
            >
              {isFuzzing ? (
                <>
                  Stop Fuzzing
                  <Loader className="ml-2 h-4 w-4 animate-spin" />
                </>
              ) : (
                "Start Fuzzing"
              )}
            </Button>
          </div>

          {isFuzzing && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs">
                <span>Fuzzing Progress</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="col-span-1 bg-card/60 backdrop-blur-sm border-emerald-900/20">
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
        
        <Card className="col-span-1 bg-card/60 backdrop-blur-sm border-emerald-900/20">
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
        
        <Card className="col-span-1 bg-card/60 backdrop-blur-sm border-emerald-900/20">
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

      <LiveLogs logs={logs} isActive={isFuzzing} />
    </div>
  );
};
