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
import { checkDVWAConnection, loginToDVWA, fuzzerRequest } from '@/utils/dvwaFuzzer';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';

export const RealTimeFuzzing: React.FC = () => {
  const { isConnected, setIsConnected, dvwaUrl, setDvwaUrl, sessionCookie, setSessionCookie } = useDVWAConnection();
  const [url, setUrl] = useState(dvwaUrl || "http://localhost:8080/DVWA");
  const [module, setModule] = useState("exec");
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

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const handlePayloadsUploaded = (payloads: string[]) => {
    setCustomPayloads(payloads);
    setPayloadsReady(true);
    addLog(`Loaded ${payloads.length} custom payloads`);
  };

  const handleConnect = async () => {
    addLog(`Attempting to connect to DVWA at ${url}`);
    
    const isReachable = await checkDVWAConnection(url);
    if (!isReachable) {
      toast({
        title: "Connection Failed",
        description: "DVWA server not reachable. Please start DVWA and try again.",
        variant: "destructive",
      });
      return;
    }

    const loginResult = await loginToDVWA(url, 'admin', 'password');
    if (loginResult.success && loginResult.cookie) {
      setIsConnected(true);
      setDvwaUrl(url);
      setSessionCookie(loginResult.cookie);
      addLog('Successfully connected to DVWA');
      toast({
        title: "Connected",
        description: "Successfully connected to DVWA",
      });
    } else {
      toast({
        title: "Login Failed",
        description: "Could not authenticate with DVWA",
        variant: "destructive",
      });
    }
  };

  const handleStartFuzzing = async () => {
    if (!isConnected) {
      toast({
        title: "Not Connected",
        description: "Please connect to DVWA first",
        variant: "destructive",
      });
      return;
    }

    if (!payloadsReady || customPayloads.length === 0) {
      toast({
        title: "No Payloads",
        description: "Please upload custom payloads first",
        variant: "destructive",
      });
      return;
    }

    setIsFuzzing(true);
    setProgress(0);
    setScanStats({
      payloadsSent: 0,
      responsesReceived: 0,
      threatsDetected: 0,
    });

    const scanId = Math.random().toString(36).substr(2, 9);
    window.dispatchEvent(new CustomEvent('scanUpdate', {
      detail: { scanId, status: 'in-progress' }
    }));

    for (let i = 0; i < customPayloads.length; i++) {
      if (!isFuzzing) break;

      const payload = customPayloads[i];
      addLog(`Testing payload: ${payload}`);

      try {
        const result = await fuzzerRequest(dvwaUrl, payload, sessionCookie, module);
        
        setScanStats(prev => ({
          payloadsSent: prev.payloadsSent + 1,
          responsesReceived: prev.responsesReceived + 1,
          threatsDetected: prev.threatsDetected + (result.vulnerabilityDetected ? 1 : 0)
        }));

        if (result.vulnerabilityDetected) {
          addLog(`⚠️ ALERT: Potential vulnerability detected with payload: ${payload}`);
          toast({
            title: "Vulnerability Detected",
            description: `A potential vulnerability was found using payload: ${payload}`,
            variant: "destructive",
          });
        }

        setProgress((i + 1) / customPayloads.length * 100);
      } catch (error) {
        addLog(`Error testing payload: ${payload}`);
      }

      await new Promise(resolve => setTimeout(resolve, 500)); // Rate limiting
    }

    setIsFuzzing(false);
    window.dispatchEvent(new CustomEvent('scanUpdate', {
      detail: {
        scanId,
        status: 'completed',
        vulnerabilities: scanStats.threatsDetected
      }
    }));

    addLog("Fuzzing process completed!");
  };

  const handleStopFuzzing = () => {
    setIsFuzzing(false);
    addLog("Fuzzing process stopped by user.");
    toast({
      title: "Fuzzing Stopped",
      description: "The fuzzing process has been stopped",
    });
  };

  useEffect(() => {
    return () => {
      setCustomPayloads([]);
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
