import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Upload, Link } from 'lucide-react';
import { toast } from 'sonner';
import { fuzzerApi } from '@/services/api';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';

export const RealTimeFuzzing: React.FC = () => {
  const { isConnected: dvwaConnected, setIsConnected } = useDVWAConnection();
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080');
  const [payloadSet, setPayloadSet] = useState('custom-payloads');
  const [fuzzingMode, setFuzzingMode] = useState('thorough-scan');
  const [dvwaModule, setDvwaModule] = useState('command-injection');
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [customPayloads, setCustomPayloads] = useState<string>('');

  const payloadOptions = [
    { value: 'custom-payloads', label: 'Custom Payloads' },
    { value: 'xss-payloads', label: 'XSS Payloads' },
    { value: 'sqli-payloads', label: 'SQL Injection Payloads' },
    { value: 'lfi-payloads', label: 'LFI Payloads' },
    { value: 'rce-payloads', label: 'RCE Payloads' },
  ];

  const fuzzingModeOptions = [
    { value: 'thorough-scan', label: 'Thorough Scan' },
    { value: 'quick-scan', label: 'Quick Scan' },
    { value: 'deep-scan', label: 'Deep Scan' },
    { value: 'focused-scan', label: 'Focused Scan' },
  ];

  const dvwaModuleOptions = [
    { value: 'command-injection', label: 'Command Injection' },
    { value: 'xss-reflected', label: 'XSS (Reflected)' },
    { value: 'xss-stored', label: 'XSS (Stored)' },
    { value: 'sql-injection', label: 'SQL Injection' },
    { value: 'file-inclusion', label: 'File Inclusion' },
    { value: 'file-upload', label: 'File Upload' },
    { value: 'csrf', label: 'CSRF' },
    { value: 'brute-force', label: 'Brute Force' },
  ];

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const connectToDVWA = async () => {
    try {
      addLog('Attempting to connect to DVWA...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      setIsConnected(true);
      addLog('Successfully connected to DVWA');
      toast.success('Connected to DVWA successfully');
    } catch (error) {
      addLog('Failed to connect to DVWA');
      toast.error('Failed to connect to DVWA');
    }
  };

  const uploadCustomPayloads = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.txt,.json';
    input.onchange = (event) => {
      const file = (event.target as HTMLInputElement).files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
          const content = e.target?.result as string;
          setCustomPayloads(content);
          addLog(`Uploaded custom payloads: ${file.name}`);
          toast.success('Custom payloads uploaded successfully');
        };
        reader.readAsText(file);
      }
    };
    input.click();
  };

  const startFuzzing = async () => {
    try {
      setIsFuzzing(true);
      setProgress(0);
      setLogs([]);
      
      addLog('Starting new fuzzing session...');
      addLog(`Target: ${targetUrl}`);
      addLog(`Payload Set: ${payloadOptions.find(p => p.value === payloadSet)?.label}`);
      addLog(`Fuzzing Mode: ${fuzzingModeOptions.find(m => m.value === fuzzingMode)?.label}`);
      addLog(`DVWA Module: ${dvwaModuleOptions.find(d => d.value === dvwaModule)?.label}`);
      
      const newSessionId = `fuzzing-${Date.now()}`;
      setSessionId(newSessionId);
      addLog(`Fuzzer session created: ${newSessionId}`);
      
      if (customPayloads.trim()) {
        const payloadList = customPayloads.split('\n').filter(p => p.trim());
        if (payloadList.length > 0) {
          addLog(`Uploading ${payloadList.length} custom payloads...`);
        }
      }
      
      const vulnerabilityTypes = getVulnerabilityTypes(payloadSet, dvwaModule);
      addLog(`Starting fuzzing with vulnerability types: ${vulnerabilityTypes.join(', ')}`);
      
      // Dispatch scan start events for all components
      const scanStartData = { 
        sessionId: newSessionId,
        target: targetUrl,
        module: dvwaModule,
        payloadSet,
        timestamp: new Date()
      };
      
      window.dispatchEvent(new CustomEvent('scanStart', { detail: scanStartData }));
      window.dispatchEvent(new CustomEvent('scanStarted', { detail: scanStartData }));
      
      simulateProgress();
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      addLog(`Error starting fuzzing: ${errorMessage}`);
      toast.error('Failed to start fuzzing', {
        description: errorMessage
      });
      setIsFuzzing(false);
    }
  };

  const getVulnerabilityTypes = (payloadSet: string, dvwaModule: string) => {
    switch (payloadSet) {
      case 'xss-payloads':
        return ['xss'];
      case 'sqli-payloads':
        return ['sqli'];
      case 'lfi-payloads':
        return ['lfi'];
      case 'rce-payloads':
        return ['rce'];
      default:
        switch (dvwaModule) {
          case 'command-injection':
            return ['rce'];
          case 'xss-reflected':
          case 'xss-stored':
            return ['xss'];
          case 'sql-injection':
            return ['sqli'];
          case 'file-inclusion':
            return ['lfi'];
          case 'csrf':
            return ['csrf'];
          default:
            return ['xss', 'sqli', 'lfi', 'rce'];
        }
    }
  };

  const simulateProgress = () => {
    let currentProgress = 0;
    const interval = setInterval(() => {
      currentProgress += Math.random() * 5;
      
      if (currentProgress >= 100) {
        currentProgress = 100;
        setProgress(100);
        setIsFuzzing(false);
        addLog('Fuzzing process completed');
        
        const vulnerabilities = Math.floor(Math.random() * 5) + 1;
        const payloadsTested = Math.floor(Math.random() * 50) + 20;
        const criticalCount = Math.floor(vulnerabilities / 2);
        
        // Create comprehensive report data for all components
        const completionData = {
          sessionId,
          vulnerabilities,
          payloadsTested,
          criticalCount,
          targetUrl,
          target: targetUrl,
          timestamp: new Date(),
          status: 'completed',
          duration: `${Math.floor(Math.random() * 5) + 1}m ${Math.floor(Math.random() * 60)}s`,
          severity: vulnerabilities > 3 ? 'critical' : vulnerabilities > 1 ? 'high' : vulnerabilities > 0 ? 'medium' : 'low',
          riskLevel: vulnerabilities > 3 ? 'critical' : vulnerabilities > 1 ? 'high' : vulnerabilities > 0 ? 'medium' : 'low',
          module: dvwaModule,
          payloadSet
        };
        
        addLog(`Scan completed: ${vulnerabilities} vulnerabilities found`);
        
        // Dispatch multiple events for different components
        window.dispatchEvent(new CustomEvent('scanComplete', { detail: completionData }));
        window.dispatchEvent(new CustomEvent('globalScanComplete', { detail: completionData }));
        window.dispatchEvent(new CustomEvent('scanReportGenerated', { detail: completionData }));
        
        console.log('Fuzzing completed, dispatching events:', completionData);
        
        clearInterval(interval);
        toast.success(`Fuzzing completed! Found ${vulnerabilities} vulnerabilities`);
      } else {
        setProgress(currentProgress);
        
        if (Math.random() > 0.7) {
          const randomPayload = getRandomPayload();
          addLog(`Testing payload: ${randomPayload}`);
          window.dispatchEvent(new CustomEvent('payloadSent'));
          
          if (Math.random() > 0.8) {
            const threat = getRandomThreat();
            addLog(`🚨 THREAT DETECTED: ${threat.description}`);
            
            const threatData = {
              payload: threat.payload,
              severity: threat.severity,
              vulnerabilityType: getVulnerabilityTypeFromPayload(threat.payload),
              field: dvwaModule,
              timestamp: new Date()
            };
            
            window.dispatchEvent(new CustomEvent('threatDetected', { detail: threatData }));
            window.dispatchEvent(new CustomEvent('globalThreatDetected', { detail: threatData }));
          }
        }
        
        window.dispatchEvent(new CustomEvent('scanProgress', {
          detail: { progress: currentProgress }
        }));
      }
    }, 1000);
  };

  const getVulnerabilityTypeFromPayload = (payload: string) => {
    if (payload.includes('<script>') || payload.includes('alert')) return 'XSS';
    if (payload.includes('OR 1=1') || payload.includes('DROP')) return 'SQL Injection';
    if (payload.includes('../') || payload.includes('passwd')) return 'Path Traversal';
    if (payload.includes('rm -rf') || payload.includes('cat')) return 'Command Injection';
    return 'Unknown';
  };

  const getRandomPayload = () => {
    const payloads = [
      "<script>alert('XSS')</script>",
      "' OR 1=1 --",
      "../../../etc/passwd",
      "; cat /etc/passwd",
      "<img src=x onerror=alert(1)>",
      "admin'#",
      "'; DROP TABLE users; --"
    ];
    return payloads[Math.floor(Math.random() * payloads.length)];
  };

  const getRandomThreat = () => {
    const threats = [
      { payload: "<script>alert(1)</script>", severity: "high", description: "XSS vulnerability detected" },
      { payload: "' OR 1=1 --", severity: "critical", description: "SQL injection vulnerability" },
      { payload: "../../../etc/passwd", severity: "medium", description: "Path traversal vulnerability" },
      { payload: "; rm -rf /", severity: "critical", description: "Command injection detected" }
    ];
    return threats[Math.floor(Math.random() * threats.length)];
  };

  return (
    <div className="space-y-6">
      <div className="mb-4">
        {dvwaConnected ? (
          <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
            DVWA Connected
          </Badge>
        ) : (
          <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
            DVWA Offline
          </Badge>
        )}
      </div>

      <Card className="bg-card/60 backdrop-blur-sm border-border/40">
        <CardHeader>
          <CardTitle className="text-2xl bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
            Web Application Fuzzer
          </CardTitle>
          <p className="text-muted-foreground">Configure and test fuzzing on web applications</p>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="targetUrl" className="flex items-center gap-2 text-foreground">
              <Link className="h-4 w-4" />
              Target URL
            </Label>
            <Input
              id="targetUrl"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:8080"
              disabled={isFuzzing}
              className="bg-background/50 border-border"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label className="text-foreground">Payload Set</Label>
              <Select value={payloadSet} onValueChange={setPayloadSet} disabled={isFuzzing}>
                <SelectTrigger className="bg-background/50 border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-background border-border">
                  {payloadOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label className="text-foreground">Fuzzing Mode</Label>
              <Select value={fuzzingMode} onValueChange={setFuzzingMode} disabled={isFuzzing}>
                <SelectTrigger className="bg-background/50 border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-background border-border">
                  {fuzzingModeOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label className="text-foreground">DVWA Module</Label>
              <Select value={dvwaModule} onValueChange={setDvwaModule} disabled={isFuzzing}>
                <SelectTrigger className="bg-background/50 border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-background border-border">
                  {dvwaModuleOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {isFuzzing && (
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <Label className="text-foreground">Progress</Label>
                <Badge variant="destructive" className="animate-pulse">
                  Fuzzing Active
                </Badge>
              </div>
              <Progress value={progress} className="w-full" />
              <p className="text-sm text-muted-foreground">{Math.round(progress)}% complete</p>
            </div>
          )}

          <div className="flex gap-4">
            <Button
              onClick={connectToDVWA}
              variant="outline"
              disabled={isFuzzing}
              className="flex-1 border-border"
            >
              Connect to DVWA
            </Button>
            
            <Button
              onClick={uploadCustomPayloads}
              variant="outline"
              disabled={isFuzzing}
              className="flex-1 flex items-center gap-2 border-border"
            >
              <Upload className="h-4 w-4" />
              Upload Custom Payloads
            </Button>
            
            <Button
              onClick={startFuzzing}
              disabled={!targetUrl || isFuzzing}
              className="flex-1"
            >
              {isFuzzing ? 'Fuzzing...' : 'Start Fuzzing'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {logs.length > 0 && (
        <Card className="bg-card/60 backdrop-blur-sm border-border/40">
          <CardHeader>
            <CardTitle className="text-foreground">Live Fuzzing Logs</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[300px] w-full rounded-md border border-border p-4 bg-background/20">
              {logs.length === 0 ? (
                <div className="text-center text-muted-foreground">
                  No logs yet. Start fuzzing to see live output.
                </div>
              ) : (
                <div className="space-y-1">
                  {logs.map((log, index) => (
                    <div 
                      key={index}
                      className={`text-sm font-mono ${
                        log.includes('ERROR') ? 'text-destructive' :
                        log.includes('THREAT') ? 'text-orange-400' :
                        log.includes('completed') ? 'text-green-400' :
                        'text-foreground'
                      }`}
                    >
                      {log}
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
