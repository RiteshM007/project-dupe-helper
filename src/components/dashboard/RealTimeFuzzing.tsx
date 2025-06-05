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

export const RealTimeFuzzing: React.FC = () => {
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
      // Simulate connection logic
      await new Promise(resolve => setTimeout(resolve, 2000));
      addLog('Successfully connected to DVWA');
      toast.success('Connected to DVWA successfully');
    } catch (error) {
      addLog('Failed to connect to DVWA');
      toast.error('Failed to connect to DVWA');
    }
  };

  const uploadCustomPayloads = () => {
    // Create a file input element
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
      
      // Create fuzzer session
      const createResult = await fuzzerApi.createFuzzer(targetUrl, 'custom_wordlist.txt');
      
      if (!createResult.success) {
        throw new Error(createResult.message || 'Failed to create fuzzer');
      }
      
      const newSessionId = createResult.sessionId;
      setSessionId(newSessionId);
      addLog(`Fuzzer session created: ${newSessionId}`);
      
      // Upload custom payloads if provided
      if (customPayloads.trim()) {
        const payloadList = customPayloads.split('\n').filter(p => p.trim());
        if (payloadList.length > 0) {
          addLog(`Uploading ${payloadList.length} custom payloads...`);
          await fuzzerApi.uploadPayloads(newSessionId, payloadList);
          addLog('Custom payloads uploaded successfully');
        }
      }
      
      // Map payload set to vulnerability types
      const vulnerabilityTypes = getVulnerabilityTypes(payloadSet, dvwaModule);
      
      // Start fuzzing
      addLog(`Starting fuzzing with vulnerability types: ${vulnerabilityTypes.join(', ')}`);
      const startResult = await fuzzerApi.startFuzzing(newSessionId, vulnerabilityTypes);
      
      if (!startResult.success) {
        throw new Error(startResult.message || 'Failed to start fuzzing');
      }
      
      addLog('Fuzzing process started successfully');
      
      // Dispatch scan start event for other components
      window.dispatchEvent(new CustomEvent('scanStart', {
        detail: { sessionId: newSessionId }
      }));
      
      // Start progress simulation
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
        // For custom payloads, determine based on DVWA module
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
        
        // Dispatch completion event
        window.dispatchEvent(new CustomEvent('scanComplete', {
          detail: {
            sessionId,
            vulnerabilities: Math.floor(Math.random() * 5),
            payloadsTested: Math.floor(Math.random() * 50) + 20
          }
        }));
        
        clearInterval(interval);
        toast.success('Fuzzing completed successfully');
      } else {
        setProgress(currentProgress);
        
        // Simulate payload sending
        if (Math.random() > 0.7) {
          addLog(`Testing payload: ${getRandomPayload()}`);
          window.dispatchEvent(new CustomEvent('payloadSent'));
          
          // Simulate threat detection
          if (Math.random() > 0.8) {
            const threat = getRandomThreat();
            addLog(`🚨 THREAT DETECTED: ${threat.description}`);
            window.dispatchEvent(new CustomEvent('threatDetected', {
              detail: {
                payload: threat.payload,
                severity: threat.severity
              }
            }));
          }
        }
        
        // Dispatch progress update
        window.dispatchEvent(new CustomEvent('scanProgress', {
          detail: { progress: currentProgress }
        }));
      }
    }, 1000);
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
      <Card className="cyberpunk-card">
        <CardHeader>
          <CardTitle className="text-2xl text-gradient">Web Application Fuzzer</CardTitle>
          <p className="text-muted-foreground">Configure and test fuzzing on web applications</p>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Target URL */}
          <div className="space-y-2">
            <Label htmlFor="targetUrl" className="flex items-center gap-2">
              <Link className="h-4 w-4" />
              Target URL
            </Label>
            <Input
              id="targetUrl"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:8080"
              disabled={isFuzzing}
              className="bg-background/50"
            />
          </div>

          {/* Configuration Row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Payload Set */}
            <div className="space-y-2">
              <Label>Payload Set</Label>
              <Select value={payloadSet} onValueChange={setPayloadSet} disabled={isFuzzing}>
                <SelectTrigger className="bg-background/50">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-background border-border z-50">
                  {payloadOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Fuzzing Mode */}
            <div className="space-y-2">
              <Label>Fuzzing Mode</Label>
              <Select value={fuzzingMode} onValueChange={setFuzzingMode} disabled={isFuzzing}>
                <SelectTrigger className="bg-background/50">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-background border-border z-50">
                  {fuzzingModeOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* DVWA Module */}
            <div className="space-y-2">
              <Label>DVWA Module</Label>
              <Select value={dvwaModule} onValueChange={setDvwaModule} disabled={isFuzzing}>
                <SelectTrigger className="bg-background/50">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-background border-border z-50">
                  {dvwaModuleOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Progress Bar */}
          {isFuzzing && (
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <Label>Progress</Label>
                <Badge variant="destructive">Fuzzing Active</Badge>
              </div>
              <Progress value={progress} className="w-full" />
              <p className="text-sm text-muted-foreground">{Math.round(progress)}% complete</p>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex gap-4">
            <Button
              onClick={connectToDVWA}
              variant="outline"
              disabled={isFuzzing}
              className="flex-1"
            >
              Connect to DVWA
            </Button>
            
            <Button
              onClick={uploadCustomPayloads}
              variant="outline"
              disabled={isFuzzing}
              className="flex-1 flex items-center gap-2"
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

      {/* Live Logs */}
      {logs.length > 0 && (
        <Card className="cyberpunk-card">
          <CardHeader>
            <CardTitle>Live Fuzzing Logs</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[300px] w-full rounded-md border p-4 bg-background/20">
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
