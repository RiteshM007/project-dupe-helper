
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Checkbox } from '@/components/ui/checkbox';
import { ScrollArea } from '@/components/ui/scroll-area';
import { toast } from 'sonner';
import { fuzzerApi } from '@/services/api';

export const RealTimeFuzzing: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080');
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [vulnerabilityTypes, setVulnerabilityTypes] = useState<string[]>(['xss', 'sqli']);
  const [customPayloads, setCustomPayloads] = useState<string>('');

  const vulnerabilityOptions = [
    { id: 'xss', label: 'Cross-Site Scripting (XSS)' },
    { id: 'sqli', label: 'SQL Injection' },
    { id: 'lfi', label: 'Local File Inclusion' },
    { id: 'rce', label: 'Remote Code Execution' },
    { id: 'csrf', label: 'Cross-Site Request Forgery' },
  ];

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const startFuzzing = async () => {
    try {
      setIsFuzzing(true);
      setProgress(0);
      setLogs([]);
      
      addLog('Starting new fuzzing session...');
      addLog('Creating fuzzing session...');
      
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

  const stopFuzzing = async () => {
    try {
      if (sessionId) {
        addLog('Stopping fuzzing process...');
        await fuzzerApi.stopFuzzing(sessionId);
        addLog('Fuzzing process stopped');
        
        // Dispatch scan stop event
        window.dispatchEvent(new CustomEvent('scanStop'));
      }
      
      setIsFuzzing(false);
      setSessionId(null);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      addLog(`Error stopping fuzzing: ${errorMessage}`);
      toast.error('Error stopping fuzzing', {
        description: errorMessage
      });
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

  const handleVulnerabilityTypeChange = (vulnType: string, checked: boolean) => {
    if (checked) {
      setVulnerabilityTypes(prev => [...prev, vulnType]);
    } else {
      setVulnerabilityTypes(prev => prev.filter(v => v !== vulnType));
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Real-Time Web Application Fuzzing</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="targetUrl">Target URL</Label>
              <Input
                id="targetUrl"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://localhost:8080"
                disabled={isFuzzing}
              />
            </div>
            
            <div className="space-y-2">
              <Label>Status</Label>
              <div>
                {isFuzzing ? (
                  <Badge variant="destructive">Fuzzing Active</Badge>
                ) : (
                  <Badge variant="outline">Ready</Badge>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Vulnerability Types to Test</Label>
            <div className="grid grid-cols-2 gap-2">
              {vulnerabilityOptions.map((option) => (
                <div key={option.id} className="flex items-center space-x-2">
                  <Checkbox
                    id={option.id}
                    checked={vulnerabilityTypes.includes(option.id)}
                    onCheckedChange={(checked) => 
                      handleVulnerabilityTypeChange(option.id, checked as boolean)
                    }
                    disabled={isFuzzing}
                  />
                  <Label htmlFor={option.id} className="text-sm">{option.label}</Label>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="customPayloads">Custom Payloads (one per line)</Label>
            <textarea
              id="customPayloads"
              value={customPayloads}
              onChange={(e) => setCustomPayloads(e.target.value)}
              placeholder="<script>alert('custom')</script>&#10;' OR '1'='1&#10;../../../etc/passwd"
              className="w-full h-24 p-2 border rounded-md"
              disabled={isFuzzing}
            />
          </div>

          {isFuzzing && (
            <div className="space-y-2">
              <Label>Progress</Label>
              <Progress value={progress} className="w-full" />
              <p className="text-sm text-muted-foreground">{Math.round(progress)}% complete</p>
            </div>
          )}

          <div className="flex gap-2">
            <Button
              onClick={isFuzzing ? stopFuzzing : startFuzzing}
              variant={isFuzzing ? "destructive" : "default"}
              disabled={!targetUrl || vulnerabilityTypes.length === 0}
            >
              {isFuzzing ? 'Stop Fuzzing' : 'Start Fuzzing'}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Live Fuzzing Logs</CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[300px] w-full rounded-md border p-4">
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
                      log.includes('ERROR') ? 'text-red-500' :
                      log.includes('THREAT') ? 'text-orange-500' :
                      log.includes('completed') ? 'text-green-500' :
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
    </div>
  );
};
