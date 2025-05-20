
import React, { useState, useEffect, useRef } from 'react';
import { HeadlessBrowser } from '@/components/fuzzer/HeadlessBrowser';
import { FieldSelector } from '@/components/fuzzer/FieldSelector';
import { LiveLogs } from '@/components/fuzzer/LiveLogs';
import { Grid, GridItem } from '@/components/ui/grid';
import { toast } from '@/hooks/use-toast';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';

export const TargetedFuzzing: React.FC = () => {
  const { isConnected, setIsConnected, dvwaUrl, setDvwaUrl } = useDVWAConnection();
  const [logs, setLogs] = useState<string[]>([]);
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [selectedField, setSelectedField] = useState<string | null>(null);
  const [selectedFieldName, setSelectedFieldName] = useState<string | undefined>(undefined);
  const [exploitKeyword, setExploitKeyword] = useState('FUZZ');
  const [payloadIndex, setPayloadIndex] = useState(0);
  
  const payloads = useRef([
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "' OR 1=1 --",
    "admin' #",
    "../../../etc/passwd",
    "| cat /etc/passwd"
  ]);
  
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const progressIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    // Clean up on unmount
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
    };
  }, []);

  const addLog = (message: string) => {
    setLogs(prevLogs => [...prevLogs, `[${new Date().toLocaleTimeString()}] ${message}`]);
  };

  const handleConnect = (url: string) => {
    setIsConnected(true);
    setDvwaUrl(url);
    addLog(`Connected to ${url}`);
  };

  const handleFieldSelected = (fieldId: string, fieldName?: string) => {
    setSelectedField(fieldId);
    setSelectedFieldName(fieldName);
    addLog(`Selected field: ${fieldName || fieldId}`);
  };

  const handleExploitKeywordChange = (keyword: string) => {
    setExploitKeyword(keyword);
    addLog(`Set exploit keyword to: ${keyword}`);
  };

  const startFuzzing = () => {
    if (!selectedField) {
      toast({
        title: "No Field Selected",
        description: "Please select a target field first",
        variant: "destructive",
      });
      return;
    }
    
    setIsFuzzing(true);
    addLog(`Starting targeted fuzzing on field: ${selectedFieldName || selectedField}`);
    addLog(`Using exploit keyword: ${exploitKeyword}`);
    
    // Simulate the exploit keyword being detected
    addLog(`Detected exploit keyword "${exploitKeyword}" in field, starting payload injection`);
    
    // Dispatch the scan start event
    const sessionId = `fuzz-${Date.now()}`;
    window.dispatchEvent(new CustomEvent('scanStart', {
      detail: { scanId: sessionId }
    }));
    
    // Start the fuzzing process
    setPayloadIndex(0);
    executeFuzzing(sessionId);
    
    // Set up progress reporting
    const startTime = Date.now();
    const totalPayloads = payloads.current.length;
    
    progressIntervalRef.current = setInterval(() => {
      const progress = Math.min(100, (payloadIndex / totalPayloads) * 100);
      
      window.dispatchEvent(new CustomEvent('scanProgress', {
        detail: { 
          scanId: sessionId,
          progress 
        }
      }));
      
      if (progress >= 100) {
        clearInterval(progressIntervalRef.current!);
      }
    }, 500);
  };

  const executeFuzzing = (sessionId: string) => {
    if (!isFuzzing || payloadIndex >= payloads.current.length) {
      // Fuzzing complete
      if (isFuzzing) {
        completeFuzzing(sessionId);
      }
      return;
    }
    
    const currentPayload = payloads.current[payloadIndex];
    addLog(`Injecting payload [${payloadIndex + 1}/${payloads.current.length}]: ${currentPayload}`);
    
    // Simulate injecting the payload and checking for vulnerabilities
    const isVulnerable = Math.random() > 0.7;
    
    timeoutRef.current = setTimeout(() => {
      if (isVulnerable) {
        addLog(`ALERT: Vulnerability detected with payload: ${currentPayload}`);
        window.dispatchEvent(new CustomEvent('threatDetected', {
          detail: { 
            payload: currentPayload,
            field: selectedField,
            severity: getRandomSeverity()
          }
        }));
      } else {
        addLog(`No issues detected with payload: ${currentPayload}`);
      }
      
      window.dispatchEvent(new CustomEvent('payloadSent'));
      
      // Move to the next payload
      setPayloadIndex(prev => prev + 1);
      
      // Schedule the next payload execution
      timeoutRef.current = setTimeout(() => {
        executeFuzzing(sessionId);
      }, 1000);
    }, 1500);
  };
  
  const getRandomSeverity = (): ThreatLevel => {
    const severities: ThreatLevel[] = ['low', 'medium', 'high', 'critical'];
    return severities[Math.floor(Math.random() * severities.length)];
  };

  const completeFuzzing = (sessionId: string) => {
    setIsFuzzing(false);
    addLog('Targeted fuzzing completed');
    
    // Calculate random number of vulnerabilities found
    const vulnerabilities = Math.floor(Math.random() * 3);
    
    // Dispatch the scan complete event
    window.dispatchEvent(new CustomEvent('scanComplete', {
      detail: {
        scanId: sessionId,
        vulnerabilities,
        payloadsTested: payloads.current.length
      }
    }));
    
    // Show completion toast
    toast({
      title: "Fuzzing Complete",
      description: `Tested ${payloads.current.length} payloads on the target field`,
    });
  };

  const stopFuzzing = () => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
    }
    
    setIsFuzzing(false);
    addLog('Targeted fuzzing stopped by user');
    
    // Dispatch the scan stop event
    window.dispatchEvent(new CustomEvent('scanStop'));
    
    toast({
      title: "Fuzzing Stopped",
      description: "The fuzzing process was stopped",
    });
  };

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold">Targeted Field Fuzzing</h2>
      <p className="text-muted-foreground">
        Fuzz a specific field on the target website by selecting a field and using an exploit keyword
      </p>
      
      <Grid cols={1} md={2} gap={6} className="mb-6">
        <GridItem className="col-span-1">
          <HeadlessBrowser
            onConnect={handleConnect}
            onStartFuzzing={startFuzzing}
            onStopFuzzing={stopFuzzing}
            isFuzzing={isFuzzing}
            hasSelectedField={!!selectedField}
            exploitKeyword={exploitKeyword}
          />
        </GridItem>
        
        <GridItem className="col-span-1">
          <FieldSelector
            isActive={isConnected}
            onFieldSelected={handleFieldSelected}
            exploitKeyword={exploitKeyword}
            onExploitKeywordChange={handleExploitKeywordChange}
          />
        </GridItem>
      </Grid>
      
      <Grid cols={1} gap={6}>
        <GridItem className="w-full">
          <LiveLogs logs={logs} isActive={isFuzzing} />
        </GridItem>
      </Grid>
    </div>
  );
};
