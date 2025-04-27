
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { fuzzerApi, systemApi } from '@/services/api';
import { toast } from '@/hooks/use-toast';
import { useNavigate } from 'react-router-dom';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { AlertCircle } from 'lucide-react';
import { CustomPayloads } from '@/components/fuzzer/CustomPayloads';
import { FuzzingLogs } from '@/components/fuzzer/FuzzingLogs';
import { ScanningStatus } from '@/components/fuzzer/ScanningStatus';

const API_BASE_URL = 'http://localhost:8080/api';

const Fuzzer = () => {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080');
  const [customPayloads, setCustomPayloads] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [serverStatus, setServerStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [vulnerabilityTypes, setVulnerabilityTypes] = useState(['xss', 'sqli']);
  const navigate = useNavigate();

  useEffect(() => {
    checkServerStatus();
    return () => {
      if (sessionId && isScanning) {
        stopScan();
      }
    };
  }, []);

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    
    if (sessionId && isScanning) {
      interval = setInterval(fetchStatus, 1000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [sessionId, isScanning]);

  const checkServerStatus = async () => {
    try {
      setServerStatus('checking');
      await systemApi.getStatus();
      setServerStatus('online');
    } catch (error) {
      console.error('Server connection error:', error);
      setServerStatus('offline');
      toast({
        title: "Server Error",
        description: "Unable to connect to the fuzzing server. Please ensure it's running.",
        variant: "destructive",
      });
    }
  };

  const startScan = async () => {
    try {
      if (!targetUrl) {
        toast({
          title: "Missing Target",
          description: "Please provide a target URL",
          variant: "destructive",
        });
        return;
      }

      const createResponse = await fuzzerApi.createFuzzer(targetUrl);
      
      if (!createResponse.success) {
        throw new Error(createResponse.error || 'Failed to create fuzzer');
      }
      
      setSessionId(createResponse.session_id);
      addLog(`Fuzzer created for ${targetUrl}`);
      
      const payloadsArray = customPayloads
        .split('\n')
        .map(p => p.trim())
        .filter(p => p);
      
      const startResponse = await fuzzerApi.startFuzzing(
        createResponse.session_id, 
        vulnerabilityTypes,
        payloadsArray
      );
      
      if (!startResponse.success) {
        throw new Error(startResponse.error || 'Failed to start fuzzing');
      }
      
      setIsScanning(true);
      addLog('Fuzzing process started');
      
      toast({
        title: "Scan Started",
        description: "The fuzzing process has been initiated",
      });
    } catch (error: any) {
      console.error('Error starting scan:', error);
      toast({
        title: "Scan Error",
        description: error.message || "Failed to start fuzzing process",
        variant: "destructive",
      });
    }
  };

  const stopScan = async () => {
    if (!sessionId) return;
    
    try {
      await fuzzerApi.stopFuzzing(sessionId);
      setIsScanning(false);
      addLog('Fuzzing process stopped');
      toast({
        title: "Scan Stopped",
        description: "The fuzzing process has been stopped",
      });
    } catch (error: any) {
      console.error('Error stopping scan:', error);
      toast({
        title: "Error",
        description: error.message || "Failed to stop fuzzing process",
        variant: "destructive",
      });
    }
  };

  const fetchStatus = async () => {
    if (!sessionId) return;
    
    try {
      const statusResponse = await fuzzerApi.getFuzzerStatus(sessionId);
      
      if (statusResponse.success) {
        setProgress(statusResponse.progress || 0);
        
        if (statusResponse.logs && statusResponse.logs.length > 0) {
          const newLogs = statusResponse.logs
            .filter((log: any) => log.type === 'activity')
            .map((log: any) => `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.message}`);
          
          if (newLogs.length > 0) {
            setLogs(prev => [...prev, ...newLogs]);
          }
        }
        
        if (!statusResponse.active && statusResponse.progress === 100) {
          setIsScanning(false);
          toast({
            title: "Scan Completed",
            description: "The fuzzing process has completed",
          });
          
          if (statusResponse.dataset && statusResponse.dataset.length > 0) {
            navigate('/ml-analysis', { 
              state: { 
                sessionId, 
                dataset: statusResponse.dataset 
              } 
            });
          }
        }
      }
    } catch (error) {
      console.error('Error fetching status:', error);
    }
  };

  const handleVulnerabilityTypeChange = (type: string) => {
    setVulnerabilityTypes(prev => 
      prev.includes(type) 
        ? prev.filter(t => t !== type) 
        : [...prev, type]
    );
  };

  const handleCustomPayloadsChange = (newPayloads: string[]) => {
    setCustomPayloads(newPayloads.join('\n'));
  };

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const clearLogs = () => {
    setLogs([]);
  };

  if (serverStatus === 'checking') {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-full">
          <div className="text-center">
            <h2 className="text-xl font-semibold mb-2">Connecting to server...</h2>
            <Progress value={50} className="w-60" />
          </div>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-6">Web Application Fuzzer</h1>
        
        {serverStatus === 'offline' && (
          <Alert variant="destructive" className="mb-6">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Server Connection Error</AlertTitle>
            <AlertDescription>
              Unable to connect to the fuzzing server. Please ensure it's running at {API_BASE_URL}.
              <Button variant="outline" size="sm" className="ml-2 mt-2" onClick={checkServerStatus}>
                Retry Connection
              </Button>
            </AlertDescription>
          </Alert>
        )}
        
        <Tabs defaultValue="config">
          <TabsList>
            <TabsTrigger value="config">Configuration</TabsTrigger>
            <TabsTrigger value="payloads">Custom Payloads</TabsTrigger>
            <TabsTrigger value="logs">Logs</TabsTrigger>
          </TabsList>
          
          <TabsContent value="config">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Target Configuration</CardTitle>
                  <CardDescription>Configure the target application to fuzz</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="target-url">Target URL</Label>
                    <Input 
                      id="target-url" 
                      placeholder="https://example.com/vulnerable-page"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      disabled={isScanning}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label>Vulnerability Types</Label>
                    <div className="flex flex-wrap gap-2">
                      {['xss', 'sqli', 'lfi', 'rce', 'csrf', 'auth'].map(type => (
                        <Button 
                          key={type}
                          variant={vulnerabilityTypes.includes(type) ? "default" : "outline"}
                          size="sm"
                          onClick={() => handleVulnerabilityTypeChange(type)}
                          disabled={isScanning}
                        >
                          {type.toUpperCase()}
                        </Button>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader>
                  <CardTitle>Fuzzing Status</CardTitle>
                  <CardDescription>Current fuzzing process status</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScanningStatus isScanning={isScanning} progress={progress} />
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="payloads">
            <Card>
              <CardHeader>
                <CardTitle>Custom Payloads</CardTitle>
                <CardDescription>Upload and manage custom fuzzing payloads</CardDescription>
              </CardHeader>
              <CardContent>
                <CustomPayloads onPayloadsChange={handleCustomPayloadsChange} />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="logs">
            <FuzzingLogs logs={logs} isScanning={isScanning} />
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
