
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { fuzzerApi, systemApi } from '@/services/api';
import { toast } from '@/hooks/use-toast';
import { useNavigate } from 'react-router-dom';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { AlertCircle } from 'lucide-react';

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
    // Check server status on component mount
    checkServerStatus();
    
    // Cleanup on component unmount
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

      // Create fuzzer session
      const createResponse = await fuzzerApi.createFuzzer(targetUrl);
      
      if (!createResponse.success) {
        throw new Error(createResponse.error || 'Failed to create fuzzer');
      }
      
      setSessionId(createResponse.session_id);
      addLog(`Fuzzer created for ${targetUrl}`);
      
      // Prepare custom payloads if any
      const payloadsArray = customPayloads
        .split('\n')
        .map(p => p.trim())
        .filter(p => p);
      
      // Start fuzzing process
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
        
        // Add new logs if available
        if (statusResponse.logs && statusResponse.logs.length > 0) {
          const newLogs = statusResponse.logs
            .filter((log: any) => log.type === 'activity')
            .map((log: any) => `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.message}`);
          
          // Only add new logs that aren't already in the state
          if (newLogs.length > 0) {
            setLogs(prev => [...prev, ...newLogs]);
          }
        }
        
        // Check if scanning has completed
        if (!statusResponse.active && statusResponse.progress === 100) {
          setIsScanning(false);
          toast({
            title: "Scan Completed",
            description: "The fuzzing process has completed",
          });
          
          // Redirect to ML analysis with this session data
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
      // Don't show toast for every status fetch error
    }
  };

  const handleVulnerabilityTypeChange = (type: string) => {
    setVulnerabilityTypes(prev => 
      prev.includes(type) 
        ? prev.filter(t => t !== type) 
        : [...prev, type]
    );
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
                  <CardTitle>Custom Payloads</CardTitle>
                  <CardDescription>Add your own custom payloads (one per line)</CardDescription>
                </CardHeader>
                <CardContent>
                  <Textarea
                    placeholder="<script>alert(1)</script>&#10;' OR 1=1 --&#10;../../etc/passwd"
                    className="h-32"
                    value={customPayloads}
                    onChange={(e) => setCustomPayloads(e.target.value)}
                    disabled={isScanning}
                  />
                </CardContent>
              </Card>
            </div>
            
            <Card className="mt-6">
              <CardHeader>
                <CardTitle>Fuzzing Status</CardTitle>
                <CardDescription>Current fuzzing process status</CardDescription>
              </CardHeader>
              <CardContent>
                <Progress value={progress} className="h-2 mb-4" />
                <div className="flex justify-between text-sm">
                  <span>{progress}% complete</span>
                  <span>{isScanning ? 'Scanning in progress' : 'Idle'}</span>
                </div>
              </CardContent>
              <CardFooter>
                <div className="flex justify-between w-full">
                  {!isScanning ? (
                    <Button onClick={startScan} disabled={serverStatus === 'offline'}>
                      Start Fuzzing
                    </Button>
                  ) : (
                    <Button variant="destructive" onClick={stopScan}>
                      Stop Fuzzing
                    </Button>
                  )}
                  
                  <Button 
                    variant="outline" 
                    onClick={() => navigate('/ml-analysis')}
                  >
                    Go to ML Analysis
                  </Button>
                </div>
              </CardFooter>
            </Card>
          </TabsContent>
          
          <TabsContent value="logs">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <CardTitle>Fuzzing Logs</CardTitle>
                  <Button variant="outline" size="sm" onClick={clearLogs}>
                    Clear Logs
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96 w-full rounded-md border p-4">
                  {logs.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      No logs available. Start fuzzing to see logs.
                    </div>
                  ) : (
                    logs.map((log, index) => (
                      <React.Fragment key={index}>
                        <div className="text-sm">{log}</div>
                        {index < logs.length - 1 && <Separator className="my-2" />}
                      </React.Fragment>
                    ))
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
