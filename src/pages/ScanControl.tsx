
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { useForm } from 'react-hook-form';
import { CyberpunkScannerAnimation } from '@/components/dashboard/CyberpunkScannerAnimation';
import DashboardLayout from '@/components/layout/DashboardLayout';

type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

const ScanControl = () => {
  const [scanProgress, setScanProgress] = useState(0);
  const [scanActive, setScanActive] = useState(false);
  const [scanTarget, setScanTarget] = useState('http://localhost/dvwa');
  const [scanType, setScanType] = useState('full');
  const [scanSpeed, setScanSpeed] = useState(50);
  const [threatLevel, setThreatLevel] = useState<ThreatLevel>('none');
  const [detectedThreats, setDetectedThreats] = useState(0);
  const [currentVulnerability, setCurrentVulnerability] = useState('');
  const [exploitPayload, setExploitPayload] = useState('');

  // Initialize the form
  const form = useForm({
    defaultValues: {
      target: scanTarget,
      type: scanType,
      speed: scanSpeed,
      authentication: false,
      cookieHandling: true,
      safeMode: true
    }
  });

  const scanTypes = [
    { value: 'quick', label: 'Quick Scan', description: 'Fast scan with basic security checks' },
    { value: 'full', label: 'Full Scan', description: 'Comprehensive scan with all security checks' },
    { value: 'custom', label: 'Custom Scan', description: 'Customize which security checks to run' }
  ];

  const vulnerabilityData = [
    { type: 'SQL Injection', payload: "' OR 1=1 --" },
    { type: 'XSS', payload: "<script>alert('XSS')</script>" },
    { type: 'CSRF', payload: "forged_token=12345" },
    { type: 'Command Injection', payload: "cat /etc/passwd | grep root" },
    { type: 'File Inclusion', payload: "../../etc/passwd" }
  ];

  useEffect(() => {
    if (scanActive) {
      const interval = setInterval(() => {
        setScanProgress(prev => {
          const newProgress = prev + (Math.random() * 5);
          
          if (newProgress > 20 && newProgress < 25 && threatLevel === 'none') {
            setThreatLevel('low');
            setDetectedThreats(1);
            const vuln = vulnerabilityData[0];
            setCurrentVulnerability(vuln.type);
            setExploitPayload(vuln.payload);
          } else if (newProgress > 40 && newProgress < 45 && threatLevel === 'low') {
            setThreatLevel('medium');
            setDetectedThreats(3);
            const vuln = vulnerabilityData[1];
            setCurrentVulnerability(vuln.type);
            setExploitPayload(vuln.payload);
          } else if (newProgress > 70 && newProgress < 75 && threatLevel === 'medium') {
            setThreatLevel('high');
            setDetectedThreats(7);
            const vuln = vulnerabilityData[3];
            setCurrentVulnerability(vuln.type);
            setExploitPayload(vuln.payload);
          }
          
          if (newProgress >= 100) {
            setScanActive(false);
            return 100;
          }
          
          return newProgress;
        });
      }, 300);
      
      return () => clearInterval(interval);
    }
  }, [scanActive, threatLevel]);

  const startScan = () => {
    setScanProgress(0);
    setThreatLevel('none');
    setDetectedThreats(0);
    setCurrentVulnerability('');
    setExploitPayload('');
    setScanActive(true);
  };

  const stopScan = () => {
    setScanActive(false);
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Web Application Scanner</CardTitle>
            <CardDescription>Configure and run security scans against web applications</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="config" className="space-y-4">
              <TabsList>
                <TabsTrigger value="config">Configuration</TabsTrigger>
                <TabsTrigger value="results">Results</TabsTrigger>
                <TabsTrigger value="logs">Logs</TabsTrigger>
              </TabsList>
              
              <TabsContent value="config" className="space-y-4">
                <Form {...form}>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <FormField
                        control={form.control}
                        name="target"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Target URL</FormLabel>
                            <FormControl>
                              <Input 
                                placeholder="https://example.com" 
                                value={scanTarget} 
                                onChange={(e) => {
                                  setScanTarget(e.target.value);
                                  field.onChange(e);
                                }}
                                disabled={scanActive}
                              />
                            </FormControl>
                            <FormDescription>Enter the URL of the target web application</FormDescription>
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={form.control}
                        name="type"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Scan Type</FormLabel>
                            <Select 
                              value={scanType} 
                              onValueChange={(value) => {
                                setScanType(value);
                                field.onChange(value);
                              }}
                              disabled={scanActive}
                            >
                              <SelectTrigger>
                                <SelectValue placeholder="Select a scan type" />
                              </SelectTrigger>
                              <SelectContent>
                                {scanTypes.map(type => (
                                  <SelectItem key={type.value} value={type.value}>
                                    {type.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                            <FormDescription>
                              {scanTypes.find(t => t.value === scanType)?.description}
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={form.control}
                        name="speed"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Scan Speed: {scanSpeed}%</FormLabel>
                            <Slider 
                              value={[scanSpeed]} 
                              onValueChange={(v) => {
                                setScanSpeed(v[0]);
                                field.onChange(v[0]);
                              }}
                              disabled={scanActive}
                              min={10}
                              max={100}
                              step={10}
                            />
                            <FormDescription>
                              Higher speeds may trigger WAF protection or cause false positives
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                    </div>
                    
                    <div className="space-y-4">
                      <FormField
                        control={form.control}
                        name="authentication"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                            <div className="space-y-0.5">
                              <FormLabel className="text-base">
                                Authentication
                              </FormLabel>
                              <FormDescription>
                                Enable if target requires authentication
                              </FormDescription>
                            </div>
                            <FormControl>
                              <Switch 
                                checked={field.value}
                                onCheckedChange={field.onChange}
                                disabled={scanActive} 
                              />
                            </FormControl>
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={form.control}
                        name="cookieHandling"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                            <div className="space-y-0.5">
                              <FormLabel className="text-base">
                                Cookie Handling
                              </FormLabel>
                              <FormDescription>
                                Maintain cookies during scan
                              </FormDescription>
                            </div>
                            <FormControl>
                              <Switch 
                                checked={field.value}
                                onCheckedChange={field.onChange}
                                disabled={scanActive} 
                              />
                            </FormControl>
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={form.control}
                        name="safeMode"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                            <div className="space-y-0.5">
                              <FormLabel className="text-base">
                                Safe Mode
                              </FormLabel>
                              <FormDescription>
                                Don't execute potentially harmful payloads
                              </FormDescription>
                            </div>
                            <FormControl>
                              <Switch 
                                checked={field.value}
                                onCheckedChange={field.onChange}
                                disabled={scanActive} 
                              />
                            </FormControl>
                          </FormItem>
                        )}
                      />
                    </div>
                  </div>
                </Form>
              </TabsContent>
              
              <TabsContent value="results" className="space-y-4">
                {!scanActive && scanProgress === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <p>Start a scan to see results</p>
                  </div>
                ) : (
                  <>
                    <div className="rounded-lg border p-4">
                      <div className="flex justify-between items-center mb-4">
                        <h3 className="font-medium">Scan Progress</h3>
                        <span className="text-sm font-mono">{Math.round(scanProgress)}%</span>
                      </div>
                      <Progress value={scanProgress} className="h-2" />
                    </div>
                    
                    {detectedThreats > 0 && (
                      <div className="rounded-lg border border-destructive/50 p-4 space-y-4">
                        <div className="flex justify-between items-center">
                          <h3 className="font-medium text-destructive">Vulnerabilities Detected</h3>
                          <span className="font-mono text-destructive">{detectedThreats}</span>
                        </div>
                        
                        {currentVulnerability && (
                          <div className="space-y-2">
                            <div className="grid grid-cols-3 gap-4 text-sm">
                              <div className="font-medium">Type</div>
                              <div className="font-medium">Severity</div>
                              <div className="font-medium">Location</div>
                            </div>
                            <div className="grid grid-cols-3 gap-4 text-sm">
                              <div>{currentVulnerability}</div>
                              <div className={
                                threatLevel === 'critical' ? 'text-red-500' :
                                threatLevel === 'high' ? 'text-orange-500' :
                                threatLevel === 'medium' ? 'text-yellow-500' :
                                'text-green-500'
                              }>
                                {threatLevel.charAt(0).toUpperCase() + threatLevel.slice(1)}
                              </div>
                              <div className="font-mono text-xs">/login.php</div>
                            </div>
                            {exploitPayload && (
                              <div className="mt-2 p-2 bg-muted rounded text-xs font-mono">
                                <p className="text-muted-foreground mb-1">Payload:</p>
                                {exploitPayload}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
              </TabsContent>
              
              <TabsContent value="logs" className="min-h-[200px]">
                <div className="rounded-lg border bg-black p-4 h-[300px] font-mono text-xs text-green-400 overflow-auto">
                  {scanActive && (
                    <div className="space-y-2">
                      <p>[{new Date().toLocaleTimeString()}] Starting scan of {scanTarget}</p>
                      <p>[{new Date().toLocaleTimeString()}] Using scan type: {scanType}</p>
                      <p>[{new Date().toLocaleTimeString()}] Checking for common web vulnerabilities...</p>
                      {scanProgress > 20 && <p>[{new Date().toLocaleTimeString()}] Checking SQL injection vulnerabilities...</p>}
                      {scanProgress > 25 && <p>[{new Date().toLocaleTimeString()}] Found potential SQL injection at /login.php</p>}
                      {scanProgress > 40 && <p>[{new Date().toLocaleTimeString()}] Checking XSS vulnerabilities...</p>}
                      {scanProgress > 45 && <p>[{new Date().toLocaleTimeString()}] Found potential XSS at /search.php</p>}
                      {scanProgress > 60 && <p>[{new Date().toLocaleTimeString()}] Checking for command injection...</p>}
                      {scanProgress > 70 && <p>[{new Date().toLocaleTimeString()}] Checking for file inclusion vulnerabilities...</p>}
                      {scanProgress > 75 && <p>[{new Date().toLocaleTimeString()}] Found potential command injection at /ping.php</p>}
                      {scanProgress > 90 && <p>[{new Date().toLocaleTimeString()}] Finalizing scan results...</p>}
                      {scanProgress >= 100 && <p>[{new Date().toLocaleTimeString()}] Scan completed. Found {detectedThreats} vulnerabilities.</p>}
                    </div>
                  )}
                  {!scanActive && scanProgress === 0 && (
                    <p>[{new Date().toLocaleTimeString()}] Scanner ready. Waiting to start...</p>
                  )}
                  {!scanActive && scanProgress === 100 && (
                    <p>[{new Date().toLocaleTimeString()}] Scan completed. Ready for next scan.</p>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
          <CardFooter className="flex justify-between">
            <div className="text-sm text-muted-foreground">
              {scanActive ? 'Scanning in progress...' : 'Ready to scan'}
            </div>
            <div className="flex gap-2">
              {scanActive ? (
                <Button variant="destructive" onClick={stopScan}>
                  Stop Scan
                </Button>
              ) : (
                <Button onClick={startScan}>
                  Start Scan
                </Button>
              )}
            </div>
          </CardFooter>
        </Card>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="md:col-span-2 h-[300px]">
            <CardHeader className="pb-2">
              <CardTitle>Live Scanner Visualization</CardTitle>
            </CardHeader>
            <CardContent className="h-[230px]">
              <CyberpunkScannerAnimation 
                active={scanActive} 
                threatLevel={threatLevel}
                detectedThreats={detectedThreats}
                dvwaConnected={true}
                dvwaUrl={scanTarget}
                currentVulnerability={currentVulnerability}
                exploitPayload={exploitPayload}
              />
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default ScanControl;
