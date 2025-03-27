
import React, { useState } from 'react';
import { Play, Pause, Square, AlertTriangle, ChevronRight, ChevronDown, Lock, Zap } from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { EnhancedScannerAnimation } from '@/components/dashboard/EnhancedScannerAnimation';

const ScanControl = () => {
  const [scanUrl, setScanUrl] = useState('https://');
  const [scanMode, setScanMode] = useState('active');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanActive, setScanActive] = useState(false);
  const [expandedPanel, setExpandedPanel] = useState('basic');
  const [threatLevel, setThreatLevel] = useState<'none' | 'low' | 'medium' | 'high' | 'critical'>('none');

  const togglePanel = (panel: string) => {
    setExpandedPanel(expandedPanel === panel ? '' : panel);
  };

  const toggleScan = () => {
    if (!scanActive) {
      if (!scanUrl || scanUrl === 'https://') {
        alert('Please enter a valid URL');
        return;
      }
      setScanProgress(0);
      setScanActive(true);
      setThreatLevel('none');
      
      // Simulate progress
      const interval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval);
            setScanActive(false);
            return 100;
          }
          
          // Simulate finding threats as scan progresses
          if (prev > 25 && prev < 30 && threatLevel === 'none') {
            setThreatLevel('low');
          } else if (prev > 50 && prev < 55 && threatLevel === 'low') {
            setThreatLevel('medium');
          } else if (prev > 75 && prev < 80 && threatLevel === 'medium') {
            setThreatLevel('high');
          } else if (prev > 90 && prev < 95 && threatLevel === 'high') {
            setThreatLevel('critical');
          }
          
          return prev + 1;
        });
      }, 150);
    } else {
      setScanActive(false);
    }
  };

  const pauseScan = () => {
    setScanActive(false);
  };

  const stopScan = () => {
    setScanActive(false);
    setScanProgress(0);
    setThreatLevel('none');
  };

  return (
    <DashboardLayout>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main control panel */}
        <Card className="lg:col-span-2 bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
          <CardHeader>
            <CardTitle className="text-xl font-bold">Scan Control</CardTitle>
            <CardDescription>Configure and manage web application fuzzing</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="url" className="text-sm font-medium">Target URL</label>
              <div className="relative">
                <Input
                  id="url"
                  value={scanUrl}
                  onChange={(e) => setScanUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="pr-10 font-mono text-sm bg-background/80 border-white/10 placeholder:text-muted-foreground/50"
                />
                <Lock className="absolute right-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between">
                <label className="text-sm font-medium">Scan Mode</label>
                <span className="text-xs text-muted-foreground">Selected: {scanMode === 'active' ? 'Active Fuzzing' : scanMode === 'passive' ? 'Passive Scanning' : 'Mutation-Based'}</span>
              </div>
              <div className="grid grid-cols-3 gap-2">
                <Button
                  variant={scanMode === 'active' ? 'default' : 'outline'}
                  className={`px-3 py-2 text-sm ${scanMode === 'active' ? 'border-purple-500 shadow-sm shadow-purple-500/20' : ''}`}
                  onClick={() => setScanMode('active')}
                >
                  Active Fuzzing
                </Button>
                <Button
                  variant={scanMode === 'passive' ? 'default' : 'outline'}
                  className={`px-3 py-2 text-sm ${scanMode === 'passive' ? 'border-blue-500 shadow-sm shadow-blue-500/20' : ''}`}
                  onClick={() => setScanMode('passive')}
                >
                  Passive Scanning
                </Button>
                <Button
                  variant={scanMode === 'mutation' ? 'default' : 'outline'}
                  className={`px-3 py-2 text-sm ${scanMode === 'mutation' ? 'border-green-500 shadow-sm shadow-green-500/20' : ''}`}
                  onClick={() => setScanMode('mutation')}
                >
                  Mutation-Based
                </Button>
              </div>
            </div>

            {/* Advanced options panels */}
            <div className="space-y-2 pt-2">
              {/* Basic settings panel */}
              <div className="border border-white/10 rounded-md overflow-hidden transition-all duration-300">
                <div 
                  className="flex items-center justify-between p-3 bg-white/5 cursor-pointer hover:bg-white/10"
                  onClick={() => togglePanel('basic')}
                >
                  <span className="font-medium">Basic Settings</span>
                  {expandedPanel === 'basic' ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                </div>
                
                {expandedPanel === 'basic' && (
                  <div className="p-3 bg-black/20 space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-xs font-medium mb-1 block">Request Timeout (ms)</label>
                        <Input type="number" defaultValue="5000" className="bg-background/80 border-white/10 text-sm" />
                      </div>
                      <div>
                        <label className="text-xs font-medium mb-1 block">Threads</label>
                        <Input type="number" defaultValue="10" className="bg-background/80 border-white/10 text-sm" />
                      </div>
                    </div>
                    
                    <div>
                      <label className="text-xs font-medium mb-1 block">User Agent</label>
                      <Input defaultValue="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" className="bg-background/80 border-white/10 text-sm font-mono text-xs" />
                    </div>
                  </div>
                )}
              </div>
              
              {/* Authentication panel */}
              <div className="border border-white/10 rounded-md overflow-hidden">
                <div 
                  className="flex items-center justify-between p-3 bg-white/5 cursor-pointer hover:bg-white/10"
                  onClick={() => togglePanel('auth')}
                >
                  <span className="font-medium">Authentication</span>
                  {expandedPanel === 'auth' ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                </div>
                
                {expandedPanel === 'auth' && (
                  <div className="p-3 bg-black/20 space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-xs font-medium mb-1 block">Username</label>
                        <Input className="bg-background/80 border-white/10 text-sm" />
                      </div>
                      <div>
                        <label className="text-xs font-medium mb-1 block">Password</label>
                        <Input type="password" className="bg-background/80 border-white/10 text-sm" />
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <Button variant="outline" size="sm" className="text-xs">
                        Test Authentication
                      </Button>
                      <span className="text-xs text-muted-foreground">Not authenticated</span>
                    </div>
                  </div>
                )}
              </div>
              
              {/* Payloads panel */}
              <div className="border border-white/10 rounded-md overflow-hidden">
                <div 
                  className="flex items-center justify-between p-3 bg-white/5 cursor-pointer hover:bg-white/10"
                  onClick={() => togglePanel('payloads')}
                >
                  <span className="font-medium">Payloads & Attack Vectors</span>
                  {expandedPanel === 'payloads' ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                </div>
                
                {expandedPanel === 'payloads' && (
                  <div className="p-3 bg-black/20 space-y-3">
                    <div className="flex flex-wrap gap-2">
                      <Button variant="outline" size="sm" className="text-xs bg-purple-500/10 hover:bg-purple-500/20 border-purple-500/30">
                        SQL Injection
                      </Button>
                      <Button variant="outline" size="sm" className="text-xs bg-blue-500/10 hover:bg-blue-500/20 border-blue-500/30">
                        XSS
                      </Button>
                      <Button variant="outline" size="sm" className="text-xs bg-green-500/10 hover:bg-green-500/20 border-green-500/30">
                        CSRF
                      </Button>
                      <Button variant="outline" size="sm" className="text-xs bg-orange-500/10 hover:bg-orange-500/20 border-orange-500/30">
                        File Inclusion
                      </Button>
                      <Button variant="outline" size="sm" className="text-xs bg-red-500/10 hover:bg-red-500/20 border-red-500/30">
                        Command Injection
                      </Button>
                      <Button variant="outline" size="sm" className="text-xs">
                        + Add Custom
                      </Button>
                    </div>
                    
                    <div>
                      <label className="text-xs font-medium mb-1 block">Custom Payloads (one per line)</label>
                      <textarea className="w-full h-20 bg-background/80 border border-white/10 rounded-md p-2 text-xs font-mono" placeholder="Enter custom payloads here..."></textarea>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
          <CardFooter className="flex justify-between border-t border-white/10 p-4">
            <div className="text-sm text-muted-foreground">
              <AlertTriangle className="h-4 w-4 inline-block mr-1 text-yellow-500" />
              Use with caution on production systems
            </div>
            <div className="flex space-x-2">
              <Button
                variant="outline"
                className="bg-white/5 hover:bg-white/10 border-white/10"
                disabled={!scanActive}
                onClick={pauseScan}
              >
                <Pause className="h-4 w-4 mr-2" />
                Pause
              </Button>
              <Button
                variant="outline"
                className="bg-white/5 hover:bg-white/10 border-white/10"
                disabled={!scanActive && scanProgress === 0}
                onClick={stopScan}
              >
                <Square className="h-4 w-4 mr-2" />
                Stop
              </Button>
              <Button
                className={scanActive ? 'bg-red-500 hover:bg-red-600' : 'bg-emerald-500 hover:bg-emerald-600'}
                onClick={toggleScan}
              >
                {scanActive ? (
                  <>
                    <Square className="h-4 w-4 mr-2" />
                    Stop Scan
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Start Scan
                  </>
                )}
              </Button>
            </div>
          </CardFooter>
        </Card>

        {/* Scan status panel */}
        <Card className="bg-card/50 backdrop-blur-sm border-cyan-900/30 shadow-lg shadow-cyan-500/5">
          <CardHeader>
            <CardTitle className="text-xl font-bold">Scan Status</CardTitle>
            <CardDescription>Current operation progress</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Overall Progress</span>
                <span className="font-mono">{scanProgress}%</span>
              </div>
              <div className="relative h-3 w-full overflow-hidden rounded-full bg-gray-700/50">
                <div 
                  className="absolute inset-0 h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
            </div>

            <div className="space-y-4">
              <h4 className="text-sm font-medium">Real-time Stats</h4>
              
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-white/5 border border-white/10 rounded-md p-3">
                  <div className="text-xs text-muted-foreground mb-1">Requests Sent</div>
                  <div className="text-lg font-mono">
                    {scanActive ? Math.floor(scanProgress * 45) : 0}
                  </div>
                </div>
                
                <div className="bg-white/5 border border-white/10 rounded-md p-3">
                  <div className="text-xs text-muted-foreground mb-1">Payloads Tested</div>
                  <div className="text-lg font-mono">
                    {scanActive ? Math.floor(scanProgress * 8) : 0}
                  </div>
                </div>
                
                <div className="bg-white/5 border border-white/10 rounded-md p-3">
                  <div className="text-xs text-muted-foreground mb-1">Response Time</div>
                  <div className="text-lg font-mono">
                    {scanActive ? (150 + Math.floor(Math.random() * 250)) : 0} ms
                  </div>
                </div>
                
                <div className="bg-white/5 border border-white/10 rounded-md p-3">
                  <div className="text-xs text-muted-foreground mb-1">Findings</div>
                  <div className="text-lg font-mono">
                    {scanActive && scanProgress > 30 ? Math.floor(scanProgress / 20) : 0}
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-md overflow-hidden border border-white/10 h-64">
              <EnhancedScannerAnimation active={scanActive} threatLevel={threatLevel} />
            </div>

            <div>
              <h4 className="text-sm font-medium mb-2">Current Activity</h4>
              <div className="font-mono text-xs bg-black/30 border border-white/10 rounded-md p-3 h-24 overflow-auto">
                {scanActive && (
                  <>
                    <div className="text-green-400">[*] Initializing scan on {scanUrl}</div>
                    <div className="text-blue-400">[+] Loading payload dictionaries</div>
                    <div className="text-blue-400">[+] Setting up {scanMode} fuzzing mode</div>
                    {scanProgress > 20 && <div className="text-yellow-400">[!] Testing parameter 'id' for SQL injection</div>}
                    {scanProgress > 40 && <div className="text-yellow-400">[!] Testing parameter 'search' for XSS vulnerabilities</div>}
                    {scanProgress > 60 && <div className="text-red-400">[!] Potential SQL injection found in 'id' parameter</div>}
                    {scanProgress > 80 && <div className="text-yellow-400">[!] Testing authentication bypass techniques</div>}
                  </>
                )}
                {!scanActive && scanProgress === 0 && (
                  <div className="text-muted-foreground">Waiting to start scan...</div>
                )}
                {!scanActive && scanProgress === 100 && (
                  <>
                    <div className="text-green-400">[*] Scan completed on {scanUrl}</div>
                    <div className="text-blue-400">[+] Generating report</div>
                    <div className="text-yellow-400">[!] 5 potential vulnerabilities found</div>
                    <div className="text-green-400">[+] Report saved to reports/scan_20230915_001.json</div>
                  </>
                )}
              </div>
            </div>
          </CardContent>
          <CardFooter className="border-t border-white/10 p-4">
            <div className="w-full">
              <Button variant="outline" className="w-full bg-white/5 hover:bg-white/10 border-white/10">
                <Zap className="h-4 w-4 mr-2" />
                View Detailed Logs
              </Button>
            </div>
          </CardFooter>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default ScanControl;
