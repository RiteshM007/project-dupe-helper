
import React, { useState, useEffect, useRef } from 'react';
import { toast } from 'sonner';
import { 
  Play, Pause, StopCircle, AlertTriangle, FileText, Upload, PieChartIcon, BarChartIcon, 
  ActivityIcon, Globe, Target, List, ExternalLink, FileUp, Brain, Database, Terminal, 
  Eye, Save, ArrowUpRight, Filter, Settings as SettingsIcon, Download, Share2
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Checkbox } from "@/components/ui/checkbox";
import { PieChart, Pie, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';
import DashboardLayout from "@/components/layout/DashboardLayout";
import { ThreatLevelIndicator } from "@/components/dashboard/ThreatLevelIndicator";
import { EnhancedScannerAnimation } from "@/components/dashboard/EnhancedScannerAnimation";
import { Grid, GridItem } from "@/components/ui/grid";
import { WebFuzzer } from '@/backend/WebFuzzer';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { Link } from "react-router-dom";
import { fuzzerApi, mlApi } from "@/services/api";
import { useMutation } from "@tanstack/react-query";

const CHART_COLORS = {
  critical: '#ff2d55',
  high: '#ff9500',
  medium: '#ffcc00',
  low: '#34c759',
  info: '#0a84ff',
  malicious: '#ef4444',
  suspicious: '#f97316',
  safe: '#10b981'
};

const RADIAN = Math.PI / 180;
const renderCustomizedLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, index, name }: any) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text x={x} y={y} fill="white" textAnchor={x > cx ? 'start' : 'end'} dominantBaseline="central">
      {`${name}: ${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

const vulnerabilityTypes = [
  { id: 'xss', name: 'XSS (Cross-Site Scripting)', description: 'Tests for cross-site scripting vulnerabilities' },
  { id: 'sqli', name: 'SQL Injection', description: 'Tests for SQL injection vulnerabilities' },
  { id: 'lfi', name: 'Local File Inclusion', description: 'Tests for path traversal and file inclusion' },
  { id: 'rce', name: 'Remote Code Execution', description: 'Tests for command injection vulnerabilities' },
  { id: 'csrf', name: 'CSRF (Cross-Site Request Forgery)', description: 'Tests for CSRF vulnerabilities' },
  { id: 'auth', name: 'Authentication Bypass', description: 'Tests for authentication bypass methods' },
  { id: 'all', name: 'All Vulnerabilities', description: 'Tests for all vulnerability types' }
];

const payloadPresets = {
  xss: [
    '<script>alert(1)</script>',
    '<img src="x" onerror="alert(1)">',
    '<svg onload="alert(1)">',
    'javascript:alert(1)',
    '"><script>alert(1)</script>',
    '"-confirm(1)-"',
    '<body onload="alert(1)">',
    '<iframe src="javascript:alert(1)">',
    '<details open ontoggle="alert(1)">',
    '<video><source onerror="alert(1)">'
  ],
  sqli: [
    "' OR 1=1 --",
    "admin' --",
    "' UNION SELECT 1,2,3 --",
    "1' ORDER BY 10 --",
    "1'; DROP TABLE users --",
    "' OR '1'='1",
    "' AND 1=0 UNION SELECT null, table_name FROM information_schema.tables --",
    "1' AND '1'='1",
    "1' AND '1'='0",
    "'; WAITFOR DELAY '0:0:5' --"
  ],
  lfi: [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "/etc/passwd",
    "../../../../../../../../etc/passwd",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "data:text/plain,<?php echo shell_exec($_GET['cmd']);?>",
    "file://etc/passwd",
    "/var/www/html/config.php"
  ],
  rce: [
    "; ls -la",
    "& ping -c 3 127.0.0.1",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
    "`cat /etc/passwd`",
    "|| dir",
    "&& ls -la",
    "; cat /etc/passwd ; ls -la",
    "| net user",
    "$(sleep 5)"
  ]
};

const Fuzzer = () => {
  const [isDVWAConnected, setIsDVWAConnected] = useState(false);
  const [dvwaUrl, setDvwaUrl] = useState("");
  const [dvwaUsername, setDvwaUsername] = useState("admin");
  const [dvwaPassword, setDvwaPassword] = useState("password");
  const [isConnecting, setIsConnecting] = useState(false);
  const [showLoginDialog, setShowLoginDialog] = useState(false);
  
  const [targetUrl, setTargetUrl] = useState('http://localhost/dvwa/vulnerabilities/xss_r/');
  const [wordlistFile, setWordlistFile] = useState('wordlists/xss-payloads.txt');
  const [selectedVulnerabilities, setSelectedVulnerabilities] = useState<string[]>(['xss']);
  const [scanActive, setScanActive] = useState(false);
  const [scanPaused, setScanPaused] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [payloadsProcessed, setPayloadsProcessed] = useState(0);
  const [totalPayloads, setTotalPayloads] = useState(0);
  
  const [logs, setLogs] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const [dataset, setDataset] = useState<any[]>([]);
  const [fuzzer, setFuzzer] = useState<WebFuzzer | null>(null);
  const [activeTab, setActiveTab] = useState("logs");
  const [securityLevel, setSecurityLevel] = useState("low");
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [exportFormat, setExportFormat] = useState("json");
  const [exportContent, setExportContent] = useState("");
  const [customPayloads, setCustomPayloads] = useState<string[]>([]);
  const [customPayloadsText, setCustomPayloadsText] = useState("");
  const [showUploadDialog, setShowUploadDialog] = useState(false);
  const [showPayloadDialog, setShowPayloadDialog] = useState(false);
  const [selectedPayloadPreset, setSelectedPayloadPreset] = useState<string | null>(null);
  const [showSettingsDialog, setShowSettingsDialog] = useState(false);
  const [advancedSettings, setAdvancedSettings] = useState({
    requestTimeout: 5000,
    requestDelay: 100,
    maxRequests: 1000,
    followRedirects: true,
    detectBodyChanges: true,
    detectAlerts: true,
    detectErrors: true,
    saveResponses: false,
    useML: true
  });
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [modelTrained, setModelTrained] = useState(false);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const statusIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Set up API mutations
  const createFuzzerMutation = useMutation({
    mutationFn: (data: { targetUrl: string, wordlistFile: string }) => 
      fuzzerApi.createFuzzer(data.targetUrl, data.wordlistFile),
    onSuccess: (data) => {
      setSessionId(data.session_id);
      toast.success("Fuzzer created successfully");
    },
    onError: (error) => {
      toast.error(`Failed to create fuzzer: ${error}`);
    }
  });

  const startFuzzingMutation = useMutation({
    mutationFn: (data: { sessionId: string, vulnerabilityTypes: string[], customPayloads: string[] }) => 
      fuzzerApi.startFuzzing(data.sessionId, data.vulnerabilityTypes, data.customPayloads),
    onSuccess: () => {
      setScanActive(true);
      setScanPaused(false);
      toast.success("Fuzzing started successfully");
      startStatusPolling();
    },
    onError: (error) => {
      toast.error(`Failed to start fuzzing: ${error}`);
    }
  });

  const stopFuzzingMutation = useMutation({
    mutationFn: (sessionId: string) => fuzzerApi.stopFuzzing(sessionId),
    onSuccess: () => {
      setScanActive(false);
      setScanPaused(false);
      toast.success("Fuzzing stopped successfully");
      stopStatusPolling();
    },
    onError: (error) => {
      toast.error(`Failed to stop fuzzing: ${error}`);
    }
  });

  const saveResultsMutation = useMutation({
    mutationFn: (data: { sessionId: string, results: any[] }) => 
      fuzzerApi.saveResults(data.sessionId, data.results),
    onSuccess: (data) => {
      toast.success(`Results saved to ${data.file_path}`);
    },
    onError: (error) => {
      toast.error(`Failed to save results: ${error}`);
    }
  });

  const trainModelsMutation = useMutation({
    mutationFn: (dataset: any[]) => mlApi.trainModels(dataset),
    onSuccess: (data) => {
      setModelTrained(true);
      toast.success("Models trained successfully");
    },
    onError: (error) => {
      toast.error(`Failed to train models: ${error}`);
    }
  });

  useEffect(() => {
    const newFuzzer = new WebFuzzer(targetUrl, wordlistFile);
    setFuzzer(newFuzzer);
    
    // Create fuzzer on server
    if (targetUrl) {
      createFuzzerMutation.mutate({ targetUrl, wordlistFile });
    }
    
    return () => {
      // Clean up interval on unmount
      if (statusIntervalRef.current) {
        clearInterval(statusIntervalRef.current);
      }
    };
  }, [targetUrl, wordlistFile]);

  const startStatusPolling = () => {
    if (statusIntervalRef.current) {
      clearInterval(statusIntervalRef.current);
    }
    
    if (sessionId) {
      statusIntervalRef.current = setInterval(async () => {
        try {
          const status = await fuzzerApi.getFuzzerStatus(sessionId);
          
          if (status.success) {
            setScanActive(status.active);
            setScanProgress(status.progress);
            setPayloadsProcessed(status.payloads_processed);
            setTotalPayloads(status.total_payloads);
            
            if (status.logs && status.logs.length > 0) {
              setLogs(prevLogs => {
                const newLogs = [...prevLogs];
                for (const log of status.logs) {
                  if (!newLogs.some(existingLog => 
                    existingLog.timestamp === log.timestamp && existingLog.message === log.message
                  )) {
                    newLogs.push(log);
                  }
                }
                return newLogs;
              });
            }
            
            if (status.reports && status.reports.length > 0) {
              setReports(prevReports => {
                const newReports = [...prevReports];
                for (const report of status.reports) {
                  if (!newReports.some(existingReport => 
                    existingReport.timestamp === report.timestamp && existingReport.data === report.data
                  )) {
                    newReports.push(report);
                  }
                }
                return newReports;
              });
            }
            
            // If scan has completed, get the full dataset
            if (!status.active && status.progress === 100) {
              const datasetResponse = await fuzzerApi.getDataset(sessionId);
              if (datasetResponse.success && datasetResponse.dataset) {
                setDataset(datasetResponse.dataset);
                
                // Stop polling if we have the data
                stopStatusPolling();
                
                toast.success("Fuzzing completed successfully");
              }
            }
          }
        } catch (error) {
          console.error("Error polling fuzzer status:", error);
        }
      }, 2000);
    }
  };

  const stopStatusPolling = () => {
    if (statusIntervalRef.current) {
      clearInterval(statusIntervalRef.current);
      statusIntervalRef.current = null;
    }
  };

  const handleDVWAConnect = async () => {
    if (!dvwaUrl) {
      toast.error("DVWA URL is required");
      return;
    }

    setIsConnecting(true);

    try {
      if (fuzzer) {
        const result = await fuzzer.connectToDVWA(
          dvwaUrl,
          dvwaUsername,
          dvwaPassword,
          securityLevel
        );

        if (result.success) {
          setIsDVWAConnected(true);
          toast.success("Connected to DVWA successfully");
          setTargetUrl(`${dvwaUrl}/vulnerabilities/xss_r/`);
          setShowLoginDialog(false);
        } else {
          toast.error("Failed to connect to DVWA");
        }
      }
    } catch (error) {
      toast.error(`Connection error: ${error}`);
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDVWADisconnect = () => {
    setIsDVWAConnected(false);
    toast.info("Disconnected from DVWA");
  };

  const handleOpenDVWA = () => {
    if (fuzzer && isDVWAConnected) {
      const opened = fuzzer.openDVWAInNewTab();
      if (!opened) {
        toast.error("Failed to open DVWA. Please check if pop-up blocker is enabled.");
      }
    } else {
      setShowLoginDialog(true);
    }
  };

  const handleOpenVulnerabilityPage = (vulnerabilityType: string) => {
    if (fuzzer && isDVWAConnected) {
      const opened = fuzzer.openVulnerabilityPage(vulnerabilityType);
      if (!opened) {
        toast.error("Failed to open vulnerability page. Please check if pop-up blocker is enabled.");
      }
    } else {
      toast.error("Connect to DVWA first");
      setShowLoginDialog(true);
    }
  };

  const handleStartFuzzing = async () => {
    if (!sessionId) {
      toast.error("No active session. Please refresh the page and try again.");
      return;
    }
    
    try {
      await startFuzzingMutation.mutate({
        sessionId,
        vulnerabilityTypes: selectedVulnerabilities,
        customPayloads
      });
      
      if (fuzzer) {
        fuzzer.logActivity("Starting fuzzing process...");
      }
    } catch (error) {
      toast.error(`Fuzzing error: ${error}`);
    }
  };

  const handlePauseFuzzing = () => {
    setScanPaused(!scanPaused);
    
    if (fuzzer) {
      fuzzer.logActivity(scanPaused ? "Fuzzing resumed" : "Fuzzing paused");
    }
    
    toast.info(scanPaused ? "Fuzzing resumed" : "Fuzzing paused");
  };

  const handleStopFuzzing = () => {
    if (!sessionId) {
      toast.error("No active session to stop");
      return;
    }
    
    stopFuzzingMutation.mutate(sessionId);
    
    if (fuzzer) {
      fuzzer.logActivity("Fuzzing stopped");
    }
  };

  const handleVulnerabilityChange = (vulnerabilityId: string) => {
    if (vulnerabilityId === 'all') {
      setSelectedVulnerabilities(['all']);
    } else {
      const newSelection = selectedVulnerabilities.filter(v => v !== 'all');
      
      if (newSelection.includes(vulnerabilityId)) {
        setSelectedVulnerabilities(newSelection.filter(v => v !== vulnerabilityId));
      } else {
        setSelectedVulnerabilities([...newSelection, vulnerabilityId]);
      }
    }
  };

  const calculateSeverityCounts = () => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    dataset.forEach(item => {
      if (item.severity) {
        counts[item.severity as keyof typeof counts]++;
      }
    });
    
    return Object.entries(counts).map(([key, value]) => ({
      name: key.charAt(0).toUpperCase() + key.slice(1),
      value
    }));
  };

  const calculateVulnerabilityTypeCounts = () => {
    const counts: Record<string, number> = {};
    
    dataset.forEach(item => {
      if (item.vulnerability_type) {
        counts[item.vulnerability_type] = (counts[item.vulnerability_type] || 0) + 1;
      }
    });
    
    return Object.entries(counts).map(([key, value]) => ({
      name: key.toUpperCase(),
      count: value
    }));
  };

  const calculateLabelCounts = () => {
    const counts = {
      malicious: 0,
      suspicious: 0,
      safe: 0
    };
    
    dataset.forEach(item => {
      if (item.label) {
        counts[item.label as keyof typeof counts]++;
      }
    });
    
    return Object.entries(counts).map(([key, value]) => ({
      name: key.charAt(0).toUpperCase() + key.slice(1),
      value
    }));
  };

  const generateExportContent = () => {
    switch (activeTab) {
      case "logs":
        return exportFormat === "json" 
          ? JSON.stringify(logs, null, 2) 
          : logs.map(log => `[${log.timestamp}] ${log.message}`).join('\n');
      case "reports":
        return exportFormat === "json" 
          ? JSON.stringify(reports, null, 2) 
          : reports.map(report => report.data).join('\n\n');
      case "results":
        return exportFormat === "json" 
          ? JSON.stringify(dataset, null, 2) 
          : dataset.map(item => {
              return `Payload: ${item.payload}\nSeverity: ${item.severity}\nLabel: ${item.label}\nVulnerability Type: ${item.vulnerability_type}\nTimestamp: ${item.timestamp}`;
            }).join('\n\n');
      case "analytics":
        return exportFormat === "json"
          ? JSON.stringify({
              severity: calculateSeverityCounts(),
              vulnerabilityTypes: calculateVulnerabilityTypeCounts(),
              labels: calculateLabelCounts()
            }, null, 2)
          : `Severity Distribution:\n${calculateSeverityCounts().map(item => `${item.name}: ${item.value}`).join('\n')}\n\nVulnerability Types:\n${calculateVulnerabilityTypeCounts().map(item => `${item.name}: ${item.count}`).join('\n')}\n\nLabels Distribution:\n${calculateLabelCounts().map(item => `${item.name}: ${item.value}`).join('\n')}`;
      default:
        return "";
    }
  };

  const handleShowExportDialog = () => {
    const content = generateExportContent();
    setExportContent(content);
    setShowExportDialog(true);
  };

  const handleExportData = () => {
    const content = exportContent;
    if (!content || content.trim() === "") {
      toast.error("No content to export");
      return;
    }

    const blob = new Blob([content], { type: exportFormat === "json" ? "application/json" : "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fuzzer-${activeTab}-${new Date().toISOString().split('T')[0]}.${exportFormat === "json" ? "json" : "txt"}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setShowExportDialog(false);
    toast.success(`${activeTab.charAt(0).toUpperCase() + activeTab.slice(1)} exported successfully`);
    
    // Also save to server if this is the results tab
    if (activeTab === "results" && sessionId) {
      saveResultsMutation.mutate({
        sessionId,
        results: dataset
      });
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const content = event.target?.result as string;
        const payloads = content.split('\n')
          .map(line => line.trim())
          .filter(line => line.length > 0 && !line.startsWith('#'));
        
        setCustomPayloads(payloads);
        setCustomPayloadsText(payloads.join('\n'));
        toast.success(`Loaded ${payloads.length} custom payloads successfully`);
        
        if (fuzzer) {
          fuzzer.logActivity(`Loaded ${payloads.length} custom payloads from file: ${file.name}`);
        }
        setShowUploadDialog(false);
      } catch (error) {
        toast.error(`Failed to parse payload file: ${error}`);
      }
    };
    
    reader.onerror = () => {
      toast.error("Error reading payload file");
    };
    
    reader.readAsText(file);
  };

  const handleSaveCustomPayloads = () => {
    if (customPayloadsText.trim() === "") {
      toast.error("No payloads to save");
      return;
    }
    
    const payloads = customPayloadsText.split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#'));
    
    setCustomPayloads(payloads);
    toast.success(`Saved ${payloads.length} custom payloads`);
    setShowPayloadDialog(false);
    
    if (fuzzer) {
      fuzzer.logActivity(`Added ${payloads.length} custom payloads from editor`);
    }
  };

  const handleApplyPayloadPreset = (presetType: string) => {
    if (!payloadPresets[presetType as keyof typeof payloadPresets]) {
      toast.error("Invalid preset type");
      return;
    }
    
    const presetPayloads = payloadPresets[presetType as keyof typeof payloadPresets];
    setCustomPayloadsText(presetPayloads.join('\n'));
    setSelectedPayloadPreset(presetType);
    
    toast.success(`Applied ${presetType.toUpperCase()} payload preset with ${presetPayloads.length} payloads`);
  };

  const handleApplyCustomPayloads = () => {
    if (!fuzzer || customPayloads.length === 0) return;
    
    fuzzer.wordlist = [...fuzzer.wordlist, ...customPayloads];
    fuzzer.totalPayloads = fuzzer.wordlist.length;
    fuzzer.logActivity(`Added ${customPayloads.length} custom payloads. Total payloads: ${fuzzer.totalPayloads}`);
    toast.success(`Added ${customPayloads.length} custom payloads to fuzzer`);
  };

  const handleSaveSettings = () => {
    if (fuzzer) {
      fuzzer.requestTimeout = advancedSettings.requestTimeout;
      fuzzer.requestDelay = advancedSettings.requestDelay;
      fuzzer.maxRequests = advancedSettings.maxRequests;
      fuzzer.followRedirects = advancedSettings.followRedirects;
      fuzzer.detectBodyChanges = advancedSettings.detectBodyChanges;
      fuzzer.detectAlerts = advancedSettings.detectAlerts;
      fuzzer.detectErrors = advancedSettings.detectErrors;
      fuzzer.saveResponses = advancedSettings.saveResponses;
      fuzzer.useML = advancedSettings.useML;
      
      fuzzer.logActivity("Updated fuzzer settings");
      toast.success("Settings saved successfully");
    }
    
    setShowSettingsDialog(false);
  };

  const handleTrainModels = () => {
    if (dataset.length === 0) {
      toast.error("No dataset available. Please run a fuzzing scan first.");
      return;
    }
    
    trainModelsMutation.mutate(dataset);
    
    if (fuzzer) {
      fuzzer.logActivity("Training machine learning models on collected dataset");
    }
  };

  const handleAnalyzeData = () => {
    if (dataset.length === 0) {
      toast.error("No dataset available. Please run a fuzzing scan first.");
      return;
    }
    
    // Navigate to ML Analysis page
    window.location.href = "/ml-analysis";
  };

  const severityData = calculateSeverityCounts();
  const vulnerabilityTypeData = calculateVulnerabilityTypeCounts();
  const labelData = calculateLabelCounts();

  const activityLogs = logs.filter(log => log.type === "activity");

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Web Fuzzer</h1>
            <p className="text-muted-foreground">
              Test web applications for security vulnerabilities through fuzzing.
            </p>
          </div>
          
          <div className="flex flex-col sm:flex-row gap-2">
            <Card className="w-full md:w-auto bg-card/50 backdrop-blur-sm border-indigo-900/30">
              <CardHeader className="py-3 px-4">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium">DVWA Connection</CardTitle>
                  {isDVWAConnected && (
                    <Badge className="bg-green-500/80 text-white px-2 py-0.5 text-xs flex items-center gap-1">
                      <div className="h-2 w-2 rounded-full bg-green-200 animate-pulse"></div>
                      Connected
                    </Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="py-2 px-4">
                {!isDVWAConnected ? (
                  <div className="flex gap-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      onClick={() => setShowLoginDialog(true)}
                      className="h-8 w-full"
                    >
                      Connect to DVWA
                    </Button>
                  </div>
                ) : (
                  <div className="flex items-center justify-between">
                    <div className="text-xs font-mono truncate max-w-[150px]">{dvwaUrl}</div>
                    <div className="flex gap-2">
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={handleOpenDVWA}
                        className="h-7 text-xs flex items-center gap-1"
                      >
                        <ExternalLink className="h-3 w-3" /> Open
                      </Button>
                      <Button 
                        size="sm" 
                        variant="destructive"
                        onClick={handleDVWADisconnect}
                        className="h-7 text-xs"
                      >
                        Disconnect
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
            
            <Link to="/ml-analysis">
              <Button variant="outline" className="flex items-center gap-2 h-full">
                <Brain className="h-4 w-4" />
                Machine Learning Analysis
                <ArrowUpRight className="h-3 w-3" />
              </Button>
            </Link>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-7 gap-6">
          <Card className="lg:col-span-2 bg-card/50 backdrop-blur-sm border-indigo-900/30">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Fuzzing Configuration</CardTitle>
                <Button 
                  variant="ghost" 
                  size="icon"
                  onClick={() => setShowSettingsDialog(true)}
                  className="h-8 w-8"
                >
                  <SettingsIcon className="h-4 w-4" />
                </Button>
              </div>
              <CardDescription>Configure target and fuzzing options</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="targetUrl">
                  Target URL
                </label>
                <Input
                  id="targetUrl"
                  placeholder="http://example.com/vulnerable-page"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>
              
              {isDVWAConnected && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">
                    DVWA Security Level
                  </label>
                  <Select 
                    value={securityLevel}
                    onValueChange={setSecurityLevel}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Security Level" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="impossible">Impossible</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
              
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  Vulnerability Types to Test
                </label>
                <div className="space-y-2 border p-2 rounded-md max-h-60 overflow-auto">
                  {vulnerabilityTypes.map((type) => (
                    <div key={type.id} className="flex items-start space-x-2">
                      <Checkbox 
                        id={`vuln-${type.id}`} 
                        checked={selectedVulnerabilities.includes(type.id)}
                        onCheckedChange={() => handleVulnerabilityChange(type.id)}
                      />
                      <div className="space-y-0.5">
                        <label htmlFor={`vuln-${type.id}`} className="text-sm font-medium cursor-pointer">
                          {type.name}
                        </label>
                        <p className="text-xs text-muted-foreground">
                          {type.description}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              
              {isDVWAConnected && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">
                    Quick Launch Pages
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {vulnerabilityTypes.map((type) => (
                      type.id !== 'all' && (
                        <Button 
                          key={`launch-${type.id}`}
                          size="sm" 
                          variant="outline"
                          className="h-7 text-xs"
                          onClick={() => handleOpenVulnerabilityPage(type.id)}
                        >
                          {type.id.toUpperCase()}
                        </Button>
                      )
                    ))}
                  </div>
                </div>
              )}
              
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium">Custom Payloads</label>
                  <div className="flex space-x-2">
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => setShowUploadDialog(true)}
                      className="h-8 text-xs"
                    >
                      <Upload className="h-3 w-3 mr-1" /> Upload
                    </Button>
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => setShowPayloadDialog(true)}
                      className="h-8 text-xs"
                    >
                      <Eye className="h-3 w-3 mr-1" /> Edit
                    </Button>
                  </div>
                </div>
                {customPayloads.length > 0 && (
                  <div className="bg-muted/40 p-2 rounded-md text-xs">
                    <div className="font-medium mb-1">Loaded {customPayloads.length} custom payloads</div>
                    <ScrollArea className="h-20">
                      <div className="font-mono text-xs space-y-1">
                        {customPayloads.slice(0, 5).map((payload, i) => (
                          <div key={i} className="truncate">{payload}</div>
                        ))}
                        {customPayloads.length > 5 && (
                          <div className="text-muted-foreground">...and {customPayloads.length - 5} more</div>
                        )}
                      </div>
                    </ScrollArea>
                    
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={handleApplyCustomPayloads}
                      className="w-full mt-2 h-7 text-xs"
                    >
                      Apply Payloads
                    </Button>
                  </div>
                )}
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium">Machine Learning</label>
                  <Badge 
                    variant={modelTrained ? "default" : "outline"}
                    className={modelTrained ? "bg-green-500" : ""}
                  >
                    {modelTrained ? "Trained" : "Not Trained"}
                  </Badge>
                </div>
                
                <div className="flex gap-2">
                  <Button 
                    variant="outline" 
                    size="sm"
                    className="flex-1 h-8 text-xs"
                    disabled={dataset.length === 0}
                    onClick={handleTrainModels}
                  >
                    <Brain className="h-3 w-3 mr-1" /> Train Models
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    size="sm"
                    className="flex-1 h-8 text-xs"
                    disabled={dataset.length === 0}
                    onClick={handleAnalyzeData}
                  >
                    <Database className="h-3 w-3 mr-1" /> Analyze Data
                  </Button>
                </div>
              </div>
            </CardContent>
            <CardFooter className="flex flex-col gap-2">
              <div className="flex gap-2 w-full">
                <Button 
                  className="flex-1" 
                  onClick={handleStartFuzzing}
                  disabled={scanActive || !sessionId}
                >
                  <Play className="mr-1 h-4 w-4" /> Start
                </Button>
                
                <Button 
                  className="flex-1" 
                  variant="outline" 
                  onClick={handlePauseFuzzing}
                  disabled={!scanActive || !sessionId}
                >
                  {scanPaused ? (
                    <>
                      <Play className="mr-1 h-4 w-4" /> Resume
                    </>
                  ) : (
                    <>
                      <Pause className="mr-1 h-4 w-4" /> Pause
                    </>
                  )}
                </Button>
                
                <Button 
                  className="flex-1" 
                  variant="destructive" 
                  onClick={handleStopFuzzing}
                  disabled={!scanActive || !sessionId}
                >
                  <StopCircle className="mr-1 h-4 w-4" /> Stop
                </Button>
              </div>
              
              {scanActive && (
                <div className="w-full space-y-1 mt-2">
                  <div className="flex justify-between text-xs">
                    <span>Progress</span>
                    <span>{scanProgress.toFixed(1)}%</span>
                  </div>
                  <Progress value={scanProgress} className="h-2" />
                  <div className="text-xs text-right text-muted-foreground">
                    {payloadsProcessed} / {totalPayloads} payloads processed
                  </div>
                </div>
              )}
            </CardFooter>
          </Card>
          
          <Card className="lg:col-span-5 bg-card/50 backdrop-blur-sm border-indigo-900/30 flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex justify-between items-center">
                <CardTitle>Fuzzing Results</CardTitle>
                <div className="flex gap-2">
                  <Button 
                    variant="outline" 
                    size="sm" 
                    disabled={dataset.length === 0}
                    onClick={handleShowExportDialog}
                  >
                    <FileUp className="h-4 w-4 mr-1" /> Export
                  </Button>
                  <Link to="/ml-analysis">
                    <Button 
                      variant="default" 
                      size="sm"
                      disabled={dataset.length === 0}
                    >
                      <Brain className="h-4 w-4 mr-1" /> ML Analysis
                    </Button>
                  </Link>
                </div>
              </div>
              
              <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                <TabsList className="grid grid-cols-4 mb-2">
                  <TabsTrigger value="logs">Activity Logs</TabsTrigger>
                  <TabsTrigger value="reports">Reports</TabsTrigger>
                  <TabsTrigger value="results">Results</TabsTrigger>
                  <TabsTrigger value="analytics">Analytics</TabsTrigger>
                </TabsList>
                
                <TabsContent value="logs" className="flex-1 overflow-hidden h-full mt-0">
                  <ScrollArea className="flex-1 border rounded-md h-[40vh]">
                    <div className="p-4 space-y-2 font-mono text-sm">
                      {activityLogs.length > 0 ? (
                        activityLogs.map((log, index) => (
                          <div key={index} className="flex">
                            <span className="text-muted-foreground mr-2">
                              [{new Date(log.timestamp).toLocaleTimeString()}]
                            </span>
                            <span>{log.message}</span>
                          </div>
                        ))
                      ) : (
                        <div className="text-muted-foreground text-center py-8">
                          No logs to display. Start the fuzzer to generate logs.
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </TabsContent>
                
                <TabsContent value="reports" className="flex-1 overflow-hidden h-full mt-0">
                  <ScrollArea className="flex-1 border rounded-md h-[40vh]">
                    <div className="p-4 space-y-4">
                      {reports.length > 0 ? (
                        reports.map((report, index) => (
                          <div key={index} className="bg-muted p-3 rounded-md font-mono text-xs whitespace-pre-wrap">
                            {report.data}
                          </div>
                        ))
                      ) : (
                        <div className="text-muted-foreground text-center py-8">
                          No reports to display. Start the fuzzer to generate reports.
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </TabsContent>
                
                <TabsContent value="results" className="flex-1 overflow-hidden h-full mt-0">
                  <ScrollArea className="flex-1 border rounded-md h-[40vh]">
                    <div className="p-4">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Payload</TableHead>
                            <TableHead>Type</TableHead>
                            <TableHead>Severity</TableHead>
                            <TableHead>Status</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {dataset.length > 0 ? (
                            dataset.map((item, index) => (
                              <TableRow key={index} className="hover:bg-muted/50">
                                <TableCell className="font-mono text-xs truncate max-w-[200px]">
                                  {item.payload}
                                </TableCell>
                                <TableCell>
                                  {item.vulnerability_type || "unknown"}
                                </TableCell>
                                <TableCell>
                                  <Badge 
                                    variant="outline" 
                                    className={`
                                      ${item.severity === 'critical' && 'border-red-500 text-red-500'}
                                      ${item.severity === 'high' && 'border-orange-500 text-orange-500'}
                                      ${item.severity === 'medium' && 'border-yellow-500 text-yellow-500'}
                                      ${item.severity === 'low' && 'border-green-500 text-green-500'}
                                      ${item.severity === 'info' && 'border-blue-500 text-blue-500'}
                                    `}
                                  >
                                    {item.severity || "unknown"}
                                  </Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge 
                                    variant="outline" 
                                    className={`
                                      ${item.label === 'malicious' && 'border-red-500 bg-red-500/10'}
                                      ${item.label === 'suspicious' && 'border-yellow-500 bg-yellow-500/10'}
                                      ${item.label === 'safe' && 'border-green-500 bg-green-500/10'}
                                    `}
                                  >
                                    {item.label}
                                  </Badge>
                                </TableCell>
                              </TableRow>
                            ))
                          ) : (
                            <TableRow>
                              <TableCell colSpan={4} className="text-center text-muted-foreground py-8">
                                No results to display. Start the fuzzer to generate results.
                              </TableCell>
                            </TableRow>
                          )}
                        </TableBody>
                      </Table>
                    </div>
                  </ScrollArea>
                </TabsContent>
                
                <TabsContent value="analytics" className="flex-1 overflow-hidden h-full mt-0">
                  {dataset.length > 0 ? (
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-[40vh]">
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-2">Severity Distribution</h3>
                        <ResponsiveContainer width="100%" height={250}>
                          <PieChart>
                            <Pie
                              data={severityData}
                              cx="50%"
                              cy="50%"
                              labelLine={false}
                              outerRadius={80}
                              fill="#8884d8"
                              dataKey="value"
                              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                            >
                              {severityData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={CHART_COLORS[entry.name.toLowerCase() as keyof typeof CHART_COLORS]} />
                              ))}
                            </Pie>
                            <Tooltip />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                      
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-2">Vulnerability Types</h3>
                        <ResponsiveContainer width="100%" height={250}>
                          <BarChart
                            data={vulnerabilityTypeData}
                            margin={{
                              top: 5,
                              right: 30,
                              left: 20,
                              bottom: 5,
                            }}
                          >
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Bar dataKey="count" fill="#8884d8">
                              {vulnerabilityTypeData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={Object.values(CHART_COLORS)[index % Object.values(CHART_COLORS).length]} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                      
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-2">Classification Labels</h3>
                        <ResponsiveContainer width="100%" height={250}>
                          <PieChart>
                            <Pie
                              data={labelData}
                              cx="50%"
                              cy="50%"
                              labelLine={false}
                              outerRadius={80}
                              fill="#8884d8"
                              dataKey="value"
                              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                            >
                              {labelData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={CHART_COLORS[entry.name.toLowerCase() as keyof typeof CHART_COLORS]} />
                              ))}
                            </Pie>
                            <Tooltip />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  ) : (
                    <div className="text-muted-foreground text-center py-8 border rounded-md h-[40vh] flex items-center justify-center">
                      <div>
                        <AlertTriangle className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-20" />
                        <p>No data available for analysis. Start the fuzzer to generate data.</p>
                      </div>
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </CardHeader>
          </Card>
        </div>

        <Card className="bg-card/50 backdrop-blur-sm border-indigo-900/30">
          <CardHeader>
            <CardTitle>Real-time Scanning Visualization</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] rounded-md overflow-hidden border border-muted">
              <EnhancedScannerAnimation 
                active={scanActive} 
                threatLevel={
                  dataset.some(item => item.severity === 'critical') ? 'critical' :
                  dataset.some(item => item.severity === 'high') ? 'high' :
                  dataset.some(item => item.severity === 'medium') ? 'medium' :
                  dataset.some(item => item.severity === 'low') ? 'low' : 
                  'none'
                }
              />
            </div>
          </CardContent>
        </Card>

        <Dialog open={showLoginDialog} onOpenChange={setShowLoginDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Connect to DVWA</DialogTitle>
              <DialogDescription>
                Enter the URL and credentials for your DVWA instance
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <label className="text-sm font-medium">DVWA URL</label>
                <Input 
                  placeholder="http://localhost/dvwa" 
                  value={dvwaUrl}
                  onChange={(e) => setDvwaUrl(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Username</label>
                <Input 
                  placeholder="admin" 
                  value={dvwaUsername}
                  onChange={(e) => setDvwaUsername(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Password</label>
                <Input 
                  type="password" 
                  placeholder="password" 
                  value={dvwaPassword}
                  onChange={(e) => setDvwaPassword(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Security Level</label>
                <Select 
                  value={securityLevel}
                  onValueChange={setSecurityLevel}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Security Level" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="impossible">Impossible</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowLoginDialog(false)}>Cancel</Button>
              <Button onClick={handleDVWAConnect} disabled={isConnecting}>
                {isConnecting ? "Connecting..." : "Connect"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog open={showExportDialog} onOpenChange={setShowExportDialog}>
          <DialogContent className="sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>Export {activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}</DialogTitle>
              <DialogDescription>
                Export your fuzzing data in the selected format.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <div className="grid grid-cols-2 gap-2">
                  <label className="flex items-center space-x-2">
                    <input 
                      type="radio" 
                      checked={exportFormat === "json"} 
                      onChange={() => setExportFormat("json")}
                      className="h-4 w-4"
                    />
                    <span>JSON</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input 
                      type="radio" 
                      checked={exportFormat === "text"} 
                      onChange={() => setExportFormat("text")}
                      className="h-4 w-4"
                    />
                    <span>Text</span>
                  </label>
                </div>
              </div>
              
              <ScrollArea className="h-[300px] border rounded-md p-2">
                <pre className="text-xs font-mono whitespace-pre-wrap">{exportContent}</pre>
              </ScrollArea>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowExportDialog(false)}>Cancel</Button>
              <Button onClick={handleExportData}>Export</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog open={showUploadDialog} onOpenChange={setShowUploadDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Upload Custom Payloads</DialogTitle>
              <DialogDescription>
                Upload a text file containing custom payloads (one per line)
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="flex flex-col items-center justify-center border-2 border-dashed rounded-md p-6 cursor-pointer"
                   onClick={() => fileInputRef.current?.click()}>
                <Upload className="h-8 w-8 text-muted-foreground mb-2" />
                <p className="text-sm text-center text-muted-foreground">
                  Click to select a file or drag and drop
                </p>
                <p className="text-xs text-center text-muted-foreground mt-1">
                  Supported format: .txt
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".txt"
                  className="hidden"
                  onChange={handleFileUpload}
                />
              </div>
              
              <div className="text-sm bg-muted/40 p-3 rounded-md">
                <p className="font-medium mb-1">Format requirements:</p>
                <ul className="list-disc pl-5 text-xs space-y-1">
                  <li>One payload per line</li>
                  <li>Empty lines will be ignored</li>
                  <li>Lines starting with # will be treated as comments</li>
                </ul>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowUploadDialog(false)}>Cancel</Button>
              <Button onClick={() => fileInputRef.current?.click()}>Select File</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        
        <Dialog open={showPayloadDialog} onOpenChange={setShowPayloadDialog}>
          <DialogContent className="sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>Custom Payloads Editor</DialogTitle>
              <DialogDescription>
                Create or edit custom payloads for fuzzing
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className={selectedPayloadPreset === 'xss' ? 'bg-primary text-primary-foreground' : ''}
                  onClick={() => handleApplyPayloadPreset('xss')}
                >
                  XSS Payloads
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className={selectedPayloadPreset === 'sqli' ? 'bg-primary text-primary-foreground' : ''}
                  onClick={() => handleApplyPayloadPreset('sqli')}
                >
                  SQL Injection
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className={selectedPayloadPreset === 'lfi' ? 'bg-primary text-primary-foreground' : ''}
                  onClick={() => handleApplyPayloadPreset('lfi')}
                >
                  LFI / Path Traversal
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className={selectedPayloadPreset === 'rce' ? 'bg-primary text-primary-foreground' : ''}
                  onClick={() => handleApplyPayloadPreset('rce')}
                >
                  RCE Payloads
                </Button>
              </div>
              
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  Enter payloads (one per line)
                </label>
                <Textarea
                  className="font-mono text-sm h-[300px]"
                  placeholder="Enter payloads here, one per line"
                  value={customPayloadsText}
                  onChange={(e) => setCustomPayloadsText(e.target.value)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowPayloadDialog(false)}>Cancel</Button>
              <Button onClick={handleSaveCustomPayloads}>Save Payloads</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        
        <Dialog open={showSettingsDialog} onOpenChange={setShowSettingsDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Advanced Fuzzer Settings</DialogTitle>
              <DialogDescription>
                Configure advanced settings for the web fuzzer
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <label className="text-sm font-medium">Request Timeout (ms)</label>
                <Input 
                  type="number"
                  value={advancedSettings.requestTimeout}
                  onChange={(e) => setAdvancedSettings({
                    ...advancedSettings,
                    requestTimeout: parseInt(e.target.value)
                  })}
                />
              </div>
              
              <div className="space-y-2">
                <label className="text-sm font-medium">Request Delay (ms)</label>
                <Input 
                  type="number"
                  value={advancedSettings.requestDelay}
                  onChange={(e) => setAdvancedSettings({
                    ...advancedSettings,
                    requestDelay: parseInt(e.target.value)
                  })}
                />
              </div>
              
              <div className="space-y-2">
                <label className="text-sm font-medium">Max Requests</label>
                <Input 
                  type="number"
                  value={advancedSettings.maxRequests}
                  onChange={(e) => setAdvancedSettings({
                    ...advancedSettings,
                    maxRequests: parseInt(e.target.value)
                  })}
                />
              </div>
              
              <Separator />
              
              <div className="space-y-4">
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="followRedirects" 
                    checked={advancedSettings.followRedirects}
                    onCheckedChange={(checked) => setAdvancedSettings({
                      ...advancedSettings,
                      followRedirects: checked === true
                    })}
                  />
                  <label htmlFor="followRedirects" className="text-sm">Follow Redirects</label>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="detectBodyChanges" 
                    checked={advancedSettings.detectBodyChanges}
                    onCheckedChange={(checked) => setAdvancedSettings({
                      ...advancedSettings,
                      detectBodyChanges: checked === true
                    })}
                  />
                  <label htmlFor="detectBodyChanges" className="text-sm">Detect Body Changes</label>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="detectAlerts" 
                    checked={advancedSettings.detectAlerts}
                    onCheckedChange={(checked) => setAdvancedSettings({
                      ...advancedSettings,
                      detectAlerts: checked === true
                    })}
                  />
                  <label htmlFor="detectAlerts" className="text-sm">Detect JavaScript Alerts</label>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="detectErrors" 
                    checked={advancedSettings.detectErrors}
                    onCheckedChange={(checked) => setAdvancedSettings({
                      ...advancedSettings,
                      detectErrors: checked === true
                    })}
                  />
                  <label htmlFor="detectErrors" className="text-sm">Detect Error Messages</label>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="saveResponses" 
                    checked={advancedSettings.saveResponses}
                    onCheckedChange={(checked) => setAdvancedSettings({
                      ...advancedSettings,
                      saveResponses: checked === true
                    })}
                  />
                  <label htmlFor="saveResponses" className="text-sm">Save Full Responses</label>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="useML" 
                    checked={advancedSettings.useML}
                    onCheckedChange={(checked) => setAdvancedSettings({
                      ...advancedSettings,
                      useML: checked === true
                    })}
                  />
                  <label htmlFor="useML" className="text-sm">Use Machine Learning</label>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowSettingsDialog(false)}>Cancel</Button>
              <Button onClick={handleSaveSettings}>Save Settings</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </DashboardLayout>
  );
};

export default Fuzzer;
