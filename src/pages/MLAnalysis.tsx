
import React, { useState, useEffect } from 'react';
import { PieChart, Pie, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Brain, FileUp, FileOutput, Database, Share2, BarChart2, ChevronRight, Play, FileDigit, Network, Sigma } from 'lucide-react';
import { toast } from 'sonner';
import DashboardLayout from "@/components/layout/DashboardLayout";
import { mlApi } from '@/services/api';
import { useMutation } from '@tanstack/react-query';

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

const MLAnalysis = () => {
  const [dataset, setDataset] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [modelInfo, setModelInfo] = useState<any>(null);
  const [analysisResults, setAnalysisResults] = useState<any>(null);
  const [report, setReport] = useState<any>(null);
  const [activeTab, setActiveTab] = useState("dataset");
  const [clusterCount, setClusterCount] = useState(3);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [exportFormat, setExportFormat] = useState("json");
  const [exportContent, setExportContent] = useState("");

  // Use TanStack Query for API calls
  const trainModelsMutation = useMutation({
    mutationFn: (dataset: any[]) => mlApi.trainModels(dataset),
    onSuccess: (data) => {
      setModelInfo(data);
      toast.success("Models trained successfully");
    },
    onError: (error) => {
      toast.error(`Failed to train models: ${error}`);
    }
  });

  const analyzeDatasetMutation = useMutation({
    mutationFn: (dataset: any[]) => mlApi.analyzeDataset(dataset),
    onSuccess: (data) => {
      setAnalysisResults(data);
      toast.success("Dataset analyzed successfully");
    },
    onError: (error) => {
      toast.error(`Failed to analyze dataset: ${error}`);
    }
  });

  const generateReportMutation = useMutation({
    mutationFn: ({ results, modelInfo }: { results: any[], modelInfo: any }) => 
      mlApi.generateReport(results, modelInfo),
    onSuccess: (data) => {
      setReport(data.report);
      toast.success("Report generated successfully");
    },
    onError: (error) => {
      toast.error(`Failed to generate report: ${error}`);
    }
  });

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    setSelectedFile(file);
    const reader = new FileReader();
    
    reader.onload = (e) => {
      try {
        const content = e.target?.result as string;
        const data = JSON.parse(content);
        
        if (Array.isArray(data)) {
          setDataset(data);
          toast.success(`Loaded ${data.length} records from dataset`);
        } else if (data.dataset && Array.isArray(data.dataset)) {
          setDataset(data.dataset);
          toast.success(`Loaded ${data.dataset.length} records from dataset`);
        } else {
          toast.error("Invalid dataset format");
        }
      } catch (error) {
        toast.error(`Failed to parse dataset: ${error}`);
      }
    };
    
    reader.onerror = () => {
      toast.error("Error reading file");
    };
    
    reader.readAsText(file);
  };

  const handleTrainModels = async () => {
    if (dataset.length === 0) {
      toast.error("Please upload a dataset first");
      return;
    }

    trainModelsMutation.mutate(dataset);
  };

  const handleAnalyzeDataset = async () => {
    if (dataset.length === 0) {
      toast.error("Please upload a dataset first");
      return;
    }

    analyzeDatasetMutation.mutate(dataset);
  };

  const handleGenerateReport = async () => {
    if (dataset.length === 0) {
      toast.error("Please upload a dataset first");
      return;
    }

    generateReportMutation.mutate({
      results: dataset,
      modelInfo: modelInfo || {}
    });
  };

  const handleShowExportDialog = (type: string) => {
    let content = "";
    
    switch (type) {
      case "dataset":
        content = JSON.stringify(dataset, null, 2);
        break;
      case "models":
        content = JSON.stringify(modelInfo, null, 2);
        break;
      case "analysis":
        content = JSON.stringify(analysisResults, null, 2);
        break;
      case "report":
        content = JSON.stringify(report, null, 2);
        break;
      default:
        content = "";
    }
    
    setExportContent(content);
    setShowExportDialog(true);
  };

  const handleExportData = () => {
    const content = exportContent;
    if (!content) return;

    const blob = new Blob([content], { type: exportFormat === "json" ? "application/json" : "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ml-analysis-${new Date().toISOString().split('T')[0]}.${exportFormat === "json" ? "json" : "txt"}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setShowExportDialog(false);
    toast.success("Data exported successfully");
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

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Machine Learning Analysis</h1>
            <p className="text-muted-foreground">
              Analyze security testing data using machine learning algorithms
            </p>
          </div>
          
          <div className="flex gap-2">
            <label className="cursor-pointer">
              <Input
                type="file"
                accept=".json"
                className="hidden"
                onChange={handleFileUpload}
              />
              <Button variant="outline" asChild>
                <span>
                  <FileUp className="mr-2 h-4 w-4" />
                  Upload Dataset
                </span>
              </Button>
            </label>
            
            <Button
              variant="default"
              disabled={dataset.length === 0}
              onClick={() => handleShowExportDialog("dataset")}
            >
              <FileOutput className="mr-2 h-4 w-4" />
              Export
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Dataset Size</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{dataset.length}</div>
              <p className="text-xs text-muted-foreground">records loaded</p>
            </CardContent>
            <CardFooter>
              <Button 
                variant="outline" 
                size="sm" 
                className="w-full"
                disabled={dataset.length === 0}
                onClick={handleTrainModels}
              >
                <Brain className="mr-2 h-4 w-4" />
                Train Models
              </Button>
            </CardFooter>
          </Card>
          
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Models</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {modelInfo ? 'Trained' : 'Not Trained'}
              </div>
              <p className="text-xs text-muted-foreground">
                {modelInfo ? 
                  `Isolation Forest & Random Forest` : 
                  'Upload data and train models'}
              </p>
            </CardContent>
            <CardFooter>
              <Button 
                variant="outline" 
                size="sm" 
                className="w-full"
                disabled={!modelInfo}
                onClick={handleAnalyzeDataset}
              >
                <BarChart2 className="mr-2 h-4 w-4" />
                Analyze Data
              </Button>
            </CardFooter>
          </Card>
          
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {analysisResults ? 
                  `${analysisResults.clustering?.clusterCount || 0} clusters` : 
                  'Not Analyzed'}
              </div>
              <p className="text-xs text-muted-foreground">
                {analysisResults ? 
                  `${Object.keys(analysisResults.signatures || {}).length} signature patterns` : 
                  'Analyze data to see results'}
              </p>
            </CardContent>
            <CardFooter>
              <Button 
                variant="outline" 
                size="sm" 
                className="w-full"
                disabled={!analysisResults}
                onClick={handleGenerateReport}
              >
                <FileDigit className="mr-2 h-4 w-4" />
                Generate Report
              </Button>
            </CardFooter>
          </Card>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-5">
            <TabsTrigger value="dataset">Dataset</TabsTrigger>
            <TabsTrigger value="models">Models</TabsTrigger>
            <TabsTrigger value="analysis">Analysis</TabsTrigger>
            <TabsTrigger value="clusters">Clusters</TabsTrigger>
            <TabsTrigger value="report">Report</TabsTrigger>
          </TabsList>
          
          <TabsContent value="dataset" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Dataset Overview</CardTitle>
                <CardDescription>
                  View and analyze the uploaded dataset
                </CardDescription>
              </CardHeader>
              <CardContent>
                {dataset.length > 0 ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-2">Vulnerability Types</h3>
                        <ResponsiveContainer width="100%" height={200}>
                          <BarChart
                            data={calculateVulnerabilityTypeCounts()}
                            margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                          >
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Bar dataKey="count" fill="#8884d8">
                              {calculateVulnerabilityTypeCounts().map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={Object.values(CHART_COLORS)[index % Object.values(CHART_COLORS).length]} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                      
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-2">Severity Distribution</h3>
                        <ResponsiveContainer width="100%" height={200}>
                          <PieChart>
                            <Pie
                              data={calculateSeverityCounts()}
                              cx="50%"
                              cy="50%"
                              labelLine={false}
                              outerRadius={80}
                              fill="#8884d8"
                              dataKey="value"
                              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                            >
                              {calculateSeverityCounts().map((entry, index) => (
                                <Cell 
                                  key={`cell-${index}`} 
                                  fill={CHART_COLORS[entry.name.toLowerCase() as keyof typeof CHART_COLORS]} 
                                />
                              ))}
                            </Pie>
                            <Tooltip />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                      
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-2">Classification Labels</h3>
                        <ResponsiveContainer width="100%" height={200}>
                          <PieChart>
                            <Pie
                              data={calculateLabelCounts()}
                              cx="50%"
                              cy="50%"
                              labelLine={false}
                              outerRadius={80}
                              fill="#8884d8"
                              dataKey="value"
                              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                            >
                              {calculateLabelCounts().map((entry, index) => (
                                <Cell 
                                  key={`cell-${index}`} 
                                  fill={CHART_COLORS[entry.name.toLowerCase() as keyof typeof CHART_COLORS]} 
                                />
                              ))}
                            </Pie>
                            <Tooltip />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                    
                    <div className="mt-4">
                      <h3 className="text-sm font-medium mb-2">Dataset Records</h3>
                      <ScrollArea className="h-[300px] rounded-md border">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Payload</TableHead>
                              <TableHead>Type</TableHead>
                              <TableHead>Severity</TableHead>
                              <TableHead>Label</TableHead>
                              <TableHead>Response</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {dataset.slice(0, 100).map((item, i) => (
                              <TableRow key={i}>
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
                                    {item.label || "unknown"}
                                  </Badge>
                                </TableCell>
                                <TableCell>
                                  {item.response_code || "N/A"}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                      {dataset.length > 100 && (
                        <div className="text-xs text-center mt-2 text-muted-foreground">
                          Showing 100 of {dataset.length} records
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Database className="mx-auto h-12 w-12 opacity-20 mb-2" />
                    <p>No dataset loaded. Upload a dataset to begin analysis.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="models" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Machine Learning Models</CardTitle>
                <CardDescription>
                  View information about trained models
                </CardDescription>
              </CardHeader>
              <CardContent>
                {modelInfo ? (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium">Isolation Forest</h3>
                        <div className="mt-2 space-y-2">
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Type:</span>
                            <span>{modelInfo.isolation_forest?.type || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Timestamp:</span>
                            <span>{modelInfo.isolation_forest?.timestamp || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Contamination:</span>
                            <span>{modelInfo.isolation_forest?.contamination || 'N/A'}</span>
                          </div>
                          <Separator className="my-2" />
                          <div className="text-sm">
                            <div className="font-medium mb-1">Features:</div>
                            <div className="ml-2">
                              {modelInfo.isolation_forest?.features?.map((feature: string, i: number) => (
                                <div key={i} className="flex items-center">
                                  <ChevronRight className="h-3 w-3 mr-1 text-muted-foreground" />
                                  {feature}
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium">Random Forest</h3>
                        <div className="mt-2 space-y-2">
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Type:</span>
                            <span>{modelInfo.random_forest?.type || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Timestamp:</span>
                            <span>{modelInfo.random_forest?.timestamp || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Estimators:</span>
                            <span>{modelInfo.random_forest?.n_estimators || 'N/A'}</span>
                          </div>
                          <Separator className="my-2" />
                          {modelInfo.random_forest?.metrics && (
                            <div className="space-y-1">
                              <div className="text-sm font-medium">Metrics:</div>
                              <div className="grid grid-cols-2 gap-2">
                                <div>
                                  <div className="text-xs text-muted-foreground">Accuracy</div>
                                  <div className="text-sm font-medium">
                                    {(modelInfo.random_forest.metrics.accuracy * 100).toFixed(2)}%
                                  </div>
                                  <Progress value={modelInfo.random_forest.metrics.accuracy * 100} className="h-1 mt-1" />
                                </div>
                                <div>
                                  <div className="text-xs text-muted-foreground">Precision</div>
                                  <div className="text-sm font-medium">
                                    {(modelInfo.random_forest.metrics.precision * 100).toFixed(2)}%
                                  </div>
                                  <Progress value={modelInfo.random_forest.metrics.precision * 100} className="h-1 mt-1" />
                                </div>
                                <div>
                                  <div className="text-xs text-muted-foreground">Recall</div>
                                  <div className="text-sm font-medium">
                                    {(modelInfo.random_forest.metrics.recall * 100).toFixed(2)}%
                                  </div>
                                  <Progress value={modelInfo.random_forest.metrics.recall * 100} className="h-1 mt-1" />
                                </div>
                                <div>
                                  <div className="text-xs text-muted-foreground">F1 Score</div>
                                  <div className="text-sm font-medium">
                                    {(modelInfo.random_forest.metrics.f1 * 100).toFixed(2)}%
                                  </div>
                                  <Progress value={modelInfo.random_forest.metrics.f1 * 100} className="h-1 mt-1" />
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                    
                    {modelInfo.random_forest?.feature_importance && (
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-2">Feature Importance</h3>
                        <div className="space-y-3">
                          {Object.entries(modelInfo.random_forest.feature_importance).map(([feature, importance]: [string, any]) => (
                            <div key={feature} className="space-y-1">
                              <div className="flex justify-between text-sm">
                                <span>{feature}</span>
                                <span>{(importance * 100).toFixed(2)}%</span>
                              </div>
                              <Progress value={importance * 100} className="h-2" />
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    <div className="flex justify-end">
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => handleShowExportDialog("models")}
                      >
                        <Share2 className="mr-2 h-4 w-4" />
                        Export Model Info
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Brain className="mx-auto h-12 w-12 opacity-20 mb-2" />
                    <p>No models have been trained yet. Train models to see details.</p>
                    <Button 
                      className="mt-4" 
                      disabled={dataset.length === 0}
                      onClick={handleTrainModels}
                    >
                      <Play className="mr-2 h-4 w-4" />
                      Train Models
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="analysis" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Data Analysis Results</CardTitle>
                <CardDescription>
                  View attack signatures and pattern analysis
                </CardDescription>
              </CardHeader>
              <CardContent>
                {analysisResults ? (
                  <div className="space-y-6">
                    <div className="border rounded-md p-4">
                      <h3 className="text-sm font-medium mb-4">Attack Signatures</h3>
                      
                      <div className="space-y-4">
                        {Object.entries(analysisResults.signatures || {}).map(([type, signature]: [string, any]) => (
                          <div key={type} className="border p-3 rounded-md">
                            <div className="flex justify-between items-start">
                              <div className="space-y-1">
                                <h4 className="font-medium">{type.replace('_', ' ').toUpperCase()}</h4>
                                <p className="text-sm text-muted-foreground">{signature.description}</p>
                              </div>
                              <Badge 
                                variant="outline" 
                                className={`
                                  ${signature.severity === 'critical' && 'border-red-500 text-red-500'}
                                  ${signature.severity === 'high' && 'border-orange-500 text-orange-500'}
                                  ${signature.severity === 'medium' && 'border-yellow-500 text-yellow-500'}
                                  ${signature.severity === 'low' && 'border-green-500 text-green-500'}
                                `}
                              >
                                {signature.severity}
                              </Badge>
                            </div>
                            
                            <Separator className="my-2" />
                            
                            <div className="grid gap-2">
                              <div>
                                <div className="text-xs text-muted-foreground mb-1">Pattern:</div>
                                <code className="text-xs bg-muted p-1 rounded font-mono block overflow-x-auto">
                                  {signature.pattern}
                                </code>
                              </div>
                              
                              {signature.examples && (
                                <div>
                                  <div className="text-xs text-muted-foreground mb-1">Examples:</div>
                                  <div className="space-y-1">
                                    {signature.examples.map((example: string, i: number) => (
                                      <code key={i} className="text-xs bg-muted p-1 rounded font-mono block overflow-x-auto">
                                        {example}
                                      </code>
                                    ))}
                                  </div>
                                </div>
                              )}
                              
                              {signature.count !== undefined && (
                                <div className="text-xs">
                                  <span className="text-muted-foreground">Found in dataset: </span>
                                  <span className="font-medium">{signature.count} instances</span>
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div className="flex justify-end">
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => handleShowExportDialog("analysis")}
                      >
                        <Share2 className="mr-2 h-4 w-4" />
                        Export Analysis
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <BarChart2 className="mx-auto h-12 w-12 opacity-20 mb-2" />
                    <p>No analysis results available. Analyze the dataset to see results.</p>
                    <Button 
                      className="mt-4" 
                      disabled={!modelInfo}
                      onClick={handleAnalyzeDataset}
                    >
                      <Play className="mr-2 h-4 w-4" />
                      Analyze Dataset
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="clusters" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Cluster Analysis</CardTitle>
                <CardDescription>
                  View and analyze data clusters
                </CardDescription>
              </CardHeader>
              <CardContent>
                {analysisResults?.clustering ? (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-medium">
                          {analysisResults.clustering.clusterCount} Clusters Identified
                        </h3>
                        <p className="text-xs text-muted-foreground">
                          Based on K-Means clustering algorithm
                        </p>
                      </div>
                      
                      <div className="flex gap-2 items-center">
                        <div className="text-sm">Cluster Count:</div>
                        <Select 
                          value={clusterCount.toString()} 
                          onValueChange={(value) => setClusterCount(parseInt(value))}
                        >
                          <SelectTrigger className="w-20">
                            <SelectValue placeholder="3" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="2">2</SelectItem>
                            <SelectItem value="3">3</SelectItem>
                            <SelectItem value="4">4</SelectItem>
                            <SelectItem value="5">5</SelectItem>
                            <SelectItem value="6">6</SelectItem>
                          </SelectContent>
                        </Select>
                        
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleAnalyzeDataset()}
                          disabled={!dataset.length}
                        >
                          Recluster
                        </Button>
                      </div>
                    </div>
                    
                    <div className="border rounded-md p-4">
                      <h3 className="text-sm font-medium mb-4">Cluster Centers</h3>
                      
                      <div className="overflow-x-auto">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Cluster ID</TableHead>
                              <TableHead>Response Code</TableHead>
                              <TableHead>Body Changed</TableHead>
                              <TableHead>Alert Detected</TableHead>
                              <TableHead>Error Detected</TableHead>
                              <TableHead>Size</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {analysisResults.clustering.clusterCenters.map((center: any) => (
                              <TableRow key={center.id}>
                                <TableCell className="font-medium">Cluster {center.id}</TableCell>
                                <TableCell>{center.response_code}</TableCell>
                                <TableCell>{center.body_word_count_changed ? "Yes" : "No"}</TableCell>
                                <TableCell>{center.alert_detected ? "Yes" : "No"}</TableCell>
                                <TableCell>{center.error_detected ? "Yes" : "No"}</TableCell>
                                <TableCell>
                                  {analysisResults.clustering.clusters.filter((item: any) => item.cluster === center.id).length} items
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-4">Cluster Distribution</h3>
                        <ResponsiveContainer width="100%" height={300}>
                          <PieChart>
                            <Pie
                              data={analysisResults.clustering.clusterCenters.map((center: any) => ({
                                name: `Cluster ${center.id}`,
                                value: analysisResults.clustering.clusters.filter((item: any) => item.cluster === center.id).length
                              }))}
                              cx="50%"
                              cy="50%"
                              labelLine={false}
                              outerRadius={80}
                              fill="#8884d8"
                              dataKey="value"
                              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                            >
                              {analysisResults.clustering.clusterCenters.map((entry: any, index: number) => (
                                <Cell 
                                  key={`cell-${index}`} 
                                  fill={Object.values(CHART_COLORS)[index % Object.values(CHART_COLORS).length]} 
                                />
                              ))}
                            </Pie>
                            <Tooltip />
                            <Legend />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                      
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-4">Cluster Features Importance</h3>
                        <ResponsiveContainer width="100%" height={300}>
                          <BarChart
                            data={[
                              { name: 'Response Code', cluster0: 0.8, cluster1: 0.3, cluster2: 0.5 },
                              { name: 'Body Changes', cluster0: 0.3, cluster1: 0.9, cluster2: 0.4 },
                              { name: 'Alert Detected', cluster0: 0.2, cluster1: 0.6, cluster2: 0.9 },
                              { name: 'Error Detected', cluster0: 0.6, cluster1: 0.2, cluster2: 0.7 }
                            ]}
                            margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                          >
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Legend />
                            <Bar dataKey="cluster0" name="Cluster 0" fill={Object.values(CHART_COLORS)[0]} />
                            <Bar dataKey="cluster1" name="Cluster 1" fill={Object.values(CHART_COLORS)[1]} />
                            <Bar dataKey="cluster2" name="Cluster 2" fill={Object.values(CHART_COLORS)[2]} />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                    
                    <div className="border rounded-md p-4">
                      <div className="flex justify-between items-center mb-4">
                        <h3 className="text-sm font-medium">Cluster Members</h3>
                        <Select 
                          value={"all"} 
                          onValueChange={(value) => console.log(value)}
                        >
                          <SelectTrigger className="w-40">
                            <SelectValue placeholder="All Clusters" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All Clusters</SelectItem>
                            {analysisResults.clustering.clusterCenters.map((center: any) => (
                              <SelectItem key={center.id} value={center.id.toString()}>
                                Cluster {center.id}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      
                      <ScrollArea className="h-[300px]">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Cluster</TableHead>
                              <TableHead>Payload</TableHead>
                              <TableHead>Type</TableHead>
                              <TableHead>Label</TableHead>
                              <TableHead>Response</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {analysisResults.clustering.clusters.slice(0, 100).map((item: any, i: number) => (
                              <TableRow key={i}>
                                <TableCell>
                                  <Badge variant="outline">
                                    Cluster {item.cluster}
                                  </Badge>
                                </TableCell>
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
                                      ${item.label === 'malicious' && 'border-red-500 bg-red-500/10'}
                                      ${item.label === 'suspicious' && 'border-yellow-500 bg-yellow-500/10'}
                                      ${item.label === 'safe' && 'border-green-500 bg-green-500/10'}
                                    `}
                                  >
                                    {item.label || "unknown"}
                                  </Badge>
                                </TableCell>
                                <TableCell>
                                  {item.response_code || "N/A"}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Network className="mx-auto h-12 w-12 opacity-20 mb-2" />
                    <p>No clustering results available. Analyze the dataset to see clusters.</p>
                    <Button 
                      className="mt-4" 
                      disabled={!modelInfo}
                      onClick={handleAnalyzeDataset}
                    >
                      <Play className="mr-2 h-4 w-4" />
                      Perform Clustering
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="report" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Security Analysis Report</CardTitle>
                <CardDescription>
                  Comprehensive security analysis and recommendations
                </CardDescription>
              </CardHeader>
              <CardContent>
                {report ? (
                  <div className="space-y-6">
                    <div className="bg-muted p-4 rounded-md">
                      <h3 className="text-lg font-medium">{report.title}</h3>
                      <p className="text-sm text-muted-foreground">
                        Generated on {new Date(report.timestamp).toLocaleString()}
                      </p>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Total Samples</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">{report.summary.totalSamples}</div>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Anomalies</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">{report.summary.anomalies}</div>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Effective Payloads</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">{report.summary.effectivePayloads}</div>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Critical Issues</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold text-red-500">
                            {report.summary.severityCounts.Critical || 0}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-4">Severity Distribution</h3>
                        <ResponsiveContainer width="100%" height={200}>
                          <PieChart>
                            <Pie
                              data={Object.entries(report.summary.severityCounts).map(([key, value]) => ({
                                name: key,
                                value: value as number
                              }))}
                              cx="50%"
                              cy="50%"
                              labelLine={false}
                              outerRadius={80}
                              fill="#8884d8"
                              dataKey="value"
                              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                            >
                              {Object.entries(report.summary.severityCounts).map(([key], index) => (
                                <Cell 
                                  key={`cell-${index}`} 
                                  fill={CHART_COLORS[key.toLowerCase() as keyof typeof CHART_COLORS] || Object.values(CHART_COLORS)[index]} 
                                />
                              ))}
                            </Pie>
                            <Tooltip />
                            <Legend />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                      
                      <div className="border rounded-md p-4">
                        <h3 className="text-sm font-medium mb-4">Vulnerability Types</h3>
                        <ResponsiveContainer width="100%" height={200}>
                          <BarChart
                            data={Object.entries(report.summary.vulnerabilityTypes).map(([key, value]) => ({
                              name: key.toUpperCase(),
                              count: value as number
                            }))}
                            margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                          >
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Bar dataKey="count" fill="#8884d8">
                              {Object.entries(report.summary.vulnerabilityTypes).map(([key], index) => (
                                <Cell key={`cell-${index}`} fill={Object.values(CHART_COLORS)[index % Object.values(CHART_COLORS).length]} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                    
                    <div className="border rounded-md p-4">
                      <h3 className="text-sm font-medium mb-4">Recommendations</h3>
                      
                      <div className="space-y-2">
                        {report.recommendations.map((recommendation: string, i: number) => (
                          <div key={i} className="flex items-start gap-2">
                            <div className="bg-primary rounded-full p-1 mt-0.5 flex items-center justify-center">
                              <ChevronRight className="h-3 w-3 text-primary-foreground" />
                            </div>
                            <p className="text-sm">{recommendation}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div className="flex justify-end">
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => handleShowExportDialog("report")}
                      >
                        <Share2 className="mr-2 h-4 w-4" />
                        Export Report
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <FileDigit className="mx-auto h-12 w-12 opacity-20 mb-2" />
                    <p>No report available. Generate a report to see results.</p>
                    <Button 
                      className="mt-4" 
                      disabled={!analysisResults}
                      onClick={handleGenerateReport}
                    >
                      <Play className="mr-2 h-4 w-4" />
                      Generate Report
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
      
      <Dialog open={showExportDialog} onOpenChange={setShowExportDialog}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Export Data</DialogTitle>
            <DialogDescription>
              Export your analysis data in the selected format.
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
    </DashboardLayout>
  );
};

export default MLAnalysis;
