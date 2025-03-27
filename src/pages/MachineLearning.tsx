
import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { toast } from "sonner";
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Brain, FileBarChart2, Download, Database, BookOpen, Activity, AlertTriangle, ShieldCheck, ShieldX, Clock, Cpu } from 'lucide-react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { AdvancedScannerAnimation } from '@/components/dashboard/AdvancedScannerAnimation';
import { trainIsolationForest, trainRandomForest, predictAnomaly, predictEffectiveness, generateReport, getSampleDataset } from '@/backend/ml_models';

const MachineLearning = () => {
  const [activeTab, setActiveTab] = useState('training');
  const [dataset, setDataset] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [trainingProgress, setTrainingProgress] = useState(0);
  const [models, setModels] = useState<any[]>([]);
  const [analysisResults, setAnalysisResults] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);
  const [recentActivity, setRecentActivity] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState<any>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  
  useEffect(() => {
    // Add some initial activity
    setRecentActivity([
      'System initialized',
      'Machine learning module loaded',
      'Ready to train models'
    ]);
  }, []);
  
  const loadSampleDataset = async () => {
    setIsLoading(true);
    addActivity('Loading sample dataset...');
    
    try {
      await new Promise(resolve => setTimeout(resolve, 1500)); // Simulate loading
      const sampleData = getSampleDataset();
      setDataset(sampleData);
      addActivity(`Loaded sample dataset with ${sampleData.length} records`);
      toast.success('Sample dataset loaded successfully');
    } catch (error) {
      toast.error('Failed to load sample dataset');
      addActivity('Error loading sample dataset');
    } finally {
      setIsLoading(false);
    }
  };
  
  const addActivity = (message: string) => {
    setRecentActivity(prev => [message, ...prev.slice(0, 14)]);
  };
  
  const handleTrainModel = async (modelType: 'IsolationForest' | 'RandomForest') => {
    if (dataset.length === 0) {
      toast.error('Please load a dataset first');
      return;
    }
    
    setIsLoading(true);
    setTrainingProgress(0);
    addActivity(`Starting ${modelType} training...`);
    
    // Simulate training progress
    const progressInterval = setInterval(() => {
      setTrainingProgress(prev => {
        if (prev >= 95) {
          clearInterval(progressInterval);
          return 95;
        }
        return prev + Math.random() * 5;
      });
    }, 200);
    
    try {
      let model;
      if (modelType === 'IsolationForest') {
        model = await trainIsolationForest(dataset);
        addActivity('Isolation Forest model training completed');
      } else {
        model = await trainRandomForest(dataset);
        addActivity('Random Forest model training completed');
      }
      
      setModels(prev => [...prev, model]);
      setTrainingProgress(100);
      toast.success(`${modelType} model trained successfully`);
      
    } catch (error) {
      toast.error(`Failed to train ${modelType} model`);
      addActivity(`Error training ${modelType} model`);
    } finally {
      clearInterval(progressInterval);
      setIsLoading(false);
    }
  };
  
  const handleAnalyzeDataset = async () => {
    if (dataset.length === 0 || models.length === 0) {
      toast.error('Please load a dataset and train at least one model first');
      return;
    }
    
    setIsLoading(true);
    addActivity('Starting vulnerability analysis...');
    
    try {
      await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate analysis
      
      // Get the most recent models of each type
      const isolationModel = models.filter(m => m.type === 'IsolationForest').pop();
      const classifierModel = models.filter(m => m.type === 'RandomForest').pop();
      
      // Analyze each item in the dataset
      const results = dataset.map(item => {
        const features = [item.response_code, item.body_word_count_changed ? 1 : 0];
        const anomalyResult = predictAnomaly(features, isolationModel);
        const effectivenessResult = predictEffectiveness(features, classifierModel);
        
        return {
          payload: item.payload,
          response_code: item.response_code,
          original_label: item.label,
          anomaly: anomalyResult,
          effective: effectivenessResult,
          severity: anomalyResult === -1 ? 
            (effectivenessResult === 1 ? 'Critical' : 'High') : 
            (effectivenessResult === 1 ? 'Medium' : 'Low')
        };
      });
      
      setAnalysisResults(results);
      addActivity(`Analyzed ${results.length} payloads successfully`);
      toast.success('Analysis completed successfully');
    } catch (error) {
      toast.error('Failed to analyze dataset');
      addActivity('Error during analysis');
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleGenerateReport = async () => {
    if (analysisResults.length === 0) {
      toast.error('Please analyze the dataset first');
      return;
    }
    
    setIsGeneratingReport(true);
    addActivity('Generating vulnerability report...');
    
    try {
      const modelInfo = models.map(m => ({
        type: m.type,
        trained: m.timestamp
      }));
      
      const generatedReport = await generateReport(analysisResults, modelInfo);
      setReport(generatedReport);
      addActivity('Vulnerability report generated successfully');
      toast.success('Report generated successfully');
    } catch (error) {
      toast.error('Failed to generate report');
      addActivity('Error generating report');
    } finally {
      setIsGeneratingReport(false);
    }
  };
  
  const handleDownloadReport = () => {
    if (!report) return;
    
    const reportContent = JSON.stringify(report, null, 2);
    const blob = new Blob([reportContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability_report_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast.success('Report downloaded successfully');
    addActivity('Report downloaded');
  };
  
  // Prepare data for charts
  const getPieChartData = () => {
    if (!analysisResults.length) return [];
    
    const counts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    };
    
    analysisResults.forEach(result => {
      counts[result.severity as keyof typeof counts]++;
    });
    
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  };
  
  const getBarChartData = () => {
    if (!analysisResults.length) return [];
    
    const payloadTypes: {[key: string]: number} = {};
    
    // Group by payload type (simplified - just using first few chars as category)
    analysisResults.forEach(result => {
      const payload = result.payload;
      let type = 'Other';
      
      if (payload.includes('<script')) type = 'XSS (Script)';
      else if (payload.includes('<img')) type = 'XSS (Image)';
      else if (payload.includes('UNION SELECT')) type = 'SQL Injection';
      else if (payload.includes("'")) type = 'SQL Quote';
      else if (payload.includes('../')) type = 'Path Traversal';
      else if (payload.includes(';')) type = 'Command Injection';
      
      payloadTypes[type] = (payloadTypes[type] || 0) + 1;
    });
    
    return Object.entries(payloadTypes).map(([name, count]) => ({ name, count }));
  };
  
  const SEVERITY_COLORS = {
    Critical: '#ff4d4f',
    High: '#ff7a45',
    Medium: '#ffa940',
    Low: '#52c41a'
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-500 to-cyan-400">
            AI Security Analysis
          </h1>
          
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              onClick={loadSampleDataset} 
              disabled={isLoading}
              className="border-purple-700/30 hover:border-purple-500/50"
            >
              <Database className="mr-2 h-4 w-4" />
              Load Sample Data
            </Button>
            
            {dataset.length > 0 && (
              <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-700/30">
                {dataset.length} Records Loaded
              </Badge>
            )}
          </div>
        </div>
        
        <Tabs 
          defaultValue="training" 
          value={activeTab} 
          onValueChange={setActiveTab}
          className="w-full"
        >
          <TabsList className="grid grid-cols-4 w-full mb-4 bg-background/20 backdrop-blur">
            <TabsTrigger value="training" className="data-[state=active]:bg-purple-500/20">
              <Brain className="mr-2 h-4 w-4" />
              Training
            </TabsTrigger>
            <TabsTrigger value="analysis" className="data-[state=active]:bg-blue-500/20">
              <Activity className="mr-2 h-4 w-4" />
              Analysis
            </TabsTrigger>
            <TabsTrigger value="reports" className="data-[state=active]:bg-green-500/20">
              <FileBarChart2 className="mr-2 h-4 w-4" />
              Reports
            </TabsTrigger>
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-cyan-500/20">
              <Cpu className="mr-2 h-4 w-4" />
              Dashboard
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="training" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card className="bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Brain className="mr-2 h-5 w-5 text-purple-400" />
                    Anomaly Detection
                  </CardTitle>
                  <CardDescription>
                    Train an Isolation Forest model to detect anomalies in web responses
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                      The Isolation Forest algorithm isolates observations by randomly selecting a feature
                      and then randomly selecting a split value between the maximum and minimum values of that feature.
                    </p>
                    
                    {isLoading && activeTab === 'training' && (
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-sm">Training Progress</span>
                          <span className="text-sm">{Math.round(trainingProgress)}%</span>
                        </div>
                        <Progress value={trainingProgress} className="h-2" />
                      </div>
                    )}
                  </div>
                </CardContent>
                <CardFooter className="flex justify-between">
                  <Button
                    variant="outline"
                    onClick={() => handleTrainModel('IsolationForest')}
                    disabled={isLoading || dataset.length === 0}
                    className="border-purple-700/30 hover:border-purple-500/50"
                  >
                    Train Model
                  </Button>
                  
                  <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-700/30">
                    {models.filter(m => m.type === 'IsolationForest').length} Models
                  </Badge>
                </CardFooter>
              </Card>
              
              <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <BookOpen className="mr-2 h-5 w-5 text-blue-400" />
                    Vulnerability Classification
                  </CardTitle>
                  <CardDescription>
                    Train a Random Forest classifier to identify effective attack payloads
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                      The Random Forest classifier builds multiple decision trees and merges them to get a more accurate
                      and stable prediction, helping identify patterns in successful attack vectors.
                    </p>
                    
                    {isLoading && activeTab === 'training' && (
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-sm">Training Progress</span>
                          <span className="text-sm">{Math.round(trainingProgress)}%</span>
                        </div>
                        <Progress value={trainingProgress} className="h-2" />
                      </div>
                    )}
                  </div>
                </CardContent>
                <CardFooter className="flex justify-between">
                  <Button
                    variant="outline"
                    onClick={() => handleTrainModel('RandomForest')}
                    disabled={isLoading || dataset.length === 0}
                    className="border-blue-700/30 hover:border-blue-500/50"
                  >
                    Train Model
                  </Button>
                  
                  <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-700/30">
                    {models.filter(m => m.type === 'RandomForest').length} Models
                  </Badge>
                </CardFooter>
              </Card>
              
              {/* Activity Log */}
              <Card className="bg-card/50 backdrop-blur-sm border-gray-900/30 shadow-lg shadow-gray-500/5 md:col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Clock className="mr-2 h-5 w-5 text-gray-400" />
                    Activity Log
                  </CardTitle>
                  <CardDescription>
                    Recent system actions and events
                  </CardDescription>
                </CardHeader>
                <CardContent className="max-h-40 overflow-y-auto scrollbar-none">
                  <div className="space-y-2">
                    {recentActivity.map((activity, i) => (
                      <div key={i} className="flex items-start p-2 text-sm border-b border-gray-800 last:border-0">
                        <div className="w-16 text-xs text-gray-500">
                          {new Date().toLocaleTimeString()}
                        </div>
                        <div className="flex-1 ml-2">{activity}</div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          
          <TabsContent value="analysis" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5 col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Activity className="mr-2 h-5 w-5 text-blue-400" />
                    Vulnerability Analysis
                  </CardTitle>
                  <CardDescription>
                    Analyze dataset using trained machine learning models
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                      Combined analysis using anomaly detection and classification to identify potential vulnerabilities.
                      Results are categorized by severity level.
                    </p>
                    
                    {analysisResults.length > 0 && (
                      <div className="rounded-md border border-gray-800 overflow-hidden">
                        <div className="max-h-64 overflow-y-auto scrollbar-none">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="bg-background/50">
                                <th className="p-2 text-left">Payload</th>
                                <th className="p-2 text-left">Response</th>
                                <th className="p-2 text-left">Severity</th>
                                <th className="p-2 text-left">Anomaly</th>
                                <th className="p-2 text-left">Effective</th>
                              </tr>
                            </thead>
                            <tbody>
                              {analysisResults.slice(0, 10).map((result, i) => (
                                <tr key={i} className="border-t border-gray-800">
                                  <td className="p-2 font-mono text-xs truncate max-w-[200px]">{result.payload}</td>
                                  <td className="p-2">{result.response_code}</td>
                                  <td className="p-2">
                                    <Badge 
                                      variant="outline" 
                                      className={`
                                        ${result.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border-red-700/30' : ''}
                                        ${result.severity === 'High' ? 'bg-orange-500/20 text-orange-400 border-orange-700/30' : ''}
                                        ${result.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-700/30' : ''}
                                        ${result.severity === 'Low' ? 'bg-green-500/20 text-green-400 border-green-700/30' : ''}
                                      `}
                                    >
                                      {result.severity}
                                    </Badge>
                                  </td>
                                  <td className="p-2">
                                    {result.anomaly === -1 ? (
                                      <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-700/30">
                                        <AlertTriangle className="h-3 w-3 mr-1" />
                                        Yes
                                      </Badge>
                                    ) : (
                                      <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-700/30">
                                        <ShieldCheck className="h-3 w-3 mr-1" />
                                        No
                                      </Badge>
                                    )}
                                  </td>
                                  <td className="p-2">
                                    {result.effective === 1 ? (
                                      <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-700/30">
                                        <ShieldX className="h-3 w-3 mr-1" />
                                        Yes
                                      </Badge>
                                    ) : (
                                      <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-700/30">
                                        <ShieldCheck className="h-3 w-3 mr-1" />
                                        No
                                      </Badge>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        {analysisResults.length > 10 && (
                          <div className="p-2 text-center text-sm text-muted-foreground border-t border-gray-800">
                            Showing 10 of {analysisResults.length} results
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </CardContent>
                <CardFooter>
                  <Button
                    onClick={handleAnalyzeDataset}
                    disabled={isLoading || dataset.length === 0 || models.length === 0}
                    className="bg-blue-600 hover:bg-blue-700 text-white"
                  >
                    Analyze Dataset
                  </Button>
                </CardFooter>
              </Card>
              
              <Card className="bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <FileBarChart2 className="mr-2 h-5 w-5 text-purple-400" />
                    Analysis Summary
                  </CardTitle>
                  <CardDescription>
                    Vulnerability severity distribution
                  </CardDescription>
                </CardHeader>
                <CardContent className="flex justify-center">
                  {analysisResults.length > 0 ? (
                    <div className="h-64 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={getPieChartData()}
                            cx="50%"
                            cy="50%"
                            outerRadius={80}
                            fill="#8884d8"
                            dataKey="value"
                            label={({ name, value }) => `${name}: ${value}`}
                          >
                            {getPieChartData().map((entry, index) => (
                              <Cell 
                                key={`cell-${index}`} 
                                fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS] || '#8884d8'} 
                              />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <div className="h-64 w-full flex items-center justify-center text-sm text-muted-foreground">
                      No analysis results available
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
            
            {analysisResults.length > 0 && (
              <Card className="bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Activity className="mr-2 h-5 w-5 text-purple-400" />
                    Payload Type Distribution
                  </CardTitle>
                  <CardDescription>
                    Types of attack vectors analyzed
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={getBarChartData()}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                        <XAxis 
                          dataKey="name" 
                          tick={{ fill: 'currentColor', fontSize: 12 }}
                          axisLine={{ stroke: '#666' }}
                          tickLine={{ stroke: '#666' }}
                        />
                        <YAxis 
                          tick={{ fill: 'currentColor', fontSize: 12 }}
                          axisLine={{ stroke: '#666' }}
                          tickLine={{ stroke: '#666' }}
                        />
                        <Tooltip />
                        <Bar dataKey="count" fill="#8884d8" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
          
          <TabsContent value="reports" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card className="bg-card/50 backdrop-blur-sm border-green-900/30 shadow-lg shadow-green-500/5">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <FileBarChart2 className="mr-2 h-5 w-5 text-green-400" />
                    Vulnerability Report
                  </CardTitle>
                  <CardDescription>
                    Generate comprehensive security assessment report
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                      Generate a detailed report of all vulnerabilities detected by the AI models.
                      The report includes severity assessments, recommendations, and detailed findings.
                    </p>
                    
                    {report && (
                      <Dialog>
                        <DialogTrigger asChild>
                          <Button variant="outline" className="w-full border-green-700/30 hover:border-green-500/50">
                            <BookOpen className="mr-2 h-4 w-4" />
                            View Report
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                          <DialogHeader>
                            <DialogTitle>{report.title}</DialogTitle>
                            <DialogDescription>
                              Generated on {new Date(report.timestamp).toLocaleString()}
                            </DialogDescription>
                          </DialogHeader>
                          
                          <div className="space-y-4">
                            <div className="space-y-2">
                              <h3 className="text-lg font-medium">Summary</h3>
                              <div className="grid grid-cols-3 gap-4">
                                <Card>
                                  <CardContent className="p-4 text-center">
                                    <div className="text-2xl font-bold">{report.summary.totalSamples}</div>
                                    <div className="text-sm">Total Samples</div>
                                  </CardContent>
                                </Card>
                                <Card>
                                  <CardContent className="p-4 text-center">
                                    <div className="text-2xl font-bold text-red-400">{report.summary.anomalies}</div>
                                    <div className="text-sm">Anomalies</div>
                                  </CardContent>
                                </Card>
                                <Card>
                                  <CardContent className="p-4 text-center">
                                    <div className="text-2xl font-bold text-yellow-400">{report.summary.effectivePayloads}</div>
                                    <div className="text-sm">Effective Payloads</div>
                                  </CardContent>
                                </Card>
                              </div>
                            </div>
                            
                            <div className="space-y-2">
                              <h3 className="text-lg font-medium">Severity Distribution</h3>
                              <div className="h-64 w-full">
                                <ResponsiveContainer width="100%" height="100%">
                                  <PieChart>
                                    <Pie
                                      data={getPieChartData()}
                                      cx="50%"
                                      cy="50%"
                                      outerRadius={80}
                                      fill="#8884d8"
                                      dataKey="value"
                                      label={({ name, value }) => `${name}: ${value}`}
                                    >
                                      {getPieChartData().map((entry, index) => (
                                        <Cell 
                                          key={`cell-${index}`} 
                                          fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS] || '#8884d8'} 
                                        />
                                      ))}
                                    </Pie>
                                    <Tooltip />
                                  </PieChart>
                                </ResponsiveContainer>
                              </div>
                            </div>
                            
                            <div className="space-y-2">
                              <h3 className="text-lg font-medium">Critical Findings</h3>
                              <div className="rounded-md border border-gray-800 overflow-hidden">
                                <table className="w-full text-sm">
                                  <thead>
                                    <tr className="bg-background/50">
                                      <th className="p-2 text-left">Payload</th>
                                      <th className="p-2 text-left">Severity</th>
                                      <th className="p-2 text-left">Response</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {report.results
                                      .filter((r: any) => r.severity === 'Critical')
                                      .slice(0, 5)
                                      .map((result: any, i: number) => (
                                        <tr key={i} className="border-t border-gray-800">
                                          <td className="p-2 font-mono text-xs truncate max-w-[300px]">{result.payload}</td>
                                          <td className="p-2">
                                            <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-700/30">
                                              {result.severity}
                                            </Badge>
                                          </td>
                                          <td className="p-2">{result.response_code}</td>
                                        </tr>
                                      ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          </div>
                          
                          <DialogFooter>
                            <Button onClick={handleDownloadReport}>
                              <Download className="mr-2 h-4 w-4" />
                              Download Report
                            </Button>
                          </DialogFooter>
                        </DialogContent>
                      </Dialog>
                    )}
                  </div>
                </CardContent>
                <CardFooter>
                  <Button
                    onClick={handleGenerateReport}
                    disabled={isGeneratingReport || analysisResults.length === 0}
                    className="bg-green-600 hover:bg-green-700 text-white"
                  >
                    {isGeneratingReport ? (
                      <>Generating...</>
                    ) : (
                      <>
                        <FileBarChart2 className="mr-2 h-4 w-4" />
                        Generate Report
                      </>
                    )}
                  </Button>
                  
                  {report && (
                    <Button 
                      variant="outline" 
                      onClick={handleDownloadReport}
                      className="ml-2 border-green-700/30 hover:border-green-500/50"
                    >
                      <Download className="mr-2 h-4 w-4" />
                      Download
                    </Button>
                  )}
                </CardFooter>
              </Card>
              
              <Card className="bg-card/50 backdrop-blur-sm border-gray-900/30 shadow-lg shadow-gray-500/5">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Activity className="mr-2 h-5 w-5 text-gray-400" />
                    Model Management
                  </CardTitle>
                  <CardDescription>
                    Manage and select AI models for analysis
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {models.length > 0 ? (
                      <div className="rounded-md border border-gray-800 overflow-hidden">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="bg-background/50">
                              <th className="p-2 text-left">Model Type</th>
                              <th className="p-2 text-left">Trained</th>
                              <th className="p-2 text-left">Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {models.map((model, i) => (
                              <tr key={i} className="border-t border-gray-800">
                                <td className="p-2">
                                  <Badge 
                                    variant="outline" 
                                    className={
                                      model.type === 'IsolationForest' 
                                        ? 'bg-purple-500/20 text-purple-400 border-purple-700/30'
                                        : 'bg-blue-500/20 text-blue-400 border-blue-700/30'
                                    }
                                  >
                                    {model.type}
                                  </Badge>
                                </td>
                                <td className="p-2 text-xs text-gray-400">
                                  {new Date(model.timestamp).toLocaleString()}
                                </td>
                                <td className="p-2">
                                  <Button 
                                    variant="ghost" 
                                    size="sm" 
                                    onClick={() => setSelectedModel(model)}
                                    className={selectedModel === model ? 'bg-primary/20' : ''}
                                  >
                                    Select
                                  </Button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="p-8 text-center text-sm text-muted-foreground">
                        No models trained yet. Go to the Training tab to train models.
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          
          <TabsContent value="dashboard" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card className="bg-card/50 backdrop-blur-sm border-cyan-900/30 shadow-lg shadow-cyan-500/5 md:col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Activity className="mr-2 h-5 w-5 text-cyan-400" />
                    ML Security Scanner
                  </CardTitle>
                  <CardDescription>
                    Real-time vulnerability detection powered by AI
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 w-full">
                    <AdvancedScannerAnimation active={true} />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Brain className="mr-2 h-5 w-5 text-purple-400" />
                    ML Stats
                  </CardTitle>
                  <CardDescription>
                    Models and datasets overview
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex flex-col gap-4">
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Datasets</span>
                        <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-700/30">
                          {dataset.length} Records
                        </Badge>
                      </div>
                      
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Models</span>
                        <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-700/30">
                          {models.length} Trained
                        </Badge>
                      </div>
                      
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Anomalies</span>
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-700/30">
                          {analysisResults.filter(r => r.anomaly === -1).length} Detected
                        </Badge>
                      </div>
                      
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Critical Severity</span>
                        <Badge variant="outline" className="bg-orange-500/10 text-orange-400 border-orange-700/30">
                          {analysisResults.filter(r => r.severity === 'Critical').length} Issues
                        </Badge>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5 md:col-span-3">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <FileBarChart2 className="mr-2 h-5 w-5 text-blue-400" />
                    Analysis Trends
                  </CardTitle>
                  <CardDescription>
                    Vulnerability detection patterns over time
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 w-full">
                    {analysisResults.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart
                          data={[
                            { name: '1', Critical: 2, High: 5, Medium: 7, Low: 12 },
                            { name: '2', Critical: 3, High: 4, Medium: 6, Low: 10 },
                            { name: '3', Critical: 4, High: 6, Medium: 4, Low: 8 },
                            { name: '4', Critical: 3, High: 7, Medium: 5, Low: 11 },
                            { name: '5', Critical: 5, High: 5, Medium: 8, Low: 9 },
                            { name: '6', Critical: 4, High: 6, Medium: 7, Low: 10 },
                            { name: '7', Critical: 3, High: 4, Medium: 6, Low: 12 },
                          ]}
                          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                          <XAxis 
                            dataKey="name" 
                            tick={{ fill: 'currentColor', fontSize: 12 }}
                            axisLine={{ stroke: '#666' }}
                            tickLine={{ stroke: '#666' }}
                          />
                          <YAxis 
                            tick={{ fill: 'currentColor', fontSize: 12 }}
                            axisLine={{ stroke: '#666' }}
                            tickLine={{ stroke: '#666' }}
                          />
                          <Tooltip />
                          <Line type="monotone" dataKey="Critical" stroke="#ff4d4f" />
                          <Line type="monotone" dataKey="High" stroke="#ff7a45" />
                          <Line type="monotone" dataKey="Medium" stroke="#ffa940" />
                          <Line type="monotone" dataKey="Low" stroke="#52c41a" />
                        </LineChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                        Run analysis to view trends
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
};

export default MachineLearning;
