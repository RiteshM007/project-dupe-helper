
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { 
  Brain, 
  Database, 
  BarChart2, 
  Zap, 
  Play, 
  Download, 
  FileText,
  Loader2,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import { mlApiService, MLAnalysisResult, PayloadGenerationResult } from '@/services/mlApi';
import { toast } from 'sonner';
import { useSocket } from '@/context/SocketContext';
import { useFuzzing } from '@/context/FuzzingContext';

const MLAnalysisPage = () => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<MLAnalysisResult | null>(null);
  const [generatedPayloads, setGeneratedPayloads] = useState<string[]>([]);
  const [modelStatus, setModelStatus] = useState<any>(null);
  const [customContext, setCustomContext] = useState('');
  
  const { socket, emit } = useSocket();
  const { mlResults, setMlResults, addThreatReport } = useFuzzing();

  useEffect(() => {
    // Load model status on component mount
    loadModelStatus();
  }, []);

  const loadModelStatus = async () => {
    try {
      const status = await mlApiService.getModelStatus();
      setModelStatus(status);
    } catch (error) {
      console.error('Failed to load model status:', error);
    }
  };

  const handleRunAnalysis = async () => {
    if (isAnalyzing) return;
    
    setIsAnalyzing(true);
    try {
      toast.info('🧠 Starting ML analysis pipeline...');
      
      // Run the complete ML analysis
      const result = await mlApiService.runAnalysis();
      
      console.log('🎯 ML Analysis Result:', result);
      
      if (result.status === 'success') {
        setAnalysisResult(result);
        
        if (result.payloads) {
          setGeneratedPayloads(prev => [...prev, ...result.payloads!]);
        }
        
        // Update global context - Fix: Use direct array value instead of function
        const newMlResult = {
          sessionId: `ml-${Date.now()}`,
          patterns: result.patterns?.length || 0,
          accuracy: result.model_performance?.accuracy || 0.85,
          riskLevel: result.anomaly_detection_rate ? 
            (result.anomaly_detection_rate > 0.3 ? 'High' : 'Medium') : 'Low',
          type: 'ml_analysis',
          timestamp: new Date().toISOString()
        };
        
        // Fixed: Create new array directly instead of using function
        const updatedMlResults = [...mlResults.slice(-4), newMlResult];
        setMlResults(updatedMlResults);
        
        // Emit Socket.IO event
        if (socket) {
          emit('mlAnalysisComplete', {
            ...result,
            timestamp: new Date().toISOString(),
            type: 'ml_analysis'
          });
        }
        
        toast.success(`✅ ML analysis completed! Generated ${result.payloads?.length || 0} payloads`);
        
        // Add threat reports for high-risk findings
        if (result.anomaly_detection_rate && result.anomaly_detection_rate > 0.2) {
          addThreatReport({
            title: 'High Anomaly Detection Rate',
            severity: result.anomaly_detection_rate > 0.4 ? 'high' : 'medium',
            detectedAt: new Date(),
            source: 'ml_analysis',
            threatType: 'anomaly_detection',
            timestamp: new Date(),
            target: 'ML Analysis Pipeline',
            payload: `Anomaly rate: ${(result.anomaly_detection_rate * 100).toFixed(1)}%`
          });
        }
        
      } else {
        toast.error(`❌ ML analysis failed: ${result.message}`);
      }
      
    } catch (error: any) {
      console.error('ML analysis error:', error);
      toast.error(`❌ ML analysis failed: ${error.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleGeneratePayloads = async (context?: string) => {
    if (isGenerating) return;
    
    setIsGenerating(true);
    try {
      const contextToUse = context || customContext || undefined;
      toast.info(`🚀 Generating payloads${contextToUse ? ` for: ${contextToUse}` : ''}...`);
      
      const result = await mlApiService.generatePayloads(contextToUse, 5);
      
      console.log('✨ Generated Payloads:', result);
      
      if (result.status === 'success') {
        setGeneratedPayloads(prev => [...prev, ...result.payloads]);
        toast.success(`✅ Generated ${result.count} new payloads!`);
        
        // Save payloads
        await mlApiService.savePayloads(result.payloads);
        
      } else {
        toast.error(`❌ Payload generation failed: ${result.message}`);
      }
      
    } catch (error: any) {
      console.error('Payload generation error:', error);
      toast.error(`❌ Payload generation failed: ${error.message}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExportResults = () => {
    if (!analysisResult && generatedPayloads.length === 0) {
      toast.error('No results to export');
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      analysis_result: analysisResult,
      generated_payloads: generatedPayloads,
      model_status: modelStatus,
      total_payloads: generatedPayloads.length
    };

    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ml-analysis-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast.success('Results exported successfully!');
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-6 max-w-7xl">
        <div className="flex justify-between items-start mb-6">
          <div>
            <h1 className="text-3xl font-bold text-white">ML Security Analysis</h1>
            <p className="text-gray-400">Production-grade ML pipeline for vulnerability detection</p>
          </div>
          <div className="flex gap-2">
            <Button onClick={handleExportResults} variant="outline">
              <Download className="w-4 h-4 mr-2" />
              Export Results
            </Button>
          </div>
        </div>

        {/* Status Cards */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <Brain className="w-5 h-5 mr-2 text-purple-400" />
                Model Status
              </CardTitle>
              <CardDescription>ML pipeline status</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold text-white">
                {modelStatus ? 'Ready' : 'Loading...'}
              </div>
              <Badge variant="outline" className="mt-2 text-green-400 border-green-400">
                {modelStatus ? 'Active' : 'Initializing'}
              </Badge>
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <BarChart2 className="w-5 h-5 mr-2 text-blue-400" />
                Analysis
              </CardTitle>
              <CardDescription>Last analysis results</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold text-white">
                {analysisResult?.model_performance?.accuracy ? 
                  `${(analysisResult.model_performance.accuracy * 100).toFixed(1)}%` : '--'}
              </div>
              <p className="text-sm text-gray-500">Model Accuracy</p>
              {analysisResult && (
                <Badge variant="outline" className="mt-2 text-blue-400 border-blue-400">
                  Completed
                </Badge>
              )}
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <Zap className="w-5 h-5 mr-2 text-orange-400" />
                Generated Payloads
              </CardTitle>
              <CardDescription>ML-generated test payloads</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{generatedPayloads.length}</div>
              <p className="text-sm text-gray-500">total payloads</p>
              <Button size="sm" onClick={() => handleGeneratePayloads()} className="mt-2" disabled={isGenerating}>
                {isGenerating ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : null}
                Generate More
              </Button>
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <AlertTriangle className="w-5 h-5 mr-2 text-red-400" />
                Anomaly Rate
              </CardTitle>
              <CardDescription>Detection rate</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold text-white">
                {analysisResult?.anomaly_detection_rate ? 
                  `${(analysisResult.anomaly_detection_rate * 100).toFixed(1)}%` : '--'}
              </div>
              <p className="text-sm text-gray-500">Anomalies detected</p>
            </CardContent>
          </Card>
        </div>

        {/* Main Analysis Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">ML Pipeline Control</CardTitle>
              <CardDescription>Run complete ML analysis and model training</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                onClick={handleRunAnalysis}
                disabled={isAnalyzing}
                className="w-full bg-purple-700 hover:bg-purple-600"
                size="lg"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" />
                    Run ML Analysis
                  </>
                )}
              </Button>
              
              {analysisResult && (
                <div className="mt-4 p-3 bg-gray-900 rounded-md">
                  <div className="flex items-center mb-2">
                    <CheckCircle className="w-4 h-4 text-green-400 mr-2" />
                    <span className="text-sm font-medium text-white">Last Analysis Results</span>
                  </div>
                  <div className="text-sm text-gray-400 space-y-1">
                    <p>Payloads Generated: {analysisResult.payloads?.length || 0}</p>
                    <p>Patterns Found: {analysisResult.patterns?.length || 0}</p>
                    {analysisResult.model_performance && (
                      <p>Model Accuracy: {(analysisResult.model_performance.accuracy * 100).toFixed(1)}%</p>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Contextual Payload Generation</CardTitle>
              <CardDescription>Generate payloads for specific vulnerability types</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-2">
                <label className="text-sm font-medium text-white">Custom Context:</label>
                <Textarea
                  placeholder="Enter context (e.g., 'XSS attack', 'SQL injection')..."
                  value={customContext}
                  onChange={(e) => setCustomContext(e.target.value)}
                  className="bg-gray-900 border-gray-700"
                />
                <Button 
                  onClick={() => handleGeneratePayloads()}
                  disabled={isGenerating}
                  className="w-full"
                >
                  {isGenerating ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
                  Generate Custom Payloads
                </Button>
              </div>
              
              <div className="border-t border-gray-700 pt-3">
                <p className="text-sm text-gray-400 mb-2">Quick Generate:</p>
                <div className="grid grid-cols-2 gap-2">
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleGeneratePayloads('SQL injection')}
                    disabled={isGenerating}
                  >
                    SQL Injection
                  </Button>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleGeneratePayloads('XSS attack')}
                    disabled={isGenerating}
                  >
                    XSS Attack
                  </Button>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleGeneratePayloads('path traversal')}
                    disabled={isGenerating}
                  >
                    Path Traversal
                  </Button>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleGeneratePayloads('command injection')}
                    disabled={isGenerating}
                  >
                    Command Injection
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Generated Payloads Display */}
        {generatedPayloads.length > 0 && (
          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <FileText className="w-5 h-5 mr-2" />
                Generated Payloads ({generatedPayloads.length})
              </CardTitle>
              <CardDescription>ML-generated security test payloads</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-2 max-h-96 overflow-y-auto">
                {generatedPayloads.map((payload, index) => (
                  <div key={index} className="p-3 bg-gray-900 rounded-md border border-gray-700">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-mono text-white">{payload}</span>
                      <Badge variant="outline" className="text-xs">
                        #{index + 1}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  );
};

export default MLAnalysisPage;
