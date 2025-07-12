import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { mlApi } from '@/services/api';
import {
  Brain, Target, Shield, AlertTriangle, TrendingUp, FileText,
  Zap, Database, Cpu, Eye, BarChart3, Network, Clock, Star
} from 'lucide-react';

interface MLAnalysisResult {
  success: boolean;
  accuracy: number;
  model_type: string;
  samples_trained: number;
  features_engineered: number;
  confusion_matrix: number[][];
  classification_report: any;
  feature_importance_plot?: string;
}

interface ClusteringResult {
  success: boolean;
  kmeans: {
    n_clusters: number;
    silhouette_score: number;
    labels: number[];
  };
  dbscan: {
    n_clusters: number;
    labels: number[];
    noise_points: number;
  };
  cluster_analysis: any;
  visualization?: string;
}

interface AttackSignatures {
  sql_injection: Array<{ pattern: string; original: string; risk_score: number }>;
  xss: Array<{ pattern: string; original: string; risk_score: number }>;
  path_traversal: Array<{ pattern: string; original: string; risk_score: number }>;
  command_injection: Array<{ pattern: string; original: string; risk_score: number }>;
  general: Array<{ pattern: string; original: string; risk_score: number }>;
}

interface ComprehensiveReport {
  success: boolean;
  report_id: string;
  executive_summary: {
    overall_risk_level: string;
    vulnerabilities_found: number;
    payloads_tested: number;
    success_rate: string;
    average_risk_score: string;
    maximum_risk_score: string;
  };
  vulnerability_breakdown: {
    by_type: Record<string, number>;
    by_severity: {
      Critical: number;
      High: number;
      Medium: number;
      Low: number;
    };
  };
  recommendations: Array<{
    priority: string;
    category: string;
    description: string;
    technical_details: string;
  }>;
  risk_timeline_plot?: string;
}

export const ComprehensiveMLDashboard: React.FC = () => {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState('training');
  const [loading, setLoading] = useState(false);
  
  // State for different ML operations
  const [analysisResult, setAnalysisResult] = useState<MLAnalysisResult | null>(null);
  const [clusteringResult, setClusteringResult] = useState<ClusteringResult | null>(null);
  const [signatures, setSignatures] = useState<AttackSignatures | null>(null);
  const [report, setReport] = useState<ComprehensiveReport | null>(null);
  const [generatedPayloads, setGeneratedPayloads] = useState<string[]>([]);
  
  // Form states
  const [payloadContext, setPayloadContext] = useState('xss');
  const [payloadCount, setPayloadCount] = useState(10);
  const [difficulty, setDifficulty] = useState('medium');
  const [testPayload, setTestPayload] = useState('');
  const [predictionResult, setPredictionResult] = useState<any>(null);

  const handleAdvancedTraining = async () => {
    setLoading(true);
    try {
      // Create comprehensive training dataset
      const trainingDataset = [
        { payload: "' OR 1=1 --", label: 'malicious', response_code: 500 },
        { payload: "<script>alert('XSS')</script>", label: 'malicious', response_code: 500 },
        { payload: "../../../etc/passwd", label: 'malicious', response_code: 404 },
        { payload: "; whoami", label: 'malicious', response_code: 500 },
        { payload: "normal search query", label: 'safe', response_code: 200 },
        { payload: "SELECT * FROM products WHERE name LIKE '%search%'", label: 'safe', response_code: 200 },
        { payload: "' UNION SELECT NULL,NULL,version() --", label: 'malicious', response_code: 500 },
        { payload: "<img src=x onerror=alert(1)>", label: 'malicious', response_code: 500 },
        { payload: "../../../../windows/system32/drivers/etc/hosts", label: 'malicious', response_code: 404 },
        { payload: "| nc -l -p 4444 -e /bin/sh", label: 'malicious', response_code: 500 },
        { payload: "user@example.com", label: 'safe', response_code: 200 },
        { payload: "Hello World", label: 'safe', response_code: 200 },
      ];

      const result = await mlApi.trainClassifier(trainingDataset);
      setAnalysisResult(result);
      
      toast({
        title: "Advanced Training Complete",
        description: `Model trained with ${result.accuracy * 100}% accuracy on ${result.samples_trained} samples`,
      });
    } catch (error: any) {
      toast({
        title: "Training Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleClusteringAnalysis = async () => {
    setLoading(true);
    try {
      const dataset = [
        { payload: "' OR 1=1 --", label: 'malicious' },
        { payload: "'; DROP TABLE users; --", label: 'malicious' },
        { payload: "admin'--", label: 'malicious' },
        { payload: "<script>alert('XSS')</script>", label: 'malicious' },
        { payload: "<img src=x onerror=alert(1)>", label: 'malicious' },
        { payload: "javascript:alert('XSS')", label: 'malicious' },
        { payload: "../../../etc/passwd", label: 'malicious' },
        { payload: "....//....//....//etc/passwd", label: 'malicious' },
        { payload: "; whoami", label: 'malicious' },
        { payload: "| cat /etc/passwd", label: 'malicious' },
        { payload: "normal input", label: 'safe' },
        { payload: "search query", label: 'safe' },
      ];

      const result = await mlApi.performClustering(dataset);
      setClusteringResult(result);
      
      toast({
        title: "Clustering Analysis Complete",
        description: `Found ${result.kmeans.n_clusters} K-Means clusters and ${result.dbscan.n_clusters} DBSCAN clusters`,
      });
    } catch (error: any) {
      toast({
        title: "Clustering Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSignatureGeneration = async () => {
    setLoading(true);
    try {
      const successfulPayloads = [
        "' OR 1=1 --",
        "<script>alert('XSS')</script>",
        "../../../etc/passwd",
        "; whoami",
        "'; DROP TABLE users; --",
        "<img src=x onerror=alert(1)>",
        "| cat /etc/passwd",
        "....//....//....//etc/passwd"
      ];

      const result = await mlApi.generateSignatures(successfulPayloads);
      setSignatures(result);
      
      const totalSignatures = Object.values(result).reduce((sum: number, sigs: any) => sum + sigs.length, 0);
      toast({
        title: "Attack Signatures Generated",
        description: `Generated ${totalSignatures} attack signatures across all categories`,
      });
    } catch (error: any) {
      toast({
        title: "Signature Generation Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleReportGeneration = async () => {
    setLoading(true);
    try {
      const sessionData = {
        vulnerabilities: [
          { type: 'XSS', payload: "<script>alert('XSS')</script>", detected_at: new Date().toISOString() },
          { type: 'SQL Injection', payload: "' OR 1=1 --", detected_at: new Date().toISOString() },
          { type: 'Path Traversal', payload: "../../../etc/passwd", detected_at: new Date().toISOString() },
        ],
        payloads_tested: 150,
        target_url: 'http://dvwa.local',
        duration: '15 minutes'
      };

      const result = await mlApi.generateReport(sessionData);
      setReport(result);
      
      toast({
        title: "Comprehensive Report Generated",
        description: `Executive summary shows ${result.executive_summary.overall_risk_level} risk level`,
      });
    } catch (error: any) {
      toast({
        title: "Report Generation Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleIntelligentPayloadGeneration = async () => {
    setLoading(true);
    try {
      const result = await mlApi.generateAdvancedPayloads(payloadContext, payloadCount, difficulty);
      setGeneratedPayloads(result.payloads || []);
      
      toast({
        title: "Intelligent Payloads Generated",
        description: `Generated ${result.payloads?.length || 0} ${difficulty} difficulty payloads for ${payloadContext}`,
      });
    } catch (error: any) {
      toast({
        title: "Payload Generation Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handlePayloadPrediction = async () => {
    if (!testPayload.trim()) return;
    
    setLoading(true);
    try {
      const [effectivenessResult, anomalyResult] = await Promise.all([
        mlApi.predictEffectiveness(testPayload, payloadContext),
        mlApi.predictAnomaly(testPayload)
      ]);

      setPredictionResult({
        effectiveness: effectivenessResult,
        anomaly: anomalyResult
      });
      
      toast({
        title: "Payload Analysis Complete",
        description: `Effectiveness: ${effectivenessResult.effectiveness}, Anomaly: ${anomalyResult.is_anomaly ? 'Detected' : 'Normal'}`,
      });
    } catch (error: any) {
      toast({
        title: "Prediction Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-red-400';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Comprehensive ML Security Analysis</h1>
          <p className="text-muted-foreground">Advanced machine learning for vulnerability detection and analysis</p>
        </div>
        <Badge variant="outline" className="text-sm">
          <Brain className="h-4 w-4 mr-1" />
          AI-Powered Security
        </Badge>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="training">
            <Cpu className="h-4 w-4 mr-2" />
            Training
          </TabsTrigger>
          <TabsTrigger value="clustering">
            <Network className="h-4 w-4 mr-2" />
            Clustering
          </TabsTrigger>
          <TabsTrigger value="signatures">
            <Shield className="h-4 w-4 mr-2" />
            Signatures
          </TabsTrigger>
          <TabsTrigger value="payloads">
            <Zap className="h-4 w-4 mr-2" />
            Payloads
          </TabsTrigger>
          <TabsTrigger value="prediction">
            <Eye className="h-4 w-4 mr-2" />
            Prediction
          </TabsTrigger>
          <TabsTrigger value="reporting">
            <FileText className="h-4 w-4 mr-2" />
            Reporting
          </TabsTrigger>
        </TabsList>

        {/* Advanced Training Tab */}
        <TabsContent value="training" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Brain className="h-5 w-5 mr-2" />
                Advanced Classifier Training
              </CardTitle>
              <CardDescription>
                Train ML models with advanced feature engineering and cross-validation
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                onClick={handleAdvancedTraining} 
                disabled={loading}
                className="w-full"
              >
                {loading ? 'Training Model...' : 'Start Advanced Training'}
              </Button>

              {analysisResult && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <Card>
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-green-600">
                          {(analysisResult.accuracy * 100).toFixed(1)}%
                        </div>
                        <div className="text-sm text-muted-foreground">Accuracy</div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-blue-600">
                          {analysisResult.samples_trained}
                        </div>
                        <div className="text-sm text-muted-foreground">Samples</div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-purple-600">
                          {analysisResult.features_engineered}
                        </div>
                        <div className="text-sm text-muted-foreground">Features</div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="p-4 text-center">
                        <div className="text-2xl font-bold text-orange-600">
                          {analysisResult.model_type}
                        </div>
                        <div className="text-sm text-muted-foreground">Model</div>
                      </CardContent>
                    </Card>
                  </div>

                  {analysisResult.feature_importance_plot && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">Feature Importance</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <img 
                          src={analysisResult.feature_importance_plot} 
                          alt="Feature Importance Plot"
                          className="w-full max-w-2xl mx-auto"
                        />
                      </CardContent>
                    </Card>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Clustering Analysis Tab */}
        <TabsContent value="clustering" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Network className="h-5 w-5 mr-2" />
                Advanced Clustering Analysis
              </CardTitle>
              <CardDescription>
                K-Means and DBSCAN clustering with silhouette analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                onClick={handleClusteringAnalysis} 
                disabled={loading}
                className="w-full"
              >
                {loading ? 'Analyzing Clusters...' : 'Perform Clustering Analysis'}
              </Button>

              {clusteringResult && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">K-Means Results</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <span>Clusters:</span>
                            <Badge>{clusteringResult.kmeans.n_clusters}</Badge>
                          </div>
                          <div className="flex justify-between">
                            <span>Silhouette Score:</span>
                            <Badge variant="outline">
                              {clusteringResult.kmeans.silhouette_score.toFixed(3)}
                            </Badge>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">DBSCAN Results</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <span>Clusters:</span>
                            <Badge>{clusteringResult.dbscan.n_clusters}</Badge>
                          </div>
                          <div className="flex justify-between">
                            <span>Noise Points:</span>
                            <Badge variant="outline">
                              {clusteringResult.dbscan.noise_points}
                            </Badge>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  {clusteringResult.visualization && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">Cluster Visualization</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <img 
                          src={clusteringResult.visualization} 
                          alt="Cluster Visualization"
                          className="w-full max-w-4xl mx-auto"
                        />
                      </CardContent>
                    </Card>
                  )}

                  {clusteringResult.cluster_analysis && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">Cluster Analysis</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {Object.entries(clusteringResult.cluster_analysis).map(([clusterId, analysis]: [string, any]) => (
                            <div key={clusterId} className="border rounded-lg p-3">
                              <h4 className="font-semibold mb-2 capitalize">{clusterId.replace('_', ' ')}</h4>
                              <div className="grid grid-cols-2 gap-2 text-sm">
                                <div>Size: {analysis.size}</div>
                                <div>Avg Length: {analysis.avg_payload_length?.toFixed(1)}</div>
                                <div>Avg Entropy: {analysis.avg_entropy?.toFixed(2)}</div>
                                <div>Patterns: {analysis.common_patterns?.join(', ') || 'None'}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Attack Signatures Tab */}
        <TabsContent value="signatures" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Shield className="h-5 w-5 mr-2" />
                Attack Signature Generation
              </CardTitle>
              <CardDescription>
                Generate attack patterns from successful payloads
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                onClick={handleSignatureGeneration} 
                disabled={loading}
                className="w-full"
              >
                {loading ? 'Generating Signatures...' : 'Generate Attack Signatures'}
              </Button>

              {signatures && (
                <div className="space-y-4">
                  {Object.entries(signatures).map(([category, sigs]: [string, any]) => (
                    sigs.length > 0 && (
                      <Card key={category}>
                        <CardHeader>
                          <CardTitle className="text-lg capitalize">
                            {category.replace('_', ' ')} Signatures ({sigs.length})
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {sigs.slice(0, 5).map((sig: any, index: number) => (
                              <div key={index} className="border rounded p-3">
                                <div className="flex justify-between items-start mb-2">
                                  <code className="text-sm bg-muted p-1 rounded flex-1 mr-2">
                                    {sig.pattern}
                                  </code>
                                  <Badge 
                                    className={`${getRiskColor(
                                      sig.risk_score > 70 ? 'critical' : 
                                      sig.risk_score > 50 ? 'high' : 
                                      sig.risk_score > 30 ? 'medium' : 'low'
                                    )} text-white`}
                                  >
                                    {sig.risk_score.toFixed(0)}
                                  </Badge>
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  Original: {sig.original}
                                </div>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    )
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Intelligent Payload Generation Tab */}
        <TabsContent value="payloads" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Zap className="h-5 w-5 mr-2" />
                Intelligent Payload Generation
              </CardTitle>
              <CardDescription>
                Generate ML-optimized payloads with difficulty levels
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="context">Attack Context</Label>
                  <Select value={payloadContext} onValueChange={setPayloadContext}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="xss">Cross-Site Scripting</SelectItem>
                      <SelectItem value="sql injection">SQL Injection</SelectItem>
                      <SelectItem value="command injection">Command Injection</SelectItem>
                      <SelectItem value="path traversal">Path Traversal</SelectItem>
                      <SelectItem value="general">General</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="difficulty">Difficulty Level</Label>
                  <Select value={difficulty} onValueChange={setDifficulty}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="easy">Easy</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="hard">Hard</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="count">Number of Payloads</Label>
                  <Input
                    type="number"
                    value={payloadCount}
                    onChange={(e) => setPayloadCount(parseInt(e.target.value) || 10)}
                    min="1"
                    max="50"
                  />
                </div>
              </div>

              <Button 
                onClick={handleIntelligentPayloadGeneration} 
                disabled={loading}
                className="w-full"
              >
                {loading ? 'Generating Payloads...' : 'Generate Intelligent Payloads'}
              </Button>

              {generatedPayloads.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Generated Payloads ({generatedPayloads.length})</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {generatedPayloads.map((payload, index) => (
                        <div key={index} className="border rounded p-3">
                          <code className="text-sm bg-muted p-2 rounded block">
                            {payload}
                          </code>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Payload Prediction Tab */}
        <TabsContent value="prediction" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Eye className="h-5 w-5 mr-2" />
                Payload Effectiveness Prediction
              </CardTitle>
              <CardDescription>
                Analyze payload effectiveness and anomaly detection
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="test-payload">Test Payload</Label>
                <Textarea
                  id="test-payload"
                  placeholder="Enter a payload to analyze..."
                  value={testPayload}
                  onChange={(e) => setTestPayload(e.target.value)}
                  rows={3}
                />
              </div>

              <Button 
                onClick={handlePayloadPrediction} 
                disabled={loading || !testPayload.trim()}
                className="w-full"
              >
                {loading ? 'Analyzing Payload...' : 'Analyze Payload'}
              </Button>

              {predictionResult && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg">Effectiveness Analysis</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        <div className="flex justify-between">
                          <span>Effectiveness:</span>
                          <Badge variant={predictionResult.effectiveness.effectiveness === 'high' ? 'destructive' : 'secondary'}>
                            {predictionResult.effectiveness.effectiveness}
                          </Badge>
                        </div>
                        <div className="flex justify-between">
                          <span>Confidence:</span>
                          <Badge variant="outline">
                            {(predictionResult.effectiveness.confidence * 100).toFixed(1)}%
                          </Badge>
                        </div>
                        <div className="flex justify-between">
                          <span>Risk Score:</span>
                          <Badge className={getRiskColor(
                            predictionResult.effectiveness.risk_score > 70 ? 'critical' : 
                            predictionResult.effectiveness.risk_score > 50 ? 'high' : 
                            predictionResult.effectiveness.risk_score > 30 ? 'medium' : 'low'
                          )}>
                            {predictionResult.effectiveness.risk_score.toFixed(0)}
                          </Badge>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg">Anomaly Detection</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        <div className="flex justify-between">
                          <span>Is Anomaly:</span>
                          <Badge variant={predictionResult.anomaly.is_anomaly ? 'destructive' : 'secondary'}>
                            {predictionResult.anomaly.is_anomaly ? 'Yes' : 'No'}
                          </Badge>
                        </div>
                        <div className="flex justify-between">
                          <span>Anomaly Score:</span>
                          <Badge variant="outline">
                            {predictionResult.anomaly.anomaly_score?.toFixed(3) || 'N/A'}
                          </Badge>
                        </div>
                        <div className="flex justify-between">
                          <span>Confidence:</span>
                          <Badge variant="outline">
                            {(predictionResult.anomaly.confidence * 100).toFixed(1)}%
                          </Badge>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Comprehensive Reporting Tab */}
        <TabsContent value="reporting" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <FileText className="h-5 w-5 mr-2" />
                Comprehensive Security Reporting
              </CardTitle>
              <CardDescription>
                Generate executive summaries with risk scoring and recommendations
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                onClick={handleReportGeneration} 
                disabled={loading}
                className="w-full"
              >
                {loading ? 'Generating Report...' : 'Generate Comprehensive Report'}
              </Button>

              {report && (
                <div className="space-y-4">
                  {/* Executive Summary */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg">Executive Summary</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                        <div className="text-center">
                          <div className={`text-2xl font-bold ${
                            report.executive_summary.overall_risk_level === 'High' ? 'text-red-600' :
                            report.executive_summary.overall_risk_level === 'Medium' ? 'text-yellow-600' :
                            'text-green-600'
                          }`}>
                            {report.executive_summary.overall_risk_level}
                          </div>
                          <div className="text-sm text-muted-foreground">Risk Level</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold text-red-600">
                            {report.executive_summary.vulnerabilities_found}
                          </div>
                          <div className="text-sm text-muted-foreground">Vulnerabilities</div>
                        </div>
                        <div className="text-center">
                          <div className="text-2xl font-bold text-blue-600">
                            {report.executive_summary.success_rate}
                          </div>
                          <div className="text-sm text-muted-foreground">Success Rate</div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Vulnerability Breakdown */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg">Vulnerability Breakdown</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="font-semibold mb-2">By Type</h4>
                          <div className="space-y-1">
                            {Object.entries(report.vulnerability_breakdown.by_type).map(([type, count]) => (
                              <div key={type} className="flex justify-between">
                                <span>{type}:</span>
                                <Badge>{count}</Badge>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div>
                          <h4 className="font-semibold mb-2">By Severity</h4>
                          <div className="space-y-1">
                            {Object.entries(report.vulnerability_breakdown.by_severity).map(([severity, count]) => (
                              <div key={severity} className="flex justify-between">
                                <span>{severity}:</span>
                                <Badge className={getRiskColor(severity.toLowerCase())}>
                                  {count}
                                </Badge>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Recommendations */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg">Security Recommendations</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {report.recommendations.map((rec, index) => (
                          <div key={index} className="border rounded-lg p-3">
                            <div className="flex justify-between items-start mb-2">
                              <h4 className="font-semibold">{rec.category}</h4>
                              <Badge 
                                className={getRiskColor(rec.priority.toLowerCase())}
                              >
                                {rec.priority}
                              </Badge>
                            </div>
                            <p className="text-sm mb-2">{rec.description}</p>
                            <p className="text-xs text-muted-foreground">
                              <strong>Technical Details:</strong> {rec.technical_details}
                            </p>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  {/* Risk Timeline */}
                  {report.risk_timeline_plot && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">Risk Timeline</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <img 
                          src={report.risk_timeline_plot} 
                          alt="Risk Timeline"
                          className="w-full max-w-4xl mx-auto"
                        />
                      </CardContent>
                    </Card>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ComprehensiveMLDashboard;