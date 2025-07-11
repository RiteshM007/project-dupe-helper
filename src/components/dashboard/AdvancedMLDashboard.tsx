import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Brain, Target, Shield, TrendingUp, AlertTriangle, FileText, Zap } from 'lucide-react';
import { mlApi } from '@/services/api';
import { useSocket } from '@/hooks/use-socket';
import { toast } from '@/hooks/use-toast';

interface ClusterData {
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
  cluster_analysis: Record<string, any>;
  visualization?: string;
}

interface SignatureData {
  signatures: Record<string, any[]>;
  total_signatures: number;
  categories: string[];
}

interface ReportData {
  report: {
    executive_summary: any;
    vulnerabilities: any[];
    risk_assessment: any;
    recommendations: any[];
    charts: any;
  };
}

export const AdvancedMLDashboard: React.FC = () => {
  const [isTraining, setIsTraining] = useState(false);
  const [modelMetrics, setModelMetrics] = useState<any>(null);
  const [clusterData, setClusterData] = useState<ClusterData | null>(null);
  const [signatures, setSignatures] = useState<SignatureData | null>(null);
  const [report, setReport] = useState<ReportData | null>(null);
  const [selectedTab, setSelectedTab] = useState('overview');

  const { addEventListener, emitEvent } = useSocket();

  useEffect(() => {
    // Set up Socket.IO event listeners for real-time updates
    const cleanupFunctions = [
      addEventListener('mlAnalysisComplete', (data: any) => {
        setModelMetrics(data);
        setIsTraining(false);
        toast({
          title: "ML Analysis Complete",
          description: `Model trained with ${data.accuracy}% accuracy`,
        });
      }),
      addEventListener('mlClusteringComplete', (data: any) => {
        setClusterData(data);
        toast({
          title: "Clustering Complete",
          description: `Found ${data.kmeans_clusters} K-Means clusters`,
        });
      }),
      addEventListener('mlSignaturesGenerated', (data: any) => {
        setSignatures(data);
        toast({
          title: "Signatures Generated",
          description: `Generated ${data.total_signatures} attack signatures`,
        });
      }),
      addEventListener('mlReportGenerated', (data: any) => {
        setReport(data);
        toast({
          title: "Report Generated",
          description: `Risk Level: ${data.report_summary?.risk_level}`,
        });
      })
    ];

    return () => {
      cleanupFunctions.forEach(cleanup => cleanup());
    };
  }, []);

  const handleTrainAdvancedModels = async () => {
    setIsTraining(true);
    try {
      // Train classifier
      const classifierResult = await mlApi.trainClassifier([]);
      setModelMetrics(classifierResult);

      // Perform clustering
      const clusteringResult = await mlApi.performClustering([]);
      setClusterData(clusteringResult);

      // Generate signatures
      const signaturesResult = await mlApi.generateSignatures([]);
      setSignatures(signaturesResult);

      toast({
        title: "Advanced ML Training Complete",
        description: "All ML models have been trained successfully",
      });
    } catch (error: any) {
      toast({
        title: "Training Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsTraining(false);
    }
  };

  const handleGenerateReport = async () => {
    try {
      const sessionData = {
        total_payloads: 150,
        vulnerabilities_found: 23,
        target_url: 'https://example.com',
        vulnerability_types: {
          sql_injection: 12,
          xss: 8,
          command_injection: 3
        },
        duration: '8 minutes'
      };

      const reportResult = await mlApi.generateReport(sessionData);
      setReport(reportResult);
    } catch (error: any) {
      toast({
        title: "Report Generation Failed",
        description: error.message,
        variant: "destructive",
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Advanced ML Dashboard</h2>
          <p className="text-muted-foreground">
            Comprehensive machine learning analysis and threat intelligence
          </p>
        </div>
        <div className="flex gap-2">
          <Button 
            onClick={handleTrainAdvancedModels} 
            disabled={isTraining}
            className="flex items-center gap-2"
          >
            <Brain className="h-4 w-4" />
            {isTraining ? "Training..." : "Train All Models"}
          </Button>
          <Button 
            onClick={handleGenerateReport}
            variant="outline"
            className="flex items-center gap-2"
          >
            <FileText className="h-4 w-4" />
            Generate Report
          </Button>
        </div>
      </div>

      {isTraining && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center space-x-4">
              <div className="flex-1">
                <p className="text-sm font-medium">Training ML Models...</p>
                <Progress value={65} className="mt-2" />
              </div>
              <Brain className="h-8 w-8 animate-pulse text-primary" />
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs value={selectedTab} onValueChange={setSelectedTab}>
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="clustering">Clustering</TabsTrigger>
          <TabsTrigger value="signatures">Signatures</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="predictions">Predictions</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Model Accuracy</CardTitle>
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {modelMetrics?.accuracy ? `${(modelMetrics.accuracy * 100).toFixed(1)}%` : 'N/A'}
                </div>
                <p className="text-xs text-muted-foreground">
                  Advanced RF Classifier
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Clusters Found</CardTitle>
                <Target className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {clusterData?.kmeans?.n_clusters || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  K-Means Analysis
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Attack Signatures</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {signatures?.total_signatures || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  Generated Patterns
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Risk Level</CardTitle>
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {report?.report?.executive_summary?.risk_level || 'UNKNOWN'}
                </div>
                <p className="text-xs text-muted-foreground">
                  Overall Assessment
                </p>
              </CardContent>
            </Card>
          </div>

          {modelMetrics && (
            <Card>
              <CardHeader>
                <CardTitle>Model Performance</CardTitle>
                <CardDescription>Detailed metrics from the latest training</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-4">
                  <div className="space-y-2">
                    <p className="text-sm font-medium">Accuracy</p>
                    <div className="text-2xl font-bold text-green-600">
                      {(modelMetrics.accuracy * 100).toFixed(1)}%
                    </div>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm font-medium">Precision</p>
                    <div className="text-2xl font-bold text-blue-600">
                      {modelMetrics.detailed_results?.random_forest?.precision?.toFixed(3) || 'N/A'}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm font-medium">Recall</p>
                    <div className="text-2xl font-bold text-purple-600">
                      {modelMetrics.detailed_results?.random_forest?.recall?.toFixed(3) || 'N/A'}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <p className="text-sm font-medium">F1 Score</p>
                    <div className="text-2xl font-bold text-orange-600">
                      {modelMetrics.detailed_results?.random_forest?.f1_score?.toFixed(3) || 'N/A'}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="clustering" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Clustering Analysis Results</CardTitle>
              <CardDescription>Attack pattern clustering using K-Means and DBSCAN</CardDescription>
            </CardHeader>
            <CardContent>
              {clusterData ? (
                <div className="space-y-6">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <h4 className="font-semibold">K-Means Clustering</h4>
                      <div className="flex items-center gap-2">
                        <Badge>{clusterData.kmeans.n_clusters} Clusters</Badge>
                        <Badge variant="outline">
                          Silhouette: {clusterData.kmeans.silhouette_score?.toFixed(3)}
                        </Badge>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <h4 className="font-semibold">DBSCAN Clustering</h4>
                      <div className="flex items-center gap-2">
                        <Badge>{clusterData.dbscan.n_clusters} Clusters</Badge>
                        <Badge variant="outline">
                          {clusterData.dbscan.noise_points} Noise Points
                        </Badge>
                      </div>
                    </div>
                  </div>
                  
                  {clusterData.visualization && (
                    <div>
                      <h4 className="font-semibold mb-2">Cluster Visualization</h4>
                      <img 
                        src={clusterData.visualization} 
                        alt="Cluster Visualization" 
                        className="max-w-full h-auto border rounded"
                      />
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-muted-foreground">No clustering data available. Run the analysis first.</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="signatures" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Attack Signatures</CardTitle>
              <CardDescription>Generated attack patterns and signatures</CardDescription>
            </CardHeader>
            <CardContent>
              {signatures ? (
                <div className="space-y-4">
                  {signatures.categories.map((category) => (
                    <div key={category} className="space-y-2">
                      <div className="flex items-center gap-2">
                        <h4 className="font-semibold capitalize">{category.replace('_', ' ')}</h4>
                        <Badge>{signatures.signatures[category]?.length || 0} signatures</Badge>
                      </div>
                      <div className="pl-4 space-y-1">
                        {signatures.signatures[category]?.slice(0, 3).map((sig: any, idx: number) => (
                          <div key={idx} className="text-sm">
                            <code className="bg-muted px-2 py-1 rounded text-xs">
                              {sig.pattern}
                            </code>
                            <span className="ml-2 text-muted-foreground">
                              Risk: {sig.risk_score}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground">No signatures generated yet.</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security Assessment Report</CardTitle>
              <CardDescription>Comprehensive security analysis and recommendations</CardDescription>
            </CardHeader>
            <CardContent>
              {report?.report ? (
                <div className="space-y-6">
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <h4 className="font-semibold">Executive Summary</h4>
                      <div className="space-y-1 text-sm">
                        <p>Total Payloads: {report.report.executive_summary?.total_payloads_tested}</p>
                        <p>Vulnerabilities: {report.report.executive_summary?.vulnerabilities_found}</p>
                        <p>Risk Level: <Badge variant={
                          report.report.executive_summary?.risk_level === 'HIGH' ? 'destructive' :
                          report.report.executive_summary?.risk_level === 'MEDIUM' ? 'default' : 'secondary'
                        }>{report.report.executive_summary?.risk_level}</Badge></p>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <h4 className="font-semibold">Risk Assessment</h4>
                      <div className="space-y-1 text-sm">
                        <p>Overall Score: {report.report.risk_assessment?.overall_score}/100</p>
                        <p>Impact Level: {report.report.risk_assessment?.impact?.join(', ')}</p>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <h4 className="font-semibold">Vulnerabilities</h4>
                      <div className="space-y-1">
                        {report.report.vulnerabilities?.slice(0, 3).map((vuln: any, idx: number) => (
                          <Badge key={idx} variant="outline">
                            {vuln.type}: {vuln.count}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h4 className="font-semibold">Recommendations</h4>
                    <div className="space-y-2">
                      {report.report.recommendations?.map((rec: any, idx: number) => (
                        <div key={idx} className="flex items-start gap-2 p-3 bg-muted rounded">
                          <Badge variant={rec.priority === 'HIGH' ? 'destructive' : 'default'}>
                            {rec.priority}
                          </Badge>
                          <div>
                            <p className="font-medium">{rec.category}</p>
                            <p className="text-sm text-muted-foreground">{rec.recommendation}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-muted-foreground">No report available. Generate one first.</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="predictions" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Real-time Predictions</CardTitle>
              <CardDescription>Anomaly detection and payload effectiveness analysis</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-center py-8">
                <div className="text-center space-y-2">
                  <Zap className="h-12 w-12 mx-auto text-muted-foreground" />
                  <p className="text-muted-foreground">Real-time prediction interface coming soon</p>
                  <p className="text-sm text-muted-foreground">This will show live anomaly detection and payload effectiveness predictions</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};