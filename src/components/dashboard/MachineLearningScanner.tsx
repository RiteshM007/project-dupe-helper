import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Brain, BarChart2, AlertTriangle, CheckCircle2, FileText } from 'lucide-react';
import { ScannerAnimation } from "./ScannerAnimation";
import { trainIsolationForest, trainRandomForest, generateReport } from "@/backend/ml_models";
import { toast } from 'sonner';

interface MachineLearningProps {
  scanActive: boolean;
  scanCompleted: boolean;
  dataset: any[];
  threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
}

export const MachineLearningScanner: React.FC<MachineLearningProps> = ({
  scanActive,
  scanCompleted,
  dataset,
  threatLevel
}) => {
  const [trainingActive, setTrainingActive] = useState(false);
  const [trainingProgress, setTrainingProgress] = useState(0);
  const [modelTrained, setModelTrained] = useState(false);
  const [collectedDataset, setCollectedDataset] = useState<any[]>([]);
  const [modelInsights, setModelInsights] = useState<{
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    payloadPatterns: string[];
    vulnerabilityTypes: { type: string; count: number; probability: number }[];
    recommendations: string[];
  }>({
    accuracy: 0,
    precision: 0,
    recall: 0,
    f1: 0,
    payloadPatterns: [],
    vulnerabilityTypes: [],
    recommendations: []
  });

  // Listen for dataset entries from fuzzer
  useEffect(() => {
    const handleDatasetEntry = (event: CustomEvent) => {
      setCollectedDataset(prev => [...prev, event.detail]);
    };

    const handleScanComplete = () => {
      setTimeout(() => {
        if (collectedDataset.length > 0) {
          trainMLModels();
        }
      }, 500);
    };

    window.addEventListener('datasetEntry', handleDatasetEntry as EventListener);
    window.addEventListener('scanComplete', handleScanComplete);

    return () => {
      window.removeEventListener('datasetEntry', handleDatasetEntry as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete);
    };
  }, [collectedDataset]);

  // Start training when scan completes and there's data
  useEffect(() => {
    const combinedDataset = [...dataset, ...collectedDataset];
    
    if (scanCompleted && combinedDataset.length > 0 && !modelTrained && !trainingActive) {
      trainMLModels();
    }
  }, [scanCompleted, dataset, collectedDataset, modelTrained]);

  // Simulate training progress
  useEffect(() => {
    if (trainingActive) {
      const interval = setInterval(() => {
        setTrainingProgress(prev => {
          const newProgress = prev + Math.random() * 5 + 2;
          if (newProgress >= 100) {
            clearInterval(interval);
            setTrainingActive(false);
            setModelTrained(true);
            generateInsights();
            return 100;
          }
          return newProgress;
        });
      }, 500);

      return () => clearInterval(interval);
    }
  }, [trainingActive]);

  const trainMLModels = async () => {
    setTrainingActive(true);
    setTrainingProgress(0);
    toast.info("Starting ML model training with scan results...");
    
    const combinedDataset = [...dataset, ...collectedDataset];
    
    try {
      // Train isolation forest for anomaly detection
      const isolationResult = await trainIsolationForest(combinedDataset);
      
      // Train random forest for classification
      const randomForestResult = await trainRandomForest(combinedDataset);
      
      setModelInsights(prev => ({
        ...prev,
        accuracy: randomForestResult.metrics.accuracy,
        precision: randomForestResult.metrics.precision,
        recall: randomForestResult.metrics.recall,
        f1: randomForestResult.metrics.f1
      }));
      
      toast.success("ML models trained successfully!");
    } catch (error) {
      console.error("Error during ML training:", error);
      toast.error("Error training ML models");
    }
  };

  const generateInsights = async () => {
    try {
      const combinedDataset = [...dataset, ...collectedDataset];
      
      // Extract patterns from payloads that were flagged as threats
      const threatPayloads = combinedDataset.filter(item => 
        item.label === 'malicious' || item.label === 'suspicious'
      );
      
      // Generate vulnerability type statistics
      const vulnTypes: Record<string, number> = {};
      threatPayloads.forEach(item => {
        const type = item.vulnerability_type || 'unknown';
        vulnTypes[type] = (vulnTypes[type] || 0) + 1;
      });
      
      const vulnerabilityTypes = Object.entries(vulnTypes).map(([type, count]) => ({
        type,
        count,
        probability: Math.min(0.95, 0.6 + (count / threatPayloads.length) * 0.3)
      }));
      
      // Pattern detection
      const patterns: string[] = [];
      
      if (vulnTypes['sql_injection'] > 0) {
        patterns.push('SQL injection patterns detected');
        patterns.push('Database manipulation attempts');
      }
      
      if (vulnTypes['xss'] > 0) {
        patterns.push('Cross-site scripting vectors');
        patterns.push('Script injection attempts');
      }
      
      if (vulnTypes['path_traversal'] > 0) {
        patterns.push('Path traversal attempts');
        patterns.push('File system access patterns');
      }
      
      if (vulnTypes['command_injection'] > 0) {
        patterns.push('Command injection patterns');
        patterns.push('System command execution');
      }
      
      // Generate recommendations
      const recommendations: string[] = [
        'Implement input validation and sanitization',
        'Use parameterized queries for database operations',
        'Apply proper output encoding',
        'Implement Content Security Policy (CSP)',
        'Regular security testing and code reviews',
        'Use Web Application Firewall (WAF)',
        'Implement rate limiting'
      ];
      
      setModelInsights(prev => ({
        ...prev,
        payloadPatterns: patterns,
        vulnerabilityTypes,
        recommendations
      }));
      
    } catch (error) {
      console.error("Error generating insights:", error);
      toast.error("Error analyzing payload patterns");
    }
  };

  const exportReport = async () => {
    try {
      const combinedDataset = [...dataset, ...collectedDataset];
      const report = await generateReport(combinedDataset, modelInsights);
      
      // Create and download the report
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `ml-security-report-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      toast.success("Report exported successfully!");
    } catch (error) {
      console.error("Error exporting report:", error);
      toast.error("Failed to export report");
    }
  };

  return (
    <Card className="border-emerald-900/20 bg-emerald-950/10 shadow-lg hover:shadow-xl transition-all duration-300">
      <CardHeader className="border-b border-emerald-900/20 pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl font-medium flex items-center">
            <Brain className="w-5 h-5 mr-2 text-emerald-400" />
            Machine Learning Analysis
          </CardTitle>
          <div className="flex gap-2">
            {modelTrained && (
              <Badge variant="outline" className="bg-emerald-900/30 text-emerald-300 border-emerald-700">
                <CheckCircle2 className="w-3 h-3 mr-1" />
                Trained
              </Badge>
            )}
            {trainingActive && (
              <Badge variant="outline" className="bg-yellow-900/30 text-yellow-300 border-yellow-700">
                Training...
              </Badge>
            )}
          </div>
        </div>
        <CardDescription className="text-emerald-100/70">
          Advanced machine learning analysis of vulnerability patterns
        </CardDescription>
      </CardHeader>
      
      <CardContent className="pt-6">
        <div className="flex flex-col space-y-4">
          {/* Training Status */}
          {trainingActive ? (
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-sm text-emerald-100/80">Training ML Models...</span>
                <span className="text-sm font-mono text-emerald-100/80">{Math.floor(trainingProgress)}%</span>
              </div>
              <Progress value={trainingProgress} />
              <p className="text-xs text-emerald-100/60 italic">
                Training on {collectedDataset.length + dataset.length} data points
              </p>
            </div>
          ) : scanActive ? (
            <div className="bg-emerald-950/20 rounded-md p-4 border border-emerald-900/30">
              <div className="flex items-center">
                <div className="w-full text-center">
                  <p className="text-emerald-100/80 text-sm">Collecting data for ML training...</p>
                  <p className="text-xs text-emerald-100/60 mt-1">Models will be trained after scan completion</p>
                </div>
              </div>
            </div>
          ) : !scanCompleted && collectedDataset.length === 0 ? (
            <div className="bg-emerald-950/20 rounded-md p-4 border border-emerald-900/30">
              <div className="flex items-center">
                <div className="w-full text-center">
                  <p className="text-emerald-100/80 text-sm">Start a scan to collect data for ML analysis</p>
                </div>
              </div>
            </div>
          ) : null}
          
          {/* ML Insights */}
          {modelTrained && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-emerald-950/20 rounded-md p-4 border border-emerald-900/30">
                  <h3 className="text-sm font-medium text-emerald-100/80 mb-2 flex items-center">
                    <BarChart2 className="w-4 h-4 mr-1 text-emerald-400" />
                    Model Performance
                  </h3>
                  <div className="space-y-2">
                    <div>
                      <div className="flex justify-between items-center text-xs">
                        <span>Accuracy</span>
                        <span>{(modelInsights.accuracy * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.accuracy * 100} />
                    </div>
                    <div>
                      <div className="flex justify-between items-center text-xs">
                        <span>Precision</span>
                        <span>{(modelInsights.precision * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.precision * 100} />
                    </div>
                    <div>
                      <div className="flex justify-between items-center text-xs">
                        <span>Recall</span>
                        <span>{(modelInsights.recall * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.recall * 100} />
                    </div>
                    <div>
                      <div className="flex justify-between items-center text-xs">
                        <span>F1 Score</span>
                        <span>{(modelInsights.f1 * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.f1 * 100} />
                    </div>
                  </div>
                </div>
                
                <div className="bg-emerald-950/20 rounded-md p-4 border border-emerald-900/30">
                  <h3 className="text-sm font-medium text-emerald-100/80 mb-2 flex items-center">
                    <AlertTriangle className="w-4 h-4 mr-1 text-yellow-400" />
                    Detected Patterns
                  </h3>
                  <ScrollArea className="h-[120px]">
                    <ul className="space-y-1 text-xs">
                      {modelInsights.payloadPatterns.map((pattern, index) => (
                        <li key={index} className="text-emerald-100/80">• {pattern}</li>
                      ))}
                    </ul>
                  </ScrollArea>
                </div>
              </div>
              
              <div className="bg-emerald-950/20 rounded-md p-4 border border-emerald-900/30">
                <h3 className="text-sm font-medium text-emerald-100/80 mb-2">Vulnerability Types</h3>
                <div className="grid grid-cols-2 gap-2">
                  {modelInsights.vulnerabilityTypes.map((vuln, index) => (
                    <div key={index} className="flex justify-between items-center p-2 bg-emerald-950/30 rounded">
                      <span className="text-xs">{vuln.type}</span>
                      <Badge variant="outline" className="text-xs">
                        {(vuln.probability * 100).toFixed(0)}%
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
              
              <div className="bg-emerald-950/20 rounded-md p-4 border border-emerald-900/30">
                <div className="flex justify-between items-center mb-2">
                  <h3 className="text-sm font-medium text-emerald-100/80">Security Recommendations</h3>
                  <Button onClick={exportReport} size="sm" variant="outline" className="border-emerald-700 text-emerald-300 hover:bg-emerald-900/30">
                    <FileText className="w-3 h-3 mr-1" />
                    Export Report
                  </Button>
                </div>
                <ScrollArea className="h-24">
                  <ul className="space-y-1 text-xs">
                    {modelInsights.recommendations.map((rec, index) => (
                      <li key={index} className="text-emerald-100/80">• {rec}</li>
                    ))}
                  </ul>
                </ScrollArea>
              </div>
            </div>
          )}
          
          {/* Manual Training */}
          {!modelTrained && !trainingActive && (collectedDataset.length > 0 || dataset.length > 0) && (
            <Button 
              onClick={trainMLModels}
              className="bg-emerald-700 hover:bg-emerald-600 text-white"
            >
              <Brain className="w-4 h-4 mr-2" />
              Train ML Models with {collectedDataset.length + dataset.length} Data Points
            </Button>
          )}
          
          {/* Visualization */}
          <div className="h-40 mt-2">
            <ScannerAnimation 
              active={scanActive || trainingActive} 
              threatLevel={trainingActive ? 'medium' : threatLevel}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
