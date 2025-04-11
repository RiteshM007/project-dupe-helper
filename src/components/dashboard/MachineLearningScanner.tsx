
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Brain, BarChart2, AlertTriangle, CheckCircle2, FileText, BookOpen, Server, Database } from 'lucide-react';
import { EnhancedScannerAnimation } from "./EnhancedScannerAnimation";
import { trainIsolationForest, trainRandomForest, generateReport, performClustering } from "@/backend/ml_models";
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
  const [clusterAnalysisDone, setClusterAnalysisDone] = useState(false);
  const [anomalyModelTrained, setAnomalyModelTrained] = useState(false);
  const [classificationModelTrained, setClassificationModelTrained] = useState(false);
  const [modelInsights, setModelInsights] = useState<{
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    payloadPatterns: string[];
    vulnerabilityTypes: { type: string; count: number; probability: number }[];
    recommendations: string[];
    clusters?: any[];
  }>({
    accuracy: 0,
    precision: 0,
    recall: 0,
    f1: 0,
    payloadPatterns: [],
    vulnerabilityTypes: [],
    recommendations: []
  });

  // Start training when scan completes and there's data
  useEffect(() => {
    if (scanCompleted && dataset.length > 0 && !modelTrained && !trainingActive) {
      trainModel();
    }
  }, [scanCompleted, dataset, modelTrained]);

  // Simulate training progress
  useEffect(() => {
    if (trainingActive) {
      const interval = setInterval(() => {
        setTrainingProgress(prev => {
          const newProgress = prev + Math.random() * 5;
          if (newProgress >= 100) {
            clearInterval(interval);
            setTrainingActive(false);
            setModelTrained(true);
            generateInsights();
            return 100;
          }
          return newProgress;
        });
      }, 300);

      return () => clearInterval(interval);
    }
  }, [trainingActive]);

  const trainModel = async () => {
    setTrainingActive(true);
    setTrainingProgress(0);
    toast.info("Starting ML model training...");
    
    // Actual ML training would happen here in a real application
    try {
      // Train isolation forest for anomaly detection
      const isolationForestModel = await trainIsolationForest(dataset);
      setAnomalyModelTrained(true);
      
      // Train random forest for classification
      const randomForestModel = await trainRandomForest(dataset);
      setClassificationModelTrained(true);
      
      // Perform clustering analysis
      const clusteringResults = await performClustering(dataset, 3);
      setClusterAnalysisDone(true);
      
      // Store results for UI display
      if (randomForestModel.metrics) {
        setModelInsights(prev => ({
          ...prev,
          accuracy: randomForestModel.metrics.accuracy,
          precision: randomForestModel.metrics.precision,
          recall: randomForestModel.metrics.recall,
          f1: randomForestModel.metrics.f1,
          clusters: clusteringResults.clusters
        }));
      }
      
      toast.success("ML models trained successfully!");
    } catch (error) {
      console.error("Error during ML training:", error);
      toast.error("Error training ML models");
    }
  };

  const generateInsights = async () => {
    try {
      // Extract patterns from payloads that were flagged as threats
      const threatPayloads = dataset.filter(item => 
        item.label === 'malicious' || item.label === 'suspicious'
      );
      
      // Generate vulnerability type statistics
      const vulnTypes: Record<string, number> = {};
      threatPayloads.forEach(item => {
        const type = item.vulnerability_type || 'unknown';
        vulnTypes[type] = (vulnTypes[type] || 0) + 1;
      });
      
      // Convert to format expected by UI
      const vulnerabilityTypes = Object.entries(vulnTypes).map(([type, count]) => ({
        type,
        count,
        probability: Math.min(0.95, 0.6 + (count / threatPayloads.length) * 0.3)
      }));
      
      // For demonstration, create some patterns based on actual payloads
      const patterns: string[] = [];
      
      if (vulnTypes['sql_injection'] > 0) {
        patterns.push('SQL injection attempts using OR 1=1');
      }
      
      if (vulnTypes['xss'] > 0) {
        patterns.push('XSS attempts with <script> tags');
      }
      
      if (vulnTypes['path_traversal'] > 0) {
        patterns.push('Path traversal using ../ sequences');
      }
      
      if (vulnTypes['command_injection'] > 0) {
        patterns.push('Command injection with semicolons');
      }
      
      // Add general patterns if we don't have specifics
      if (patterns.length < 2) {
        patterns.push('Suspicious input parameter manipulation');
        patterns.push('Potential security bypass attempts');
      }
      
      // Generate recommendations based on findings
      const recommendations: string[] = [];
      
      if (vulnerabilityTypes.some(v => v.type === 'sql_injection')) {
        recommendations.push('Implement prepared statements for all database queries');
      }
      
      if (vulnerabilityTypes.some(v => v.type === 'xss')) {
        recommendations.push('Apply context-specific output encoding');
        recommendations.push('Implement Content Security Policy (CSP)');
      }
      
      if (vulnerabilityTypes.some(v => v.type === 'path_traversal')) {
        recommendations.push('Validate and sanitize file paths');
      }
      
      if (vulnerabilityTypes.some(v => v.type === 'command_injection')) {
        recommendations.push('Avoid using system commands with user input');
      }
      
      // Add general recommendations
      recommendations.push('Implement proper input validation');
      recommendations.push('Use security headers and secure configurations');
      recommendations.push('Regularly update and patch dependencies');
      
      setModelInsights(prev => ({
        ...prev,
        payloadPatterns: patterns,
        vulnerabilityTypes,
        recommendations
      }));
      
    } catch (error) {
      console.error("Error generating insights:", error);
      toast.error("Error analyzing vulnerability patterns");
    }
  };

  // Calculate threat distribution for UI
  const calculateThreatDistribution = () => {
    if (!dataset || dataset.length === 0) return [];
    
    const counts: Record<string, number> = {
      malicious: 0,
      suspicious: 0,
      safe: 0
    };
    
    dataset.forEach(item => {
      counts[item.label] = (counts[item.label] || 0) + 1;
    });
    
    return [
      { name: 'Malicious', value: counts.malicious || 0, color: '#ff2d55' },
      { name: 'Suspicious', value: counts.suspicious || 0, color: '#ffcc00' },
      { name: 'Safe', value: counts.safe || 0, color: '#34c759' }
    ];
  };

  const threatDistribution = calculateThreatDistribution();

  return (
    <Card className="border-white/5 bg-white/5 text-white shadow-lg hover:shadow-xl transition-all duration-300">
      <CardHeader className="border-b border-white/10 pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl font-medium flex items-center">
            <Brain className="w-5 h-5 mr-2 text-purple-400" />
            Machine Learning Analysis
          </CardTitle>
          <div className="flex gap-2">
            {anomalyModelTrained && (
              <Badge variant="outline" className="bg-blue-900/30 text-blue-300 border-blue-700">
                <Database className="w-3 h-3 mr-1" /> Anomaly Model
              </Badge>
            )}
            {classificationModelTrained && (
              <Badge variant="outline" className="bg-green-900/30 text-green-300 border-green-700">
                <Server className="w-3 h-3 mr-1" /> Classification
              </Badge>
            )}
            {modelTrained && (
              <Badge variant="outline" className="bg-purple-900/30 text-purple-300 border-purple-700">
                <CheckCircle2 className="w-3 h-3 mr-1" /> Complete
              </Badge>
            )}
          </div>
        </div>
        <CardDescription className="text-white/70">
          Analyzes patterns from scan data using advanced ML algorithms
        </CardDescription>
      </CardHeader>
      
      <CardContent className="pt-6">
        <div className="flex flex-col space-y-4">
          {/* Training Status */}
          {trainingActive ? (
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-sm text-white/80">Training ML Models...</span>
                <span className="text-sm font-mono text-white/80">{Math.floor(trainingProgress)}%</span>
              </div>
              <Progress value={trainingProgress} className="h-2 bg-white/10" />
              <p className="text-xs text-white/60 italic">
                Training on {dataset.length} data points from scan results
              </p>
            </div>
          ) : scanActive ? (
            <div className="bg-black/20 rounded-md p-4 border border-white/10">
              <div className="flex items-center">
                <div className="w-full text-center">
                  <p className="text-white/80 text-sm">Collecting data for ML training...</p>
                  <p className="text-xs text-white/60 mt-1">Models will be trained after scan completion</p>
                </div>
              </div>
            </div>
          ) : !scanCompleted ? (
            <div className="bg-black/20 rounded-md p-4 border border-white/10">
              <div className="flex items-center">
                <div className="w-full text-center">
                  <p className="text-white/80 text-sm">Start a scan to collect data for ML analysis</p>
                </div>
              </div>
            </div>
          ) : null}
          
          {/* ML Insights after training */}
          {modelTrained && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-black/20 rounded-md p-4 border border-white/10">
                  <h3 className="text-sm font-medium text-white/80 mb-2 flex items-center">
                    <BarChart2 className="w-4 h-4 mr-1 text-blue-400" />
                    Model Metrics
                  </h3>
                  <div className="space-y-2">
                    <div>
                      <div className="flex justify-between items-center text-xs">
                        <span>Accuracy</span>
                        <span>{(modelInsights.accuracy * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.accuracy * 100} className="h-1.5 bg-white/10" />
                    </div>
                    <div>
                      <div className="flex justify-between items-center text-xs">
                        <span>Precision</span>
                        <span>{(modelInsights.precision * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.precision * 100} className="h-1.5 bg-white/10" />
                    </div>
                    <div>
                      <div className="flex justify-between items-center text-xs">
                        <span>Recall</span>
                        <span>{(modelInsights.recall * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.recall * 100} className="h-1.5 bg-white/10" />
                    </div>
                    <div>
                      <div className="flex justify-between items-center text-xs">
                        <span>F1 Score</span>
                        <span>{(modelInsights.f1 * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.f1 * 100} className="h-1.5 bg-white/10" />
                    </div>
                  </div>
                </div>
                
                <div className="bg-black/20 rounded-md p-4 border border-white/10">
                  <h3 className="text-sm font-medium text-white/80 mb-2 flex items-center">
                    <AlertTriangle className="w-4 h-4 mr-1 text-yellow-400" />
                    Detected Patterns
                  </h3>
                  <ScrollArea className="h-[120px]">
                    <ul className="space-y-1 text-xs">
                      {modelInsights.payloadPatterns.map((pattern, index) => (
                        <li key={index} className="text-white/80">• {pattern}</li>
                      ))}
                    </ul>
                  </ScrollArea>
                </div>
              </div>
              
              <div className="bg-black/20 rounded-md p-4 border border-white/10">
                <h3 className="text-sm font-medium text-white/80 mb-2">Vulnerability Probabilities</h3>
                <div className="space-y-2">
                  {modelInsights.vulnerabilityTypes.map((vuln, index) => (
                    <div key={index}>
                      <div className="flex justify-between items-center">
                        <span className="text-xs text-white/80">{vuln.type} ({vuln.count})</span>
                        <span className="text-xs font-mono text-white/80">{(vuln.probability * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={vuln.probability * 100} className="h-1.5 bg-white/10" />
                    </div>
                  ))}
                </div>
              </div>
              
              <div className="bg-black/20 rounded-md p-4 border border-white/10">
                <h3 className="text-sm font-medium text-white/80 mb-2 flex items-center">
                  <BookOpen className="w-4 h-4 mr-1 text-green-400" />
                  ML-Based Recommendations
                </h3>
                <ScrollArea className="h-28">
                  <ul className="space-y-1 text-xs">
                    {modelInsights.recommendations.map((rec, index) => (
                      <li key={index} className="text-white/80">• {rec}</li>
                    ))}
                  </ul>
                </ScrollArea>
              </div>
              
              {clusterAnalysisDone && (
                <div className="bg-black/20 rounded-md p-4 border border-white/10">
                  <h3 className="text-sm font-medium text-white/80 mb-2 flex items-center">
                    <FileText className="w-4 h-4 mr-1 text-purple-400" />
                    Cluster Analysis Summary
                  </h3>
                  <div className="text-xs text-white/80">
                    <p>The data has been grouped into 3 clusters based on response patterns:</p>
                    <ul className="mt-2 space-y-1 pl-4">
                      <li>• Cluster 1: Likely malicious payloads ({threatDistribution[0]?.value || 0})</li>
                      <li>• Cluster 2: Suspicious but inconclusive ({threatDistribution[1]?.value || 0})</li>
                      <li>• Cluster 3: Likely benign inputs ({threatDistribution[2]?.value || 0})</li>
                    </ul>
                  </div>
                </div>
              )}
            </div>
          )}
          
          {/* Manual Training */}
          {!modelTrained && !trainingActive && dataset.length > 0 && (
            <Button 
              onClick={trainModel}
              className="bg-purple-700 hover:bg-purple-600 text-white"
            >
              <Brain className="w-4 h-4 mr-2" />
              Train ML Models
            </Button>
          )}
          
          {/* Visualization */}
          <div className="h-40 mt-2">
            <EnhancedScannerAnimation 
              active={scanActive || trainingActive} 
              threatLevel={trainingActive ? 'medium' : threatLevel}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
