import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Brain, BarChart2, AlertTriangle, CheckCircle2, FileText, BookOpen, Server, Database, Zap } from 'lucide-react';
import { EnhancedScannerAnimation } from "./EnhancedScannerAnimation";
import { trainIsolationForest, trainRandomForest, generateReport, performClustering, EnhancedPayloadGenerator } from "@/backend/enhanced_ml_models";
import { toast } from 'sonner';

interface EnhancedMLScannerProps {
  scanActive: boolean;
  scanCompleted: boolean;
  dataset: any[];
  threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
}

export const EnhancedMLScanner: React.FC<EnhancedMLScannerProps> = ({
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
  const [payloadGeneratorReady, setPayloadGeneratorReady] = useState(false);
  const [collectedDataset, setCollectedDataset] = useState<any[]>([]);
  const [payloadGenerator, setPayloadGenerator] = useState<EnhancedPayloadGenerator | null>(null);
  const [modelInsights, setModelInsights] = useState<{
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    anomalyRate: number;
    payloadPatterns: string[];
    vulnerabilityTypes: { type: string; count: number; probability: number }[];
    recommendations: string[];
    clusters?: any[];
    generatedPayloads: string[];
  }>({
    accuracy: 0,
    precision: 0,
    recall: 0,
    f1: 0,
    anomalyRate: 0,
    payloadPatterns: [],
    vulnerabilityTypes: [],
    recommendations: [],
    generatedPayloads: []
  });

  // Initialize payload generator
  useEffect(() => {
    const initGenerator = async () => {
      try {
        const generator = new EnhancedPayloadGenerator();
        setPayloadGenerator(generator);
        setPayloadGeneratorReady(true);
      } catch (error) {
        console.error("Failed to initialize payload generator:", error);
      }
    };
    initGenerator();
  }, []);

  // Listen for dataset entries from fuzzer
  useEffect(() => {
    const handleDatasetEntry = (event: CustomEvent) => {
      setCollectedDataset(prev => [...prev, event.detail]);
    };

    const handleScanComplete = () => {
      setTimeout(() => {
        if (collectedDataset.length > 0) {
          trainEnhancedModels();
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
      trainEnhancedModels();
    }
  }, [scanCompleted, dataset, collectedDataset, modelTrained]);

  // Simulate training progress
  useEffect(() => {
    if (trainingActive) {
      const interval = setInterval(() => {
        setTrainingProgress(prev => {
          const newProgress = prev + Math.random() * 3 + 1;
          if (newProgress >= 100) {
            clearInterval(interval);
            setTrainingActive(false);
            setModelTrained(true);
            generateEnhancedInsights();
            return 100;
          }
          return newProgress;
        });
      }, 400);

      return () => clearInterval(interval);
    }
  }, [trainingActive]);

  const trainEnhancedModels = async () => {
    setTrainingActive(true);
    setTrainingProgress(0);
    toast.info("Starting enhanced ML model training with scan results...");
    
    const combinedDataset = [...dataset, ...collectedDataset];
    
    try {
      // Train isolation forest for anomaly detection
      const isolationResult = await trainIsolationForest(combinedDataset);
      setAnomalyModelTrained(true);
      
      // Train random forest for classification
      const randomForestResult = await trainRandomForest(combinedDataset);
      setClassificationModelTrained(true);
      
      // Perform clustering analysis
      const clusteringResults = await performClustering(combinedDataset, 3);
      setClusterAnalysisDone(true);
      
      // Train payload generator
      if (payloadGenerator) {
        await payloadGenerator.analyzeDataset(combinedDataset);
        const generatedPayloads = await payloadGenerator.generatePayloads(5);
        
        setModelInsights(prev => ({
          ...prev,
          accuracy: randomForestResult.metrics.accuracy,
          precision: randomForestResult.metrics.precision,
          recall: randomForestResult.metrics.recall,
          f1: randomForestResult.metrics.f1,
          anomalyRate: isolationResult.metrics.anomalyRate,
          clusters: clusteringResults.clusters,
          generatedPayloads
        }));
      }
      
      toast.success("Enhanced ML models trained successfully!");
    } catch (error) {
      console.error("Error during enhanced ML training:", error);
      toast.error("Error training enhanced ML models");
    }
  };

  const generateEnhancedInsights = async () => {
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
      
      // Enhanced pattern detection
      const patterns: string[] = [];
      
      if (vulnTypes['sql_injection'] > 0) {
        patterns.push('SQL injection with OR/UNION operators');
        patterns.push('Database enumeration attempts');
      }
      
      if (vulnTypes['xss'] > 0) {
        patterns.push('XSS with script injection');
        patterns.push('DOM manipulation attempts');
      }
      
      if (vulnTypes['path_traversal'] > 0) {
        patterns.push('Directory traversal patterns');
        patterns.push('File inclusion attempts');
      }
      
      if (vulnTypes['command_injection'] > 0) {
        patterns.push('Command execution via shell metacharacters');
        patterns.push('System command chaining');
      }
      
      // Enhanced recommendations
      const recommendations: string[] = [
        'Implement parameterized queries to prevent SQL injection',
        'Use Content Security Policy (CSP) headers',
        'Sanitize and validate all user inputs',
        'Implement proper file path validation',
        'Use whitelist-based input validation',
        'Deploy Web Application Firewall (WAF)',
        'Regular security code reviews and testing',
        'Implement rate limiting and anomaly detection'
      ];
      
      // Generate contextual payloads for different vulnerability types
      if (payloadGenerator) {
        const contextualPayloads: string[] = [];
        for (const vulnType of Object.keys(vulnTypes)) {
          const typePayloads = await payloadGenerator.generateContextualPayloads(vulnType, 2);
          contextualPayloads.push(...typePayloads);
        }
        
        setModelInsights(prev => ({
          ...prev,
          payloadPatterns: patterns,
          vulnerabilityTypes,
          recommendations,
          generatedPayloads: [...prev.generatedPayloads, ...contextualPayloads]
        }));
      } else {
        setModelInsights(prev => ({
          ...prev,
          payloadPatterns: patterns,
          vulnerabilityTypes,
          recommendations
        }));
      }
      
    } catch (error) {
      console.error("Error generating enhanced insights:", error);
      toast.error("Error analyzing vulnerability patterns");
    }
  };

  const generateNewPayloads = async () => {
    if (!payloadGenerator) return;
    
    try {
      toast.info("Generating new payloads...");
      const newPayloads = await payloadGenerator.generatePayloads(10);
      
      setModelInsights(prev => ({
        ...prev,
        generatedPayloads: [...prev.generatedPayloads, ...newPayloads]
      }));
      
      toast.success(`Generated ${newPayloads.length} new payloads!`);
    } catch (error) {
      console.error("Error generating payloads:", error);
      toast.error("Failed to generate new payloads");
    }
  };

  return (
    <Card className="border-white/5 bg-white/5 text-white shadow-lg hover:shadow-xl transition-all duration-300">
      <CardHeader className="border-b border-white/10 pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl font-medium flex items-center">
            <Brain className="w-5 h-5 mr-2 text-purple-400" />
            Enhanced ML Analysis
          </CardTitle>
          <div className="flex gap-2">
            {anomalyModelTrained && (
              <Badge variant="outline" className="bg-blue-900/30 text-blue-300 border-blue-700">
                <Database className="w-3 h-3 mr-1" /> Anomaly
              </Badge>
            )}
            {classificationModelTrained && (
              <Badge variant="outline" className="bg-green-900/30 text-green-300 border-green-700">
                <Server className="w-3 h-3 mr-1" /> Classification
              </Badge>
            )}
            {payloadGeneratorReady && (
              <Badge variant="outline" className="bg-orange-900/30 text-orange-300 border-orange-700">
                <Zap className="w-3 h-3 mr-1" /> Generator
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
          Advanced ML analysis with enhanced payload generation capabilities
        </CardDescription>
      </CardHeader>
      
      <CardContent className="pt-6">
        <div className="flex flex-col space-y-4">
          {/* Training Status */}
          {trainingActive ? (
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-sm text-white/80">Training Enhanced ML Models...</span>
                <span className="text-sm font-mono text-white/80">{Math.floor(trainingProgress)}%</span>
              </div>
              <Progress value={trainingProgress} />
              <p className="text-xs text-white/60 italic">
                Training on {collectedDataset.length + dataset.length} data points with enhanced algorithms
              </p>
            </div>
          ) : scanActive ? (
            <div className="bg-black/20 rounded-md p-4 border border-white/10">
              <div className="flex items-center">
                <div className="w-full text-center">
                  <p className="text-white/80 text-sm">Collecting data for enhanced ML training...</p>
                  <p className="text-xs text-white/60 mt-1">Enhanced models will be trained after scan completion</p>
                </div>
              </div>
            </div>
          ) : !scanCompleted && collectedDataset.length === 0 ? (
            <div className="bg-black/20 rounded-md p-4 border border-white/10">
              <div className="flex items-center">
                <div className="w-full text-center">
                  <p className="text-white/80 text-sm">Start a scan to collect data for enhanced ML analysis</p>
                </div>
              </div>
            </div>
          ) : null}
          
          {/* Enhanced ML Insights */}
          {modelTrained && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-black/20 rounded-md p-4 border border-white/10">
                  <h3 className="text-sm font-medium text-white/80 mb-2 flex items-center">
                    <BarChart2 className="w-4 h-4 mr-1 text-blue-400" />
                    Enhanced Model Metrics
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
                        <span>Anomaly Rate</span>
                        <span>{(modelInsights.anomalyRate * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={modelInsights.anomalyRate * 100} />
                    </div>
                  </div>
                </div>
                
                <div className="bg-black/20 rounded-md p-4 border border-white/10">
                  <h3 className="text-sm font-medium text-white/80 mb-2 flex items-center">
                    <AlertTriangle className="w-4 h-4 mr-1 text-yellow-400" />
                    Enhanced Pattern Detection
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
                <div className="flex justify-between items-center mb-2">
                  <h3 className="text-sm font-medium text-white/80">Generated Payloads</h3>
                  <Button 
                    onClick={generateNewPayloads}
                    size="sm"
                    className="bg-orange-700 hover:bg-orange-600 text-white"
                  >
                    <Zap className="w-3 h-3 mr-1" />
                    Generate More
                  </Button>
                </div>
                <ScrollArea className="h-32">
                  <div className="space-y-1">
                    {modelInsights.generatedPayloads.map((payload, index) => (
                      <div key={index} className="text-xs font-mono text-white/80 bg-black/30 p-2 rounded">
                        {payload}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </div>
              
              <div className="bg-black/20 rounded-md p-4 border border-white/10">
                <h3 className="text-sm font-medium text-white/80 mb-2 flex items-center">
                  <BookOpen className="w-4 h-4 mr-1 text-green-400" />
                  Enhanced Recommendations
                </h3>
                <ScrollArea className="h-28">
                  <ul className="space-y-1 text-xs">
                    {modelInsights.recommendations.map((rec, index) => (
                      <li key={index} className="text-white/80">• {rec}</li>
                    ))}
                  </ul>
                </ScrollArea>
              </div>
            </div>
          )}
          
          {/* Manual Training */}
          {!modelTrained && !trainingActive && (collectedDataset.length > 0 || dataset.length > 0) && (
            <Button 
              onClick={trainEnhancedModels}
              className="bg-purple-700 hover:bg-purple-600 text-white"
            >
              <Brain className="w-4 h-4 mr-2" />
              Train Enhanced ML Models with {collectedDataset.length + dataset.length} Data Points
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
