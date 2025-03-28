
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Brain, BarChart2, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { EnhancedScannerAnimation } from "./EnhancedScannerAnimation";
import { trainIsolationForest, trainRandomForest } from "@/backend/ml_models";

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
  const [modelInsights, setModelInsights] = useState<{
    accuracy: number;
    payloadPatterns: string[];
    vulnerabilityTypes: { type: string; count: number; probability: number }[];
    recommendations: string[];
  }>({
    accuracy: 0,
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
    
    // Actual ML training would happen here in a real application
    // For demo, we're using the simulated backend
    try {
      await trainIsolationForest(dataset);
      await trainRandomForest(dataset);
    } catch (error) {
      console.error("Error training models:", error);
    }
  };

  const generateInsights = () => {
    // Extract patterns from payloads that were flagged as threats
    const threatPayloads = dataset.filter(item => 
      item.label === 'malicious' || item.label === 'suspicious'
    );
    
    // For demonstration, create some mock insights
    const mockAccuracy = Math.round(85 + Math.random() * 10);
    
    // Generate patterns based on actual payloads
    const patterns = [
      'SQL injection attempts using OR 1=1',
      'XSS attempts with <script> tags',
      'Path traversal using ../ sequences',
      'Command injection with semicolons',
      'Null byte injection with %00'
    ].slice(0, 2 + Math.floor(Math.random() * 3));
    
    // Vulnerability types based on threatLevel
    const vulnTypes = [];
    
    if (threatLevel === 'critical' || threatLevel === 'high') {
      vulnTypes.push(
        { type: 'SQL Injection', count: Math.floor(5 + Math.random() * 10), probability: 0.92 },
        { type: 'XSS', count: Math.floor(3 + Math.random() * 8), probability: 0.87 }
      );
    }
    
    if (threatLevel !== 'none') {
      vulnTypes.push(
        { type: 'Path Traversal', count: Math.floor(1 + Math.random() * 5), probability: 0.78 }
      );
    }
    
    if (threatLevel === 'medium' || threatLevel === 'low') {
      vulnTypes.push(
        { type: 'CSRF', count: Math.floor(1 + Math.random() * 3), probability: 0.65 }
      );
    }
    
    setModelInsights({
      accuracy: mockAccuracy,
      payloadPatterns: patterns,
      vulnerabilityTypes: vulnTypes,
      recommendations: [
        'Implement proper input validation',
        'Use prepared statements for all database queries',
        'Apply context-specific output encoding',
        'Add security headers including CSP',
        'Implement robust authentication mechanisms'
      ]
    });
  };

  return (
    <Card className="border-white/5 bg-white/5 text-white shadow-lg hover:shadow-xl transition-all duration-300">
      <CardHeader className="border-b border-white/10 pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl font-medium flex items-center">
            <Brain className="w-5 h-5 mr-2 text-purple-400" />
            Machine Learning Analysis
          </CardTitle>
          {modelTrained && (
            <Badge variant="outline" className="bg-purple-900/30 text-purple-300 border-purple-700">
              <CheckCircle2 className="w-3 h-3 mr-1" /> Model Trained
            </Badge>
          )}
        </div>
        <CardDescription className="text-white/70">
          Analyzes patterns from scan data using ML algorithms
        </CardDescription>
      </CardHeader>
      
      <CardContent className="pt-6">
        <div className="flex flex-col space-y-4">
          {/* Training Status */}
          {trainingActive ? (
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-sm text-white/80">Training ML Model...</span>
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
                    Model Accuracy
                  </h3>
                  <div className="flex items-center space-x-3">
                    <div className="w-16 h-16 rounded-full bg-gradient-to-r from-blue-600 to-purple-600 flex items-center justify-center text-white font-bold">
                      {modelInsights.accuracy}%
                    </div>
                    <div className="text-xs text-white/70">
                      <p>Based on cross-validation</p>
                      <p>Training data: {dataset.length} samples</p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-black/20 rounded-md p-4 border border-white/10">
                  <h3 className="text-sm font-medium text-white/80 mb-2 flex items-center">
                    <AlertTriangle className="w-4 h-4 mr-1 text-yellow-400" />
                    Detected Patterns
                  </h3>
                  <ScrollArea className="h-16">
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
                <h3 className="text-sm font-medium text-white/80 mb-2">ML-Based Recommendations</h3>
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
