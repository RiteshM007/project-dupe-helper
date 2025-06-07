import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Toggle } from '@/components/ui/toggle';
import { Brain, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface MachineLearningScannerProps {
  scanActive: boolean;
  scanCompleted: boolean;
  dataset: any[];
  threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
}

export const MachineLearningScanner: React.FC<MachineLearningScannerProps> = ({ 
  scanActive, 
  scanCompleted, 
  dataset, 
  threatLevel 
}) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [progress, setProgress] = useState(0);
  const [confidence, setConfidence] = useState(75);
  const [detectedPatterns, setDetectedPatterns] = useState<string[]>([]);
  const { toast } = useToast();

  useEffect(() => {
    if (scanActive && !isAnalyzing) {
      startAnalysis();
    }
  }, [scanActive, isAnalyzing]);

  const startAnalysis = () => {
    setIsAnalyzing(true);
    setAnalysisComplete(false);
    setProgress(0);
    setDetectedPatterns([]);

    const interval = setInterval(() => {
      setProgress(prev => {
        const newProgress = Math.min(prev + 10, 95);
        if (newProgress >= 95) {
          clearInterval(interval);
          completeAnalysis();
        }
        return newProgress;
      });
    }, 500);

    // Simulate pattern detection
    setTimeout(() => {
      setDetectedPatterns(['XSS', 'SQL Injection', 'CSRF']);
    }, 1500);
  };

  const completeAnalysis = useCallback(() => {
    setIsAnalyzing(false);
    setProgress(100);
    setAnalysisComplete(true);
    
    const analysisResults = {
      sessionId: `ml-${Date.now()}`,
      patterns: detectedPatterns.length,
      accuracy: confidence,
      riskLevel: threatLevel,
      type: 'machine-learning',
      target: 'ML Analysis',
      targetUrl: 'ML Analysis',
      vulnerabilities: detectedPatterns.length,
      payloadsTested: Math.floor(confidence),
      duration: '2m 30s',
      severity: detectedPatterns.length > 2 ? 'high' : detectedPatterns.length > 0 ? 'medium' : 'low'
    };

    console.log('MachineLearningScanner: Completing analysis with results:', analysisResults);
    
    // Dispatch multiple event types to ensure compatibility
    const mlCompleteEvent = new CustomEvent('mlAnalysisComplete', { detail: analysisResults });
    const scanCompleteEvent = new CustomEvent('scanComplete', { detail: analysisResults });
    const globalScanCompleteEvent = new CustomEvent('globalScanComplete', { detail: analysisResults });
    
    window.dispatchEvent(mlCompleteEvent);
    window.dispatchEvent(scanCompleteEvent);
    window.dispatchEvent(globalScanCompleteEvent);
    
    console.log('MachineLearningScanner: Dispatched ML complete events');
    
    toast({
      title: "ML Analysis Complete",
      description: `Detected ${detectedPatterns.length} patterns with ${confidence}% confidence`,
    });
  }, [detectedPatterns.length, confidence, threatLevel, toast]);

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-500';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-green-500';
      default: return 'text-gray-500';
    }
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-purple-900/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Brain className="h-5 w-5" />
          ML Analysis
        </CardTitle>
        <CardDescription>Automated threat pattern detection</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <span>Status:</span>
          <Badge variant={isAnalyzing ? "default" : "secondary"}>
            {isAnalyzing ? "Analyzing" : analysisComplete ? "Complete" : "Ready"}
          </Badge>
        </div>
        <Progress value={progress} className="h-4" />
        <div className="flex items-center justify-between">
          <span>Confidence:</span>
          <span className="font-medium">{confidence}%</span>
        </div>
        <div>
          <h3 className="text-sm font-medium">Detected Patterns:</h3>
          {detectedPatterns.length === 0 ? (
            <p className="text-muted-foreground text-sm">No patterns detected</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {detectedPatterns.map((pattern, index) => (
                <Badge key={index} variant="outline">{pattern}</Badge>
              ))}
            </div>
          )}
        </div>
        <div className="flex items-center justify-between">
          <span>Threat Level:</span>
          <span className={`font-medium ${getThreatLevelColor(threatLevel)}`}>{threatLevel}</span>
        </div>
      </CardContent>
    </Card>
  );
};
