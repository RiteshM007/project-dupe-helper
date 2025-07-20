import * as React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { mlApiService } from '@/services/mlApi';
import { fuzzingService } from '@/services/fuzzingService';
import { supabase } from '@/integrations/supabase/client';
import { 
  Brain, 
  Upload, 
  Download, 
  Play, 
  BarChart3, 
  Shield, 
  Target,
  AlertTriangle,
  CheckCircle,
  Clock,
  Database,
  TrendingUp
} from 'lucide-react';

interface TrainingResult {
  id: string;
  accuracy: number;
  model_performance: any;
  dataset_size: number;
  patterns_detected: number;
  training_duration: number;
  created_at: string;
}

interface PayloadResult {
  id: string;
  payload: string;
  vulnerability_type: string;
  effectiveness_score: number;
  created_at: string;
}

const EnhancedMLAnalysis: React.FC = () => {
  const [isTraining, setIsTraining] = React.useState(false);
  const [isGenerating, setIsGenerating] = React.useState(false);
  const [dataset, setDataset] = React.useState<any[]>([]);
  const [trainingResults, setTrainingResults] = React.useState<TrainingResult[]>([]);
  const [generatedPayloads, setGeneratedPayloads] = React.useState<PayloadResult[]>([]);
  const [currentTraining, setCurrentTraining] = React.useState<any>(null);
  const [targetUrl, setTargetUrl] = React.useState('');
  const [vulnerabilityType, setVulnerabilityType] = React.useState('general');
  const [payloadCount, setPayloadCount] = React.useState(10);
  const { toast } = useToast();

  // Load user's ML training history
  React.useEffect(() => {
    loadTrainingHistory();
    loadPayloadHistory();
  }, []);

  const loadTrainingHistory = async () => {
    try {
      const { data, error } = await supabase
        .from('ml_training_results')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) throw error;
      setTrainingResults(data?.map(item => ({
        id: item.id,
        accuracy: item.accuracy,
        model_performance: {
          accuracy: item.accuracy,
          precision: item.precision_score,
          recall: item.recall_score,
          f1_score: item.f1_score
        },
        dataset_size: item.dataset_size,
        patterns_detected: item.patterns_detected,
        training_duration: item.training_duration,
        created_at: item.created_at
      })) || []);
    } catch (error: any) {
      console.error('Error loading training history:', error);
    }
  };

  const loadPayloadHistory = async () => {
    try {
      const { data, error } = await supabase
        .from('ml_payloads')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      setGeneratedPayloads(data || []);
    } catch (error: any) {
      console.error('Error loading payload history:', error);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.txt') && !file.name.endsWith('.csv')) {
      toast({
        title: "Invalid file type",
        description: "Please upload a .txt or .csv file",
        variant: "destructive"
      });
      return;
    }

    try {
      const text = await file.text();
      const lines = text.split('\n').filter(line => line.trim());
      
      const parsedDataset = lines.map((line, index) => {
        const parts = line.split(',');
        return {
          id: index,
          payload: parts[0]?.trim() || '',
          label: parts[1]?.trim() || 'unknown',
          response_code: parseInt(parts[2]) || 200
        };
      });

      setDataset(parsedDataset);
      toast({
        title: "Dataset uploaded",
        description: `Successfully loaded ${parsedDataset.length} samples`
      });
    } catch (error: any) {
      toast({
        title: "Upload failed",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleTrainModel = async () => {
    if (dataset.length === 0) {
      toast({
        title: "No dataset",
        description: "Please upload a dataset first",
        variant: "destructive"
      });
      return;
    }

    setIsTraining(true);
    try {
      const result = await mlApiService.runAnalysis(dataset);
      
      if (result.status === 'success') {
        setCurrentTraining(result);
        await loadTrainingHistory(); // Refresh history
        toast({
          title: "Training completed",
          description: `Model trained with ${result.accuracy?.toFixed(2)}% accuracy`
        });
      } else {
        throw new Error(result.message || 'Training failed');
      }
    } catch (error: any) {
      toast({
        title: "Training failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsTraining(false);
    }
  };

  const handleGeneratePayloads = async () => {
    setIsGenerating(true);
    try {
      const result = await mlApiService.generatePayloads(
        vulnerabilityType, 
        payloadCount, 
        currentTraining?.training_result_id
      );
      
      if (result.status === 'success') {
        await loadPayloadHistory(); // Refresh payload history
        toast({
          title: "Payloads generated",
          description: `Generated ${result.count} payloads for ${vulnerabilityType}`
        });
      } else {
        throw new Error(result.message || 'Payload generation failed');
      }
    } catch (error: any) {
      toast({
        title: "Generation failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleStartFuzzing = async () => {
    if (!targetUrl) {
      toast({
        title: "No target URL",
        description: "Please enter a target URL",
        variant: "destructive"
      });
      return;
    }

    try {
      const session = await fuzzingService.createSession(targetUrl, {
        vulnerability_types: [vulnerabilityType],
        payload_count: payloadCount
      });

      const latestPayloads = generatedPayloads
        .filter(p => p.vulnerability_type === vulnerabilityType)
        .slice(0, payloadCount)
        .map(p => p.payload);

      await fuzzingService.startSession(session.sessionId, latestPayloads);

      toast({
        title: "Fuzzing started",
        description: `Session ${session.sessionId} started against ${targetUrl}`
      });
    } catch (error: any) {
      toast({
        title: "Fuzzing failed",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const exportResults = () => {
    const exportData = {
      training_results: trainingResults,
      generated_payloads: generatedPayloads,
      current_training: currentTraining,
      export_timestamp: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ml_analysis_results_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-4">
        <Brain className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Enhanced ML Analysis</h1>
          <p className="text-muted-foreground">
            Advanced machine learning-powered security analysis with full data persistence
          </p>
        </div>
      </div>

      <Tabs defaultValue="training" className="space-y-6">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="training">Training</TabsTrigger>
          <TabsTrigger value="payloads">Payloads</TabsTrigger>
          <TabsTrigger value="fuzzing">Fuzzing</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
        </TabsList>

        <TabsContent value="training" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="h-5 w-5" />
                Dataset Upload & Training
              </CardTitle>
              <CardDescription>
                Upload your dataset and train ML models for vulnerability detection
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4">
                <div>
                  <Label htmlFor="dataset-upload">Upload Dataset (CSV/TXT)</Label>
                  <Input
                    id="dataset-upload"
                    type="file"
                    accept=".txt,.csv"
                    onChange={handleFileUpload}
                    className="cursor-pointer"
                  />
                  <p className="text-sm text-muted-foreground mt-1">
                    Format: payload,label,response_code (one per line)
                  </p>
                </div>

                {dataset.length > 0 && (
                  <Alert>
                    <Database className="h-4 w-4" />
                    <AlertDescription>
                      Dataset loaded: {dataset.length} samples ready for training
                    </AlertDescription>
                  </Alert>
                )}

                <Button 
                  onClick={handleTrainModel} 
                  disabled={isTraining || dataset.length === 0}
                  className="w-full"
                >
                  {isTraining ? (
                    <>
                      <Clock className="h-4 w-4 mr-2 animate-spin" />
                      Training Model...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Train ML Model
                    </>
                  )}
                </Button>

                {isTraining && (
                  <div className="space-y-2">
                    <Progress value={75} className="w-full" />
                    <p className="text-sm text-center text-muted-foreground">
                      Training in progress... This may take a few minutes.
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {currentTraining && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  Training Results
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-primary">
                      {(currentTraining.accuracy * 100).toFixed(1)}%
                    </div>
                    <div className="text-sm text-muted-foreground">Accuracy</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-primary">
                      {currentTraining.dataset_size}
                    </div>
                    <div className="text-sm text-muted-foreground">Samples</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-primary">
                      {currentTraining.patterns?.length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Patterns</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-primary">
                      {(currentTraining.anomaly_detection_rate * 100).toFixed(1)}%
                    </div>
                    <div className="text-sm text-muted-foreground">Anomaly Rate</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="payloads" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-5 w-5" />
                Payload Generation
              </CardTitle>
              <CardDescription>
                Generate intelligent payloads based on trained models
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="vuln-type">Vulnerability Type</Label>
                  <select
                    id="vuln-type"
                    className="w-full p-2 border rounded-md"
                    value={vulnerabilityType}
                    onChange={(e) => setVulnerabilityType(e.target.value)}
                  >
                    <option value="general">General</option>
                    <option value="sql">SQL Injection</option>
                    <option value="xss">Cross-Site Scripting</option>
                    <option value="command">Command Injection</option>
                    <option value="path">Path Traversal</option>
                  </select>
                </div>
                <div>
                  <Label htmlFor="payload-count">Payload Count</Label>
                  <Input
                    id="payload-count"
                    type="number"
                    min="1"
                    max="100"
                    value={payloadCount}
                    onChange={(e) => setPayloadCount(parseInt(e.target.value))}
                  />
                </div>
                <div className="flex items-end">
                  <Button 
                    onClick={handleGeneratePayloads}
                    disabled={isGenerating}
                    className="w-full"
                  >
                    {isGenerating ? (
                      <>
                        <Clock className="h-4 w-4 mr-2 animate-spin" />
                        Generating...
                      </>
                    ) : (
                      <>
                        <Brain className="h-4 w-4 mr-2" />
                        Generate Payloads
                      </>
                    )}
                  </Button>
                </div>
              </div>

              {generatedPayloads.length > 0 && (
                <div className="space-y-2">
                  <h4 className="font-semibold">Recent Generated Payloads:</h4>
                  <div className="max-h-60 overflow-y-auto space-y-2">
                    {generatedPayloads.slice(0, 10).map((payload) => (
                      <div key={payload.id} className="p-3 bg-muted rounded-lg">
                        <div className="flex items-center justify-between">
                          <code className="text-sm font-mono bg-background px-2 py-1 rounded">
                            {payload.payload}
                          </code>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{payload.vulnerability_type}</Badge>
                            <Badge variant="secondary">
                              {(payload.effectiveness_score * 100).toFixed(0)}%
                            </Badge>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="fuzzing" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Automated Fuzzing
              </CardTitle>
              <CardDescription>
                Start automated fuzzing sessions with generated payloads
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="target-url">Target URL</Label>
                <Input
                  id="target-url"
                  type="url"
                  placeholder="https://example.com/vulnerable-endpoint"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>

              <Button 
                onClick={handleStartFuzzing}
                disabled={!targetUrl || generatedPayloads.length === 0}
                className="w-full"
              >
                <Play className="h-4 w-4 mr-2" />
                Start Fuzzing Session
              </Button>

              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  Only test applications you own or have explicit permission to test.
                  Unauthorized testing may be illegal.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history" className="space-y-4">
          <div className="grid gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Training History</CardTitle>
              </CardHeader>
              <CardContent>
                {trainingResults.length === 0 ? (
                  <p className="text-muted-foreground">No training results yet</p>
                ) : (
                  <div className="space-y-2">
                    {trainingResults.map((result) => (
                      <div key={result.id} className="p-3 border rounded-lg">
                        <div className="flex justify-between items-center">
                          <div>
                            <div className="font-semibold">
                              Accuracy: {(result.accuracy * 100).toFixed(1)}%
                            </div>
                            <div className="text-sm text-muted-foreground">
                              {result.dataset_size} samples • {result.patterns_detected} patterns
                            </div>
                          </div>
                          <div className="text-sm text-muted-foreground">
                            {new Date(result.created_at).toLocaleDateString()}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Total Models Trained</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-primary">
                  {trainingResults.length}
                </div>
                <p className="text-sm text-muted-foreground">
                  Lifetime training sessions
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Payloads Generated</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-primary">
                  {generatedPayloads.length}
                </div>
                <p className="text-sm text-muted-foreground">
                  Total unique payloads
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Average Accuracy</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-primary">
                  {trainingResults.length > 0 
                    ? (trainingResults.reduce((sum, r) => sum + r.accuracy, 0) / trainingResults.length * 100).toFixed(1)
                    : 0}%
                </div>
                <p className="text-sm text-muted-foreground">
                  Model performance metric
                </p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={exportResults}>
          <Download className="h-4 w-4 mr-2" />
          Export Results
        </Button>
      </div>
    </div>
  );
};

export default EnhancedMLAnalysis;