import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { MLAnalysisDashboard } from '@/components/dashboard/MLAnalysisDashboard';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Brain, Database, BarChart2, Zap, Upload, Download, FileText } from 'lucide-react';
import { mlApi } from '@/services/api';
import { toast } from 'sonner';
import { useSocket } from '@/context/SocketContext';

const MachineLearning = () => {
  const [dataset, setDataset] = useState<any[]>([]);
  const [datasetFileName, setDatasetFileName] = useState<string>('');
  const [isTraining, setIsTraining] = useState(false);
  const [isModelTrained, setIsModelTrained] = useState(false);
  const [trainingResults, setTrainingResults] = useState<any>(null);
  const [generatedPayloads, setGeneratedPayloads] = useState<string[]>([]);
  const { socket } = useSocket();

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file type
    const validTypes = ['.txt', '.csv'];
    const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
    
    if (!validTypes.includes(fileExtension)) {
      toast.error("Please upload a .txt or .csv file");
      return;
    }

    try {
      toast.info("Uploading and training with file...");
      
      // Use the backend API to train directly with the file
      const response = await mlApi.trainClassifierWithFile(file);
      
      console.log("🎯 File training response:", response);
      
      if (response.success) {
        // Create a mock dataset for UI display
        const mockDataset = Array.from({ length: response.dataset_size }, (_, i) => ({
          id: i,
          payload: `sample_${i}`,
          label: Math.random() > 0.7 ? 'malicious' : 'safe'
        }));
        
        setDataset(mockDataset);
        setDatasetFileName(file.name);
        setTrainingResults(response);
        setIsModelTrained(true);
        
        toast.success(`Model trained successfully! Accuracy: ${(response.accuracy * 100).toFixed(1)}%`);
        
        // Emit Socket.IO event
        if (socket) {
          socket.emit('mlAnalysisComplete', {
            accuracy: response.accuracy,
            dataset_size: response.dataset_size,
            timestamp: response.last_trained
          });
        }
      } else {
        throw new Error(response.error || 'Training failed');
      }
      
    } catch (error: any) {
      console.error("Error uploading dataset:", error);
      toast.error(`Failed to train with file: ${error.message}`);
    }
  };

  const handleTrainModels = async () => {
    if (dataset.length === 0) {
      toast.error("Please upload a dataset first");
      return;
    }

    setIsTraining(true);
    
    try {
      toast.info("Training classifier model on backend...");
      
      console.log("🧠 Starting ML training with dataset:", dataset.length, "samples");
      
      // Call the actual backend API
      const response = await mlApi.trainClassifier(dataset);
      
      console.log("🎯 Backend training response:", response);
      
      if (response.success) {
        setTrainingResults(response);
        setIsModelTrained(true);
        
        toast.success(`Model trained successfully! Accuracy: ${(response.accuracy * 100).toFixed(1)}%`);
        
        // Emit Socket.IO event for real-time updates
        if (socket) {
          socket.emit('mlAnalysisComplete', {
            accuracy: response.accuracy,
            dataset_size: response.dataset_size,
            timestamp: response.last_trained
          });
        }
      } else {
        throw new Error(response.error || 'Training failed');
      }
      
    } catch (error: any) {
      console.error("Error training models:", error);
      toast.error(`Training failed: ${error.message}`);
    } finally {
      setIsTraining(false);
    }
  };

  const handleGeneratePayloads = async (vulnerabilityType?: string) => {
    try {
      toast.info("Generating enhanced payloads...");
      
      console.log("🚀 Generating payloads for:", vulnerabilityType);
      
      const response = await mlApi.generatePayloads(vulnerabilityType, 5);
      
      console.log("✅ Generated payloads:", response);
      
      if (response.success) {
        setGeneratedPayloads(prev => [...prev, ...response.payloads]);
        toast.success(`Generated ${response.count} new payloads!`);
      } else {
        throw new Error(response.error || 'Payload generation failed');
      }
      
    } catch (error: any) {
      console.error("Error generating payloads:", error);
      toast.error(`Failed to generate payloads: ${error.message}`);
    }
  };

  const handleExportResults = () => {
    if (!trainingResults) {
      toast.error("No training results to export");
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      dataset_info: {
        filename: datasetFileName,
        total_records: dataset.length,
        class_distribution: trainingResults.class_distribution
      },
      model_performance: {
        accuracy: trainingResults.accuracy,
        classification_report: trainingResults.classification_report,
        confusion_matrix: trainingResults.confusion_matrix
      },
      generated_payloads: generatedPayloads
    };

    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ml-analysis-results-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast.success("Results exported successfully!");
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-6 max-w-7xl">
        <div className="flex justify-between items-start mb-6">
          <div>
            <h1 className="text-3xl font-bold text-white">Enhanced Machine Learning</h1>
            <p className="text-gray-400">Advanced ML classifier training and analysis</p>
          </div>
          <div className="flex gap-2">
            <input
              type="file"
              id="dataset-upload"
              accept=".txt,.csv"
              onChange={handleFileUpload}
              className="hidden"
            />
            <Button variant="outline" asChild>
              <label htmlFor="dataset-upload" className="cursor-pointer">
                <Upload className="w-4 h-4 mr-2" />
                Upload Dataset
              </label>
            </Button>
            <Button onClick={handleExportResults} disabled={!trainingResults}>
              <Download className="w-4 h-4 mr-2" />
              Export Results
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <Database className="w-5 h-5 mr-2 text-blue-400" />
                Dataset
              </CardTitle>
              <CardDescription>Uploaded training data</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{dataset.length}</div>
              <p className="text-sm text-gray-500">
                {datasetFileName ? `File: ${datasetFileName}` : 'No file uploaded'}
              </p>
              {dataset.length > 0 && (
                <Badge variant="outline" className="mt-2">
                  Ready for training
                </Badge>
              )}
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <Brain className="w-5 h-5 mr-2 text-purple-400" />
                Model Status
              </CardTitle>
              <CardDescription>Classifier training status</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold text-white">
                {isTraining ? 'Training...' : isModelTrained ? 'Trained' : 'Not Trained'}
              </div>
              {trainingResults && (
                <p className="text-sm text-gray-500">
                  Accuracy: {(trainingResults.accuracy * 100).toFixed(1)}%
                </p>
              )}
              <Badge 
                variant="outline" 
                className={`mt-2 ${
                  isModelTrained ? 'text-green-400 border-green-400' : 
                  isTraining ? 'text-yellow-400 border-yellow-400' : 
                  'text-gray-400 border-gray-400'
                }`}
              >
                {isTraining ? 'Training' : isModelTrained ? 'Complete' : 'Pending'}
              </Badge>
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <BarChart2 className="w-5 h-5 mr-2 text-green-400" />
                Performance
              </CardTitle>
              <CardDescription>Model evaluation metrics</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold text-white">
                {trainingResults ? `${(trainingResults.accuracy * 100).toFixed(1)}%` : '--'}
              </div>
              <p className="text-sm text-gray-500">Overall Accuracy</p>
              {trainingResults && (
                <Badge variant="outline" className="mt-2 text-green-400 border-green-400">
                  {Object.keys(trainingResults.classification_report).length} Classes
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
              <p className="text-sm text-gray-500">payloads generated</p>
              <Button size="sm" onClick={() => handleGeneratePayloads()} className="mt-2">
                Generate More
              </Button>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Model Training</CardTitle>
              <CardDescription>Train classifier on uploaded dataset</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                onClick={handleTrainModels}
                disabled={dataset.length === 0 || isTraining}
                className="w-full bg-purple-700 hover:bg-purple-600"
              >
                <Brain className="w-4 h-4 mr-2" />
                {isTraining ? 'Training Models...' : 'Train Classifier'}
              </Button>
              
              {dataset.length > 0 && (
                <div className="text-sm text-gray-400">
                  <p>Dataset contains {dataset.length} samples</p>
                  <p>Classes: {[...new Set(dataset.map(item => item.label))].join(', ')}</p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Contextual Payload Generation</CardTitle>
              <CardDescription>Generate payloads for specific attack types</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button 
                variant="outline" 
                className="w-full justify-start"
                onClick={() => handleGeneratePayloads('sql_injection')}
              >
                SQL Injection Payloads
              </Button>
              <Button 
                variant="outline" 
                className="w-full justify-start"
                onClick={() => handleGeneratePayloads('xss')}
              >
                XSS Payloads
              </Button>
              <Button 
                variant="outline" 
                className="w-full justify-start"
                onClick={() => handleGeneratePayloads('path_traversal')}
              >
                Path Traversal Payloads
              </Button>
              <Button 
                variant="outline" 
                className="w-full justify-start"
                onClick={() => handleGeneratePayloads('command_injection')}
              >
                Command Injection Payloads
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* ML Analysis Dashboard Component */}
        <MLAnalysisDashboard 
          dataset={dataset}
          trainingResults={trainingResults}
          isTraining={isTraining}
          isModelTrained={isModelTrained}
          generatedPayloads={generatedPayloads}
        />
      </div>
    </DashboardLayout>
  );
};

export default MachineLearning;
