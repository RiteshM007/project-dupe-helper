
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { EnhancedMLScanner } from '@/components/dashboard/EnhancedMLScanner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Brain, Database, BarChart2, Zap, Upload, Download } from 'lucide-react';
import { EnhancedPayloadGenerator } from '@/backend/enhanced_ml_models';
import { toast } from 'sonner';

const MachineLearning = () => {
  const [scanActive, setScanActive] = useState(false);
  const [scanCompleted, setScanCompleted] = useState(false);
  const [dataset, setDataset] = useState<any[]>([]);
  const [threatLevel, setThreatLevel] = useState<'none' | 'low' | 'medium' | 'high' | 'critical'>('none');
  const [payloadGenerator, setPayloadGenerator] = useState<EnhancedPayloadGenerator | null>(null);
  const [generatedPayloads, setGeneratedPayloads] = useState<string[]>([]);

  useEffect(() => {
    // Initialize enhanced payload generator
    const initGenerator = async () => {
      try {
        const generator = new EnhancedPayloadGenerator();
        setPayloadGenerator(generator);
        toast.success("Enhanced ML payload generator initialized!");
      } catch (error) {
        console.error("Failed to initialize payload generator:", error);
        toast.error("Failed to initialize payload generator");
      }
    };
    
    initGenerator();

    // Listen for scan events
    const handleScanStart = () => setScanActive(true);
    const handleScanComplete = () => {
      setScanActive(false);
      setScanCompleted(true);
      setThreatLevel('medium'); // Example threat level
    };

    window.addEventListener('scanStart', handleScanStart);
    window.addEventListener('scanComplete', handleScanComplete);

    return () => {
      window.removeEventListener('scanStart', handleScanStart);
      window.removeEventListener('scanComplete', handleScanComplete);
    };
  }, []);

  const handleGeneratePayloads = async (vulnerabilityType?: string) => {
    if (!payloadGenerator) {
      toast.error("Payload generator not initialized");
      return;
    }

    try {
      toast.info("Generating enhanced payloads...");
      
      let newPayloads: string[];
      if (vulnerabilityType) {
        newPayloads = await payloadGenerator.generateContextualPayloads(vulnerabilityType, 5);
      } else {
        newPayloads = await payloadGenerator.generatePayloads(10);
      }
      
      setGeneratedPayloads(prev => [...prev, ...newPayloads]);
      toast.success(`Generated ${newPayloads.length} new payloads!`);
    } catch (error) {
      console.error("Error generating payloads:", error);
      toast.error("Failed to generate payloads");
    }
  };

  const handleUploadDataset = () => {
    // Simulate dataset upload
    const mockDataset = Array.from({ length: 50 }, (_, i) => ({
      id: i,
      payload: `test_payload_${i}`,
      response_code: Math.random() > 0.7 ? 500 : 200,
      body_word_count_changed: Math.random() > 0.5 ? 1 : 0,
      alert_detected: Math.random() > 0.8 ? 1 : 0,
      error_detected: Math.random() > 0.7 ? 1 : 0,
      label: Math.random() > 0.7 ? 'malicious' : Math.random() > 0.5 ? 'suspicious' : 'safe',
      vulnerability_type: ['sql_injection', 'xss', 'path_traversal', 'command_injection'][Math.floor(Math.random() * 4)]
    }));
    
    setDataset(mockDataset);
    toast.success("Dataset uploaded successfully!");
  };

  const handleExportPayloads = () => {
    if (generatedPayloads.length === 0) {
      toast.error("No payloads to export");
      return;
    }

    const dataStr = generatedPayloads.join('\n');
    const dataBlob = new Blob([dataStr], { type: 'text/plain' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'enhanced_ml_payloads.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast.success("Payloads exported successfully!");
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-6 max-w-7xl">
        <div className="flex justify-between items-start mb-6">
          <div>
            <h1 className="text-3xl font-bold text-white">Enhanced Machine Learning</h1>
            <p className="text-gray-400">Advanced ML-driven security testing and payload generation</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleUploadDataset}>
              <Upload className="w-4 h-4 mr-2" />
              Upload Dataset
            </Button>
            <Button onClick={handleExportPayloads} disabled={generatedPayloads.length === 0}>
              <Download className="w-4 h-4 mr-2" />
              Export Payloads
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <Database className="w-5 h-5 mr-2 text-blue-400" />
                Dataset
              </CardTitle>
              <CardDescription>Training data for ML models</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{dataset.length}</div>
              <p className="text-sm text-gray-500">samples loaded</p>
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
                <Zap className="w-5 h-5 mr-2 text-orange-400" />
                Generated Payloads
              </CardTitle>
              <CardDescription>ML-generated security payloads</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{generatedPayloads.length}</div>
              <p className="text-sm text-gray-500">payloads generated</p>
              <div className="flex gap-2 mt-2">
                <Button size="sm" onClick={() => handleGeneratePayloads()}>
                  Generate
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="flex items-center text-white">
                <BarChart2 className="w-5 h-5 mr-2 text-green-400" />
                Analysis Status
              </CardTitle>
              <CardDescription>ML model training status</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold text-white">
                {scanCompleted ? 'Complete' : scanActive ? 'Active' : 'Ready'}
              </div>
              <p className="text-sm text-gray-500">
                {scanCompleted ? 'Models trained' : scanActive ? 'Collecting data' : 'Waiting for scan'}
              </p>
              <Badge 
                variant="outline" 
                className={`mt-2 ${
                  scanCompleted ? 'text-green-400 border-green-400' : 
                  scanActive ? 'text-yellow-400 border-yellow-400' : 
                  'text-gray-400 border-gray-400'
                }`}
              >
                {scanCompleted ? 'Complete' : scanActive ? 'Running' : 'Idle'}
              </Badge>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Contextual Payload Generation</CardTitle>
              <CardDescription>Generate payloads for specific vulnerability types</CardDescription>
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

          <Card className="bg-black/20 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Recent Generated Payloads</CardTitle>
              <CardDescription>Latest ML-generated security payloads</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="max-h-48 overflow-y-auto space-y-2">
                {generatedPayloads.length === 0 ? (
                  <p className="text-gray-500 text-sm">No payloads generated yet</p>
                ) : (
                  generatedPayloads.slice(-10).map((payload, index) => (
                    <div key={index} className="text-xs font-mono bg-black/30 p-2 rounded text-gray-300">
                      {payload}
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        <EnhancedMLScanner 
          scanActive={scanActive}
          scanCompleted={scanCompleted}
          dataset={dataset}
          threatLevel={threatLevel}
        />
      </div>
    </DashboardLayout>
  );
};

export default MachineLearning;
