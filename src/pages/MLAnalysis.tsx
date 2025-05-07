
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Progress } from '@/components/ui/progress';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { FileUp, Upload, Database, BarChart2, Layers, FileText, Share } from 'lucide-react';

const MLAnalysis = () => {
  const [dataset, setDataset] = useState<any[]>([]);
  const [loadingDataset, setLoadingDataset] = useState<boolean>(false);
  const [anomalyScore, setAnomalyScore] = useState<number>(0);
  const [vulnerableEndpoints, setVulnerableEndpoints] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<string>("dataset");
  const [modelTrained, setModelTrained] = useState<boolean>(false);
  const [trainingProgress, setTrainingProgress] = useState<number>(0);

  // Simulated data for demonstration
  useEffect(() => {
    // Simulate loading dataset
    setLoadingDataset(true);
    
    // Simulate dataset fetch delay
    setTimeout(() => {
      const sampleData = generateSampleData(50);
      setDataset(sampleData);
      
      // Calculate statistics
      const anomalies = sampleData.filter(item => item.anomalyScore > 0.7).length;
      setAnomalyScore(anomalies / sampleData.length * 100);
      setVulnerableEndpoints(Math.floor(Math.random() * 5) + 1);
      
      setLoadingDataset(false);
    }, 1500);
  }, []);

  // Function to simulate model training
  const handleTrainModel = () => {
    if (modelTrained) return;
    
    setTrainingProgress(0);
    const interval = setInterval(() => {
      setTrainingProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setModelTrained(true);
          return 100;
        }
        return prev + 5;
      });
    }, 200);
  };
  
  // Function to handle uploading a dataset
  const handleUploadDataset = () => {
    // Simulate upload
    console.log("Upload dataset functionality would be implemented here");
  };
  
  // Function to handle exporting results
  const handleExport = () => {
    // Simulate export
    console.log("Export functionality would be implemented here");
  };

  // Generate sample data for demonstration
  const generateSampleData = (count: number) => {
    return Array.from({ length: count }, (_, i) => ({
      id: i + 1,
      endpoint: `/api/products/${i}`,
      method: Math.random() > 0.5 ? 'GET' : 'POST',
      payload: Math.random() > 0.7 ? "'; DROP TABLE users; --" : "normal_value",
      responseTime: Math.floor(Math.random() * 500) + 50,
      statusCode: Math.random() > 0.8 ? 500 : 200,
      anomalyScore: Math.random(),
      isMalicious: Math.random() > 0.7
    }));
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-6">
        <div className="flex flex-col gap-6">
          <div className="flex justify-between items-center">
            <h1 className="text-3xl font-semibold text-white">Machine Learning Analysis</h1>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="bg-black/20 border-gray-800 text-white">
              <CardContent className="p-6">
                <div className="flex flex-col gap-2">
                  <h3 className="text-lg font-medium">Anomaly Score</h3>
                  <div className="text-3xl font-bold text-purple-400">{anomalyScore.toFixed(1)}%</div>
                  <Progress value={anomalyScore} className="bg-gray-800 [&>*]:bg-purple-600" />
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-black/20 border-gray-800 text-white">
              <CardContent className="p-6">
                <div className="flex flex-col gap-2">
                  <h3 className="text-lg font-medium">Vulnerable Endpoints</h3>
                  <div className="text-3xl font-bold text-red-400">{vulnerableEndpoints}</div>
                  <div className="text-sm text-gray-400">Detected across {dataset.length} requests</div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-black/20 border-gray-800 text-white">
              <CardContent className="p-6">
                <div className="flex flex-col gap-2">
                  <h3 className="text-lg font-medium">Model Status</h3>
                  {modelTrained ? (
                    <div className="text-xl font-semibold text-green-400">Trained & Ready</div>
                  ) : (
                    <>
                      <div className="text-xl font-semibold text-yellow-400">Not Trained</div>
                      <Button onClick={handleTrainModel} className="bg-purple-600 hover:bg-purple-700 mt-2">
                        Train Model
                      </Button>
                    </>
                  )}
                  {trainingProgress > 0 && trainingProgress < 100 && (
                    <Progress value={trainingProgress} className="mt-2 bg-gray-800 [&>*]:bg-blue-600" />
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
          
          <div className="flex justify-between items-center">
            <div className="text-xl font-semibold text-white">Analysis Results</div>
            <div className="flex gap-2">
              <Button variant="outline" className="gap-2" onClick={handleUploadDataset}>
                <Upload size={18} />
                Upload Dataset
              </Button>
              <Button className="bg-purple-600 hover:bg-purple-700 gap-2" onClick={handleExport}>
                <Share size={18} />
                Export
              </Button>
            </div>
          </div>
          
          <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="bg-gray-900/60 border-gray-800 w-full justify-start">
              <TabsTrigger value="dataset" className="data-[state=active]:bg-purple-900/40">
                <Database className="w-4 h-4 mr-2" />
                Dataset
              </TabsTrigger>
              <TabsTrigger value="models" className="data-[state=active]:bg-purple-900/40">
                <FileUp className="w-4 h-4 mr-2" />
                Models
              </TabsTrigger>
              <TabsTrigger value="analysis" className="data-[state=active]:bg-purple-900/40">
                <BarChart2 className="w-4 h-4 mr-2" />
                Analysis
              </TabsTrigger>
              <TabsTrigger value="clusters" className="data-[state=active]:bg-purple-900/40">
                <Layers className="w-4 h-4 mr-2" />
                Clusters
              </TabsTrigger>
              <TabsTrigger value="report" className="data-[state=active]:bg-purple-900/40">
                <FileText className="w-4 h-4 mr-2" />
                Report
              </TabsTrigger>
            </TabsList>
            
            <TabsContent value="dataset" className="border-gray-800 bg-black/20 rounded-md mt-2">
              {/* Dataset content would go here */}
              <div className="p-4">
                <h3 className="text-lg font-semibold text-white mb-4">Dataset Analysis</h3>
                {loadingDataset ? (
                  <div className="text-center py-20">Loading dataset...</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm text-left text-gray-300">
                      <thead className="text-xs uppercase bg-gray-900/60 text-gray-400">
                        <tr>
                          <th className="px-6 py-3">ID</th>
                          <th className="px-6 py-3">Endpoint</th>
                          <th className="px-6 py-3">Method</th>
                          <th className="px-6 py-3">Status</th>
                          <th className="px-6 py-3">Anomaly Score</th>
                        </tr>
                      </thead>
                      <tbody>
                        {dataset.slice(0, 10).map((item) => (
                          <tr key={item.id} className="border-b border-gray-800 hover:bg-gray-900/30">
                            <td className="px-6 py-4">{item.id}</td>
                            <td className="px-6 py-4 font-mono text-xs">{item.endpoint}</td>
                            <td className="px-6 py-4">{item.method}</td>
                            <td className="px-6 py-4">
                              <span className={`px-2 py-1 rounded-full text-xs ${
                                item.statusCode >= 400 ? 'bg-red-900/50 text-red-300' : 'bg-green-900/50 text-green-300'
                              }`}>
                                {item.statusCode}
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <div className="w-full bg-gray-800 h-2 rounded-full">
                                <div 
                                  className={`h-2 rounded-full ${
                                    item.anomalyScore > 0.7 ? 'bg-red-500' : 
                                    item.anomalyScore > 0.4 ? 'bg-yellow-500' : 'bg-green-500'
                                  }`}
                                  style={{ width: `${item.anomalyScore * 100}%` }}
                                />
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {dataset.length > 10 && (
                      <div className="text-center py-2 text-gray-400 text-sm">
                        Showing 10 of {dataset.length} entries
                      </div>
                    )}
                  </div>
                )}
              </div>
            </TabsContent>
            
            <TabsContent value="models" className="border-gray-800 bg-black/20 rounded-md mt-2">
              <div className="p-4">
                <h3 className="text-lg font-semibold text-white mb-4">ML Models</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card className="bg-gray-900/60 border-gray-800">
                    <CardContent className="p-4">
                      <h4 className="text-md font-semibold mb-2">Anomaly Detection</h4>
                      <p className="text-sm text-gray-400 mb-3">Isolation Forest model to detect anomalies in request patterns.</p>
                      <div className="flex justify-between items-center">
                        <div className="text-xs text-gray-500">
                          Status: {modelTrained ? <span className="text-green-400">Trained</span> : <span className="text-yellow-400">Not Trained</span>}
                        </div>
                        <Button size="sm" variant="outline" disabled={!modelTrained}>View Details</Button>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="bg-gray-900/60 border-gray-800">
                    <CardContent className="p-4">
                      <h4 className="text-md font-semibold mb-2">Payload Classification</h4>
                      <p className="text-sm text-gray-400 mb-3">RandomForest classifier to identify malicious payloads.</p>
                      <div className="flex justify-between items-center">
                        <div className="text-xs text-gray-500">
                          Status: {modelTrained ? <span className="text-green-400">Trained</span> : <span className="text-yellow-400">Not Trained</span>}
                        </div>
                        <Button size="sm" variant="outline" disabled={!modelTrained}>View Details</Button>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="analysis" className="border-gray-800 bg-black/20 rounded-md mt-2">
              <div className="p-4">
                <h3 className="text-lg font-semibold text-white mb-4">Analysis Results</h3>
                <p className="text-gray-400 mb-4">Model analysis and vulnerability predictions will appear here once models are trained.</p>
                {!modelTrained && (
                  <Button onClick={handleTrainModel} className="bg-purple-600 hover:bg-purple-700">
                    Train Models to See Analysis
                  </Button>
                )}
              </div>
            </TabsContent>
            
            <TabsContent value="clusters" className="border-gray-800 bg-black/20 rounded-md mt-2">
              <div className="p-4">
                <h3 className="text-lg font-semibold text-white mb-4">Cluster Analysis</h3>
                <p className="text-gray-400">Clustering of similar attack patterns and request characteristics.</p>
              </div>
            </TabsContent>
            
            <TabsContent value="report" className="border-gray-800 bg-black/20 rounded-md mt-2">
              <div className="p-4">
                <h3 className="text-lg font-semibold text-white mb-4">Security Report</h3>
                <p className="text-gray-400 mb-4">Comprehensive security report with findings and recommendations.</p>
                <Button disabled={!modelTrained} className="bg-purple-600 hover:bg-purple-700">
                  Generate Report
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default MLAnalysis;
