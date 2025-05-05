
import React, { useState, useEffect } from 'react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { FileUp, Upload, Database, BarChart2, Layers, FileText, Export } from 'lucide-react';

const MLAnalysis = () => {
  const [dataset, setDataset] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState('dataset');
  const [modelTrained, setModelTrained] = useState(false);
  const [analysisComplete, setAnalysisComplete] = useState(false);

  // Simulate uploading dataset
  const handleUploadDataset = () => {
    // In a real implementation, this would open a file dialog
    const mockDataset = Array.from({ length: 25 }, (_, i) => ({
      id: i,
      timestamp: new Date().toISOString(),
      payload: `test${i}' OR 1=1 --`,
      vulnerability: i % 3 === 0 ? 'SQL Injection' : i % 5 === 0 ? 'XSS' : 'None',
      severity: i % 3 === 0 ? 'High' : i % 5 === 0 ? 'Medium' : 'Low',
    }));
    
    setDataset(mockDataset);
    // Dispatch event for any components listening for dataset changes
    window.dispatchEvent(new CustomEvent('dataset_loaded', { detail: mockDataset }));
  };

  const handleTrainModels = () => {
    if (dataset.length === 0) return;
    
    // Simulate training process
    const trainingEvent = new CustomEvent('model_training_started');
    window.dispatchEvent(trainingEvent);
    
    // After "training" is complete
    setTimeout(() => {
      setModelTrained(true);
      window.dispatchEvent(new CustomEvent('model_training_complete'));
    }, 2000);
  };
  
  const handleAnalyzeData = () => {
    if (!modelTrained) return;
    
    // Simulate analysis process
    const analysisEvent = new CustomEvent('analysis_started');
    window.dispatchEvent(analysisEvent);
    
    // After "analysis" is complete
    setTimeout(() => {
      setAnalysisComplete(true);
      window.dispatchEvent(new CustomEvent('analysis_complete'));
    }, 2500);
  };
  
  const handleGenerateReport = () => {
    if (!analysisComplete) return;
    
    // Simulate report generation
    window.dispatchEvent(new CustomEvent('report_generation_started'));
    
    // In a real app, this would generate and possibly download a PDF
    setTimeout(() => {
      window.dispatchEvent(new CustomEvent('report_generation_complete'));
      alert('Report generated!');
    }, 1500);
  };

  const handleExport = () => {
    if (dataset.length === 0) return;
    
    // In a real app, this would export the dataset to CSV or similar
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(dataset));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "ml_analysis_dataset.json");
    document.body.appendChild(downloadAnchorNode); // Required for Firefox
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  return (
    <DashboardLayout>
      <div className="container mx-auto p-6 max-w-7xl">
        <div className="flex justify-between items-start mb-2">
          <div>
            <h1 className="text-3xl font-bold text-white">Machine Learning Analysis</h1>
            <p className="text-gray-400">Analyze security testing data using machine learning algorithms</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" className="gap-2" onClick={handleUploadDataset}>
              <FileUp size={18} />
              Upload Dataset
            </Button>
            <Button className="bg-purple-600 hover:bg-purple-700 gap-2" onClick={handleExport}>
              <Export size={18} />
              Export
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {/* Dataset Size Card */}
          <Card className="bg-black/20 border-gray-800 text-white">
            <CardContent className="p-6">
              <h3 className="text-lg font-medium text-gray-400">Dataset Size</h3>
              <div className="text-4xl font-bold mt-2">{dataset.length}</div>
              <p className="text-sm text-gray-500">records loaded</p>
              
              <Button 
                variant="outline" 
                className="w-full mt-6 border-gray-700 text-gray-300 hover:bg-gray-800 gap-2"
                disabled={dataset.length === 0}
                onClick={handleTrainModels}
              >
                <Database size={16} />
                Train Models
              </Button>
            </CardContent>
          </Card>
          
          {/* Models Card */}
          <Card className="bg-black/20 border-gray-800 text-white">
            <CardContent className="p-6">
              <h3 className="text-lg font-medium text-gray-400">Models</h3>
              <div className="text-4xl font-bold mt-2">
                {modelTrained ? 'Trained' : 'Not Trained'}
              </div>
              <p className="text-sm text-gray-500">
                {modelTrained ? 'Models ready for analysis' : 'Upload data and train models'}
              </p>
              
              <Button 
                variant="outline" 
                className="w-full mt-6 border-gray-700 text-gray-300 hover:bg-gray-800 gap-2"
                disabled={!modelTrained}
                onClick={handleAnalyzeData}
              >
                <BarChart2 size={16} />
                Analyze Data
              </Button>
            </CardContent>
          </Card>
          
          {/* Analysis Card */}
          <Card className="bg-black/20 border-gray-800 text-white">
            <CardContent className="p-6">
              <h3 className="text-lg font-medium text-gray-400">Analysis</h3>
              <div className="text-4xl font-bold mt-2">
                {analysisComplete ? 'Complete' : 'Not Analyzed'}
              </div>
              <p className="text-sm text-gray-500">
                {analysisComplete ? 'Results available' : 'Analyze data to see results'}
              </p>
              
              <Button 
                variant="outline" 
                className="w-full mt-6 border-gray-700 text-gray-300 hover:bg-gray-800 gap-2"
                disabled={!analysisComplete}
                onClick={handleGenerateReport}
              >
                <FileText size={16} />
                Generate Report
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Tabs Navigation */}
        <div className="bg-black/20 border border-gray-800 rounded-lg overflow-hidden">
          <Tabs defaultValue="dataset" value={activeTab} onValueChange={setActiveTab}>
            <div className="border-b border-gray-800">
              <TabsList className="bg-transparent border-b border-gray-800 w-full justify-start">
                <TabsTrigger 
                  value="dataset" 
                  className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-purple-500 data-[state=active]:shadow-none rounded-none py-3"
                >
                  Dataset
                </TabsTrigger>
                <TabsTrigger 
                  value="models" 
                  className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-purple-500 data-[state=active]:shadow-none rounded-none py-3"
                >
                  Models
                </TabsTrigger>
                <TabsTrigger 
                  value="analysis" 
                  className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-purple-500 data-[state=active]:shadow-none rounded-none py-3"
                >
                  Analysis
                </TabsTrigger>
                <TabsTrigger 
                  value="clusters" 
                  className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-purple-500 data-[state=active]:shadow-none rounded-none py-3"
                >
                  Clusters
                </TabsTrigger>
                <TabsTrigger 
                  value="report" 
                  className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-purple-500 data-[state=active]:shadow-none rounded-none py-3"
                >
                  Report
                </TabsTrigger>
              </TabsList>
            </div>
            
            <TabsContent value="dataset" className="p-6 focus-visible:outline-none focus-visible:ring-0">
              <h2 className="text-2xl font-bold text-white mb-2">Dataset Overview</h2>
              <p className="text-gray-400 mb-6">View and analyze the uploaded dataset</p>
              
              {dataset.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-gray-300">
                    <thead className="border-b border-gray-800">
                      <tr>
                        <th className="py-3 px-4 text-left">ID</th>
                        <th className="py-3 px-4 text-left">Payload</th>
                        <th className="py-3 px-4 text-left">Vulnerability</th>
                        <th className="py-3 px-4 text-left">Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dataset.slice(0, 10).map((item) => (
                        <tr key={item.id} className="border-b border-gray-800">
                          <td className="py-2 px-4">{item.id}</td>
                          <td className="py-2 px-4 font-mono text-sm">{item.payload}</td>
                          <td className="py-2 px-4">{item.vulnerability}</td>
                          <td className="py-2 px-4">
                            <span className={`px-2 py-1 rounded text-xs ${
                              item.severity === 'High' ? 'bg-red-900/30 text-red-400' :
                              item.severity === 'Medium' ? 'bg-yellow-900/30 text-yellow-400' :
                              'bg-blue-900/30 text-blue-400'
                            }`}>
                              {item.severity}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  
                  {dataset.length > 10 && (
                    <p className="text-center text-gray-500 text-sm mt-4">
                      Showing 10 of {dataset.length} records
                    </p>
                  )}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-16">
                  <Database className="h-16 w-16 text-gray-700 mb-4" />
                  <p className="text-gray-500">No dataset loaded. Upload a dataset to begin analysis.</p>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="models" className="p-6 focus-visible:outline-none focus-visible:ring-0">
              <h2 className="text-2xl font-bold text-white mb-2">Model Training</h2>
              <p className="text-gray-400 mb-6">View and manage machine learning models</p>
              
              {!modelTrained ? (
                <div className="flex flex-col items-center justify-center py-16">
                  <Layers className="h-16 w-16 text-gray-700 mb-4" />
                  <p className="text-gray-500">No models trained yet. Train models to see details.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Card className="bg-black/30 border-gray-800">
                    <CardContent className="p-6">
                      <h3 className="text-lg font-medium text-white">Isolation Forest</h3>
                      <p className="text-gray-500 text-sm mb-4">Anomaly detection model</p>
                      
                      <div className="space-y-2">
                        <div>
                          <div className="flex justify-between">
                            <span className="text-gray-400 text-sm">Contamination</span>
                            <span className="text-gray-400 text-sm">0.1</span>
                          </div>
                          <div className="h-2 bg-gray-800 rounded overflow-hidden">
                            <div className="h-full bg-purple-600" style={{ width: '30%' }}></div>
                          </div>
                        </div>
                        <div>
                          <div className="flex justify-between">
                            <span className="text-gray-400 text-sm">n_estimators</span>
                            <span className="text-gray-400 text-sm">100</span>
                          </div>
                          <div className="h-2 bg-gray-800 rounded overflow-hidden">
                            <div className="h-full bg-purple-600" style={{ width: '70%' }}></div>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="bg-black/30 border-gray-800">
                    <CardContent className="p-6">
                      <h3 className="text-lg font-medium text-white">Random Forest</h3>
                      <p className="text-gray-500 text-sm mb-4">Classification model</p>
                      
                      <div className="space-y-2">
                        <div>
                          <div className="flex justify-between">
                            <span className="text-gray-400 text-sm">Accuracy</span>
                            <span className="text-gray-400 text-sm">87%</span>
                          </div>
                          <div className="h-2 bg-gray-800 rounded overflow-hidden">
                            <div className="h-full bg-green-600" style={{ width: '87%' }}></div>
                          </div>
                        </div>
                        <div>
                          <div className="flex justify-between">
                            <span className="text-gray-400 text-sm">Precision</span>
                            <span className="text-gray-400 text-sm">92%</span>
                          </div>
                          <div className="h-2 bg-gray-800 rounded overflow-hidden">
                            <div className="h-full bg-green-600" style={{ width: '92%' }}></div>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="analysis" className="p-6 focus-visible:outline-none focus-visible:ring-0">
              <h2 className="text-2xl font-bold text-white mb-2">Analysis Results</h2>
              <p className="text-gray-400 mb-6">View detailed analysis of the dataset</p>
              
              {!analysisComplete ? (
                <div className="flex flex-col items-center justify-center py-16">
                  <BarChart2 className="h-16 w-16 text-gray-700 mb-4" />
                  <p className="text-gray-500">Analysis not yet performed. Analyze data to see results.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Card className="bg-black/30 border-gray-800">
                    <CardContent className="p-6">
                      <h3 className="text-lg font-medium text-white">Vulnerability Distribution</h3>
                      <div className="mt-4 h-64 flex items-end justify-around">
                        <div className="flex flex-col items-center">
                          <div className="h-32 w-16 bg-red-700/70 rounded-t"></div>
                          <p className="text-xs text-gray-400 mt-2">SQL Injection</p>
                          <p className="text-sm text-white">32%</p>
                        </div>
                        <div className="flex flex-col items-center">
                          <div className="h-20 w-16 bg-yellow-700/70 rounded-t"></div>
                          <p className="text-xs text-gray-400 mt-2">XSS</p>
                          <p className="text-sm text-white">20%</p>
                        </div>
                        <div className="flex flex-col items-center">
                          <div className="h-12 w-16 bg-purple-700/70 rounded-t"></div>
                          <p className="text-xs text-gray-400 mt-2">Path Traversal</p>
                          <p className="text-sm text-white">12%</p>
                        </div>
                        <div className="flex flex-col items-center">
                          <div className="h-36 w-16 bg-blue-700/70 rounded-t"></div>
                          <p className="text-xs text-gray-400 mt-2">None</p>
                          <p className="text-sm text-white">36%</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="bg-black/30 border-gray-800">
                    <CardContent className="p-6">
                      <h3 className="text-lg font-medium text-white">Detected Patterns</h3>
                      <ul className="mt-4 space-y-2">
                        <li className="text-gray-300 flex items-start">
                          <span className="inline-block w-2 h-2 rounded-full bg-red-500 mt-1.5 mr-2"></span>
                          SQL injection attempts using OR 1=1 statements
                        </li>
                        <li className="text-gray-300 flex items-start">
                          <span className="inline-block w-2 h-2 rounded-full bg-yellow-500 mt-1.5 mr-2"></span>
                          XSS attempts with script tags and event handlers
                        </li>
                        <li className="text-gray-300 flex items-start">
                          <span className="inline-block w-2 h-2 rounded-full bg-purple-500 mt-1.5 mr-2"></span>
                          Path traversal using ../ sequences
                        </li>
                        <li className="text-gray-300 flex items-start">
                          <span className="inline-block w-2 h-2 rounded-full bg-blue-500 mt-1.5 mr-2"></span>
                          Command injection with semicolons and pipes
                        </li>
                        <li className="text-gray-300 flex items-start">
                          <span className="inline-block w-2 h-2 rounded-full bg-green-500 mt-1.5 mr-2"></span>
                          SSRF attempts with localhost references
                        </li>
                      </ul>
                    </CardContent>
                  </Card>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="clusters" className="p-6 focus-visible:outline-none focus-visible:ring-0">
              <h2 className="text-2xl font-bold text-white mb-2">Cluster Analysis</h2>
              <p className="text-gray-400 mb-6">View clustering results from the dataset</p>
              
              {!analysisComplete ? (
                <div className="flex flex-col items-center justify-center py-16">
                  <Layers className="h-16 w-16 text-gray-700 mb-4" />
                  <p className="text-gray-500">Clustering not yet performed. Analyze data to see results.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-6">
                  <Card className="bg-black/30 border-gray-800">
                    <CardContent className="p-6">
                      <h3 className="text-lg font-medium text-white mb-4">Cluster Distribution</h3>
                      <div className="relative h-64 w-full border border-gray-800 rounded-lg overflow-hidden">
                        {/* Mock scatter plot - in a real app, use a proper chart library */}
                        <div className="absolute h-3 w-3 rounded-full bg-red-500" style={{ left: '30%', top: '40%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-red-500" style={{ left: '32%', top: '45%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-red-500" style={{ left: '28%', top: '42%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-red-500" style={{ left: '25%', top: '38%' }}></div>
                        
                        <div className="absolute h-3 w-3 rounded-full bg-blue-500" style={{ left: '70%', top: '30%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-blue-500" style={{ left: '72%', top: '28%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-blue-500" style={{ left: '68%', top: '32%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-blue-500" style={{ left: '71%', top: '33%' }}></div>
                        
                        <div className="absolute h-3 w-3 rounded-full bg-green-500" style={{ left: '50%', top: '70%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-green-500" style={{ left: '52%', top: '72%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-green-500" style={{ left: '48%', top: '68%' }}></div>
                        <div className="absolute h-3 w-3 rounded-full bg-green-500" style={{ left: '51%', top: '74%' }}></div>
                      </div>
                      
                      <div className="flex justify-around mt-6">
                        <div className="text-center">
                          <div className="flex items-center justify-center">
                            <span className="h-3 w-3 rounded-full bg-red-500 mr-2"></span>
                            <span className="text-gray-300">Cluster 1</span>
                          </div>
                          <p className="text-sm text-gray-500">Malicious</p>
                        </div>
                        <div className="text-center">
                          <div className="flex items-center justify-center">
                            <span className="h-3 w-3 rounded-full bg-blue-500 mr-2"></span>
                            <span className="text-gray-300">Cluster 2</span>
                          </div>
                          <p className="text-sm text-gray-500">Benign</p>
                        </div>
                        <div className="text-center">
                          <div className="flex items-center justify-center">
                            <span className="h-3 w-3 rounded-full bg-green-500 mr-2"></span>
                            <span className="text-gray-300">Cluster 3</span>
                          </div>
                          <p className="text-sm text-gray-500">Suspicious</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="report" className="p-6 focus-visible:outline-none focus-visible:ring-0">
              <h2 className="text-2xl font-bold text-white mb-2">Analysis Report</h2>
              <p className="text-gray-400 mb-6">Generate comprehensive reports from your analysis</p>
              
              {!analysisComplete ? (
                <div className="flex flex-col items-center justify-center py-16">
                  <FileText className="h-16 w-16 text-gray-700 mb-4" />
                  <p className="text-gray-500">Analysis not yet performed. Complete analysis to generate reports.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-6">
                  <Card className="bg-black/30 border-gray-800">
                    <CardContent className="p-6">
                      <h3 className="text-lg font-medium text-white mb-4">Report Summary</h3>
                      
                      <div className="space-y-4">
                        <div>
                          <h4 className="text-gray-300 font-medium">Vulnerability Assessment</h4>
                          <p className="text-gray-500 mt-1">
                            The analysis detected multiple vulnerability patterns with SQL injection being the most prevalent (32%). 
                            The overall risk assessment is medium-high based on the types and frequency of detected vulnerabilities.
                          </p>
                        </div>
                        
                        <div>
                          <h4 className="text-gray-300 font-medium">Recommendations</h4>
                          <ul className="mt-1 space-y-1 text-gray-500">
                            <li>- Implement prepared statements for database queries</li>
                            <li>- Add input validation for all user inputs</li>
                            <li>- Consider implementing a web application firewall</li>
                            <li>- Update security training for development team</li>
                          </ul>
                        </div>
                        
                        <Button 
                          className="bg-purple-600 hover:bg-purple-700 mt-2"
                          onClick={handleGenerateReport}
                        >
                          <FileText className="h-4 w-4 mr-2" />
                          Download Full Report
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default MLAnalysis;
