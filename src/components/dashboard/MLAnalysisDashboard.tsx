
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Database, Brain, BarChart2, FileText, Zap } from 'lucide-react';
import { ConfusionMatrixHeatmap } from './ConfusionMatrixHeatmap';
import { ClassificationReportTable } from './ClassificationReportTable';

interface MLAnalysisDashboardProps {
  dataset: any[];
  trainingResults: any;
  isTraining: boolean;
  isModelTrained: boolean;
  generatedPayloads: string[];
}

export const MLAnalysisDashboard: React.FC<MLAnalysisDashboardProps> = ({
  dataset,
  trainingResults,
  isTraining,
  isModelTrained,
  generatedPayloads
}) => {
  return (
    <Card className="bg-black/20 border-gray-800">
      <CardHeader>
        <CardTitle className="text-white">ML Analysis Dashboard</CardTitle>
        <CardDescription>Comprehensive machine learning analysis and results</CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="dataset" className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="dataset">
              <Database className="w-4 h-4 mr-2" />
              Dataset
            </TabsTrigger>
            <TabsTrigger value="models" disabled={!isModelTrained && !isTraining}>
              <Brain className="w-4 h-4 mr-2" />
              Models
            </TabsTrigger>
            <TabsTrigger value="analysis" disabled={!isModelTrained}>
              <BarChart2 className="w-4 h-4 mr-2" />
              Analysis
            </TabsTrigger>
            <TabsTrigger value="report" disabled={!isModelTrained}>
              <FileText className="w-4 h-4 mr-2" />
              Report
            </TabsTrigger>
            <TabsTrigger value="payloads">
              <Zap className="w-4 h-4 mr-2" />
              Payloads
            </TabsTrigger>
          </TabsList>

          <TabsContent value="dataset" className="mt-6">
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="bg-black/20 border-gray-700">
                  <CardContent className="pt-6">
                    <div className="text-2xl font-bold text-white">{dataset.length}</div>
                    <p className="text-sm text-gray-400">Total Records</p>
                  </CardContent>
                </Card>
                
                <Card className="bg-black/20 border-gray-700">
                  <CardContent className="pt-6">
                    <div className="text-2xl font-bold text-white">
                      {[...new Set(dataset.map(item => item.label))].length}
                    </div>
                    <p className="text-sm text-gray-400">Classes</p>
                  </CardContent>
                </Card>
                
                <Card className="bg-black/20 border-gray-700">
                  <CardContent className="pt-6">
                    <div className="text-2xl font-bold text-white">
                      {dataset.filter(item => item.label === 'malicious').length}
                    </div>
                    <p className="text-sm text-gray-400">Malicious Samples</p>
                  </CardContent>
                </Card>
              </div>

              {dataset.length > 0 && (
                <Card className="bg-black/20 border-gray-700">
                  <CardHeader>
                    <CardTitle className="text-white text-sm">Sample Data Preview</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-48">
                      <div className="space-y-2">
                        {dataset.slice(0, 5).map((item, index) => (
                          <div key={index} className="p-3 bg-black/30 rounded border border-gray-700">
                            <div className="flex justify-between items-start mb-2">
                              <Badge variant="outline" className={
                                item.label === 'malicious' ? 'text-red-400 border-red-400' :
                                item.label === 'suspicious' ? 'text-yellow-400 border-yellow-400' :
                                'text-green-400 border-green-400'
                              }>
                                {item.label}
                              </Badge>
                              <span className="text-xs text-gray-500">{item.vulnerability_type}</span>
                            </div>
                            <p className="text-sm font-mono text-gray-300 break-all">
                              {item.payload}
                            </p>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          <TabsContent value="models" className="mt-6">
            <div className="space-y-4">
              {isTraining && (
                <Card className="bg-black/20 border-gray-700">
                  <CardContent className="pt-6">
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-white">Training in Progress...</span>
                        <span className="text-sm text-gray-400">Please wait</span>
                      </div>
                      <Progress value={75} />
                      <p className="text-xs text-gray-500">Training classifier on {dataset.length} samples</p>
                    </div>
                  </CardContent>
                </Card>
              )}

              {trainingResults && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card className="bg-black/20 border-gray-700">
                    <CardHeader>
                      <CardTitle className="text-white text-sm">Model Information</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Type:</span>
                        <span className="text-white">{trainingResults.type}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Accuracy:</span>
                        <span className="text-white">{(trainingResults.accuracy * 100).toFixed(1)}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Last Trained:</span>
                        <span className="text-white text-xs">
                          {new Date(trainingResults.last_trained).toLocaleString()}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Features:</span>
                        <span className="text-white">{trainingResults.features?.length || 8}</span>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-black/20 border-gray-700">
                    <CardHeader>
                      <CardTitle className="text-white text-sm">Confusion Matrix</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ConfusionMatrixHeatmap 
                        confusionMatrix={trainingResults.confusion_matrix}
                        classNames={['Safe', 'Suspicious', 'Malicious']}
                      />
                    </CardContent>
                  </Card>
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="analysis" className="mt-6">
            <div className="space-y-4">
              {trainingResults && (
                <>
                  <Card className="bg-black/20 border-gray-700">
                    <CardHeader>
                      <CardTitle className="text-white text-sm">Classification Report</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ClassificationReportTable 
                        classificationReport={trainingResults.classification_report}
                        classNames={['Safe', 'Suspicious', 'Malicious']}
                      />
                    </CardContent>
                  </Card>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Card className="bg-black/20 border-gray-700">
                      <CardContent className="pt-6">
                        <div className="text-2xl font-bold text-green-400">
                          {(trainingResults.accuracy * 100).toFixed(1)}%
                        </div>
                        <p className="text-sm text-gray-400">Overall Accuracy</p>
                      </CardContent>
                    </Card>
                    
                    <Card className="bg-black/20 border-gray-700">
                      <CardContent className="pt-6">
                        <div className="text-2xl font-bold text-blue-400">
                          {Object.keys(trainingResults.classification_report).length}
                        </div>
                        <p className="text-sm text-gray-400">Classes Detected</p>
                      </CardContent>
                    </Card>
                    
                    <Card className="bg-black/20 border-gray-700">
                      <CardContent className="pt-6">
                        <div className="text-2xl font-bold text-purple-400">
                          {trainingResults.features?.length || 8}
                        </div>
                        <p className="text-sm text-gray-400">Features Used</p>
                      </CardContent>
                    </Card>
                  </div>
                </>
              )}
            </div>
          </TabsContent>

          <TabsContent value="report" className="mt-6">
            <div className="space-y-4">
              {trainingResults && (
                <Card className="bg-black/20 border-gray-700">
                  <CardHeader>
                    <CardTitle className="text-white text-sm">Training Summary</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="text-gray-400">Training Timestamp:</span>
                          <p className="text-white">{new Date(trainingResults.timestamp).toLocaleString()}</p>
                        </div>
                        <div>
                          <span className="text-gray-400">Model Type:</span>
                          <p className="text-white">{trainingResults.type}</p>
                        </div>
                        <div>
                          <span className="text-gray-400">Dataset Size:</span>
                          <p className="text-white">{dataset.length} samples</p>
                        </div>
                        <div>
                          <span className="text-gray-400">Accuracy Achieved:</span>
                          <p className="text-white">{(trainingResults.accuracy * 100).toFixed(2)}%</p>
                        </div>
                      </div>
                      
                      <div>
                        <span className="text-gray-400 text-sm">Model Path:</span>
                        <p className="text-white font-mono text-xs">{trainingResults.model_path}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          <TabsContent value="payloads" className="mt-6">
            <div className="space-y-4">
              <Card className="bg-black/20 border-gray-700">
                <CardHeader>
                  <CardTitle className="text-white text-sm">Generated Payloads</CardTitle>
                  <CardDescription>ML-generated security test payloads</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-64">
                    <div className="space-y-2">
                      {generatedPayloads.length === 0 ? (
                        <p className="text-gray-500 text-sm">No payloads generated yet</p>
                      ) : (
                        generatedPayloads.map((payload, index) => (
                          <div key={index} className="p-2 bg-black/30 rounded border border-gray-700">
                            <code className="text-sm text-gray-300 break-all">{payload}</code>
                          </div>
                        ))
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};
