
import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { 
  Download, 
  FileDown, 
  Filter, 
  Calendar, 
  SortDesc, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Search
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import DashboardLayout from "@/components/layout/DashboardLayout";

// Sample data for reports
const generateMockReports = () => {
  const reports = [];
  const scanTypes = ['Full Scan', 'Quick Scan', 'Custom Scan', 'Vulnerability Assessment'];
  const domains = ['example.com', 'testsite.org', 'demo-app.net', 'webapp.io', 'secureapp.co'];
  const threats = ['XSS Vulnerability', 'SQL Injection', 'CSRF Vulnerability', 'File Inclusion', 'Command Injection'];
  
  for (let i = 0; i < 10; i++) {
    const threatCount = Math.floor(Math.random() * 10);
    const scanType = scanTypes[Math.floor(Math.random() * scanTypes.length)];
    const domain = domains[Math.floor(Math.random() * domains.length)];
    const timestamp = new Date();
    timestamp.setDate(timestamp.getDate() - Math.floor(Math.random() * 30));
    
    reports.push({
      id: `report-${i + 1}`,
      name: `${scanType} - ${domain}`,
      scanType,
      domain,
      timestamp: timestamp.toISOString(),
      threatCount,
      critical: Math.floor(Math.random() * threatCount),
      high: Math.floor(Math.random() * (threatCount - Math.floor(threatCount / 2))),
      medium: Math.floor(Math.random() * threatCount),
      low: Math.floor(Math.random() * threatCount),
      findings: Array(Math.max(1, threatCount)).fill(null).map(() => ({
        type: threats[Math.floor(Math.random() * threats.length)],
        severity: Math.random() > 0.7 ? 'critical' : 
                 Math.random() > 0.5 ? 'high' : 
                 Math.random() > 0.3 ? 'medium' : 'low',
        url: `https://${domain}/page${Math.floor(Math.random() * 10) + 1}.html`,
        details: 'Potentially vulnerable code detected that could allow malicious script execution.'
      }))
    });
  }
  
  return reports;
};

const Reports = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [timeFilter, setTimeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selectedReport, setSelectedReport] = useState<string | null>(null);

  // Fetch reports data
  const { data: reports = [], isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => Promise.resolve(generateMockReports()),
  });

  // Filter reports based on search and filters
  const filteredReports = reports.filter(report => {
    const matchesSearch = report.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          report.domain.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesTime = timeFilter === 'all' ||
                       (timeFilter === 'today' && new Date(report.timestamp).toDateString() === new Date().toDateString()) ||
                       (timeFilter === 'week' && new Date(report.timestamp) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)) ||
                       (timeFilter === 'month' && new Date(report.timestamp) > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000));
    
    const matchesSeverity = severityFilter === 'all' ||
                           (severityFilter === 'critical' && report.critical > 0) ||
                           (severityFilter === 'high' && report.high > 0) ||
                           (severityFilter === 'medium' && report.medium > 0) ||
                           (severityFilter === 'low' && report.low > 0);
    
    return matchesSearch && matchesTime && matchesSeverity;
  });

  // Get selected report details
  const selectedReportData = selectedReport ? reports.find(r => r.id === selectedReport) : null;

  // Function to generate PDF report
  const generatePdfReport = (reportId: string) => {
    toast.success('PDF report generated successfully');
    // In a real implementation, this would trigger the PDF generation
    setTimeout(() => {
      // Simulate download complete
      toast.success('Report downloaded');
    }, 1500);
  };

  return (
    <DashboardLayout>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Reports List Panel */}
        <Card className="lg:col-span-1 bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
          <CardHeader>
            <CardTitle className="text-xl font-bold">Scan Reports</CardTitle>
            <CardDescription>View and analyze security scan results</CardDescription>
          </CardHeader>
          
          <div className="px-4 pb-2">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search reports..."
                className="pl-8 bg-background/80 border-white/10"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
          
          <div className="px-4 py-2 flex space-x-2">
            <Select value={timeFilter} onValueChange={setTimeFilter}>
              <SelectTrigger className="bg-background/80 border-white/10 h-8 text-xs">
                <Calendar className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue placeholder="Time" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Time</SelectItem>
                <SelectItem value="today">Today</SelectItem>
                <SelectItem value="week">This Week</SelectItem>
                <SelectItem value="month">This Month</SelectItem>
              </SelectContent>
            </Select>
            
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="bg-background/80 border-white/10 h-8 text-xs">
                <Filter className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            
            <Button variant="outline" size="sm" className="h-8 text-xs bg-background/80 border-white/10">
              <SortDesc className="h-3.5 w-3.5 mr-1.5" />
              Newest
            </Button>
          </div>
          
          <CardContent className="pt-2">
            <ScrollArea className="h-[500px]">
              <div className="space-y-2">
                {isLoading ? (
                  <div className="text-center py-8 text-muted-foreground">
                    Loading reports...
                  </div>
                ) : filteredReports.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    No reports found
                  </div>
                ) : (
                  filteredReports.map((report) => (
                    <div
                      key={report.id}
                      className={`p-3 rounded-md cursor-pointer transition-all border ${
                        selectedReport === report.id
                          ? 'bg-purple-950/30 border-purple-500/50'
                          : 'bg-white/5 border-white/10 hover:bg-white/10'
                      }`}
                      onClick={() => setSelectedReport(report.id)}
                    >
                      <div className="flex justify-between items-start">
                        <div>
                          <h3 className="font-medium text-sm">{report.name}</h3>
                          <div className="text-xs text-muted-foreground flex items-center mt-1">
                            <Clock className="h-3 w-3 inline mr-1" />
                            {new Date(report.timestamp).toLocaleDateString()}
                          </div>
                        </div>
                        
                        {report.threatCount > 0 ? (
                          <Badge
                            variant={
                              report.critical > 0 ? "destructive" : 
                              report.high > 0 ? "outline" : "secondary"
                            }
                            className={
                              report.critical > 0 ? "border-red-500/50 bg-red-950/30" : 
                              report.high > 0 ? "border-orange-500/50 bg-orange-950/30 text-orange-400" : 
                              "border-yellow-500/50 bg-yellow-950/30 text-yellow-400"
                            }
                          >
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            {report.threatCount} {report.threatCount === 1 ? 'threat' : 'threats'}
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="border-green-500/50 bg-green-950/30 text-green-400">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Secure
                          </Badge>
                        )}
                      </div>
                      
                      <div className="flex space-x-1 mt-2">
                        {report.critical > 0 && (
                          <Badge variant="outline" className="border-red-500/50 bg-red-950/30 text-red-400 text-xs px-1.5 py-0">
                            {report.critical} Critical
                          </Badge>
                        )}
                        {report.high > 0 && (
                          <Badge variant="outline" className="border-orange-500/50 bg-orange-950/30 text-orange-400 text-xs px-1.5 py-0">
                            {report.high} High
                          </Badge>
                        )}
                        {report.medium > 0 && (
                          <Badge variant="outline" className="border-yellow-500/50 bg-yellow-950/30 text-yellow-400 text-xs px-1.5 py-0">
                            {report.medium} Medium
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Report Details Panel */}
        <Card className="lg:col-span-2 bg-card/50 backdrop-blur-sm border-cyan-900/30 shadow-lg shadow-cyan-500/5">
          {selectedReportData ? (
            <>
              <CardHeader className="pb-2 flex flex-row items-start justify-between">
                <div>
                  <CardTitle className="text-xl font-bold">{selectedReportData.name}</CardTitle>
                  <CardDescription>
                    Scanned on {new Date(selectedReportData.timestamp).toLocaleDateString()} at {new Date(selectedReportData.timestamp).toLocaleTimeString()}
                  </CardDescription>
                </div>
                <Button
                  onClick={() => generatePdfReport(selectedReportData.id)}
                  className="bg-cyan-600 hover:bg-cyan-700"
                >
                  <Download className="mr-2 h-4 w-4" />
                  Download Report
                </Button>
              </CardHeader>
              
              <CardContent>
                <Tabs defaultValue="summary">
                  <TabsList className="bg-background/50 backdrop-blur-sm mb-4">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="findings">Findings</TabsTrigger>
                    <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="summary" className="space-y-4">
                    <div className="grid grid-cols-4 gap-4">
                      <Card className="bg-white/5 border-white/10">
                        <CardHeader className="p-4 pb-2">
                          <CardTitle className="text-sm">Total Threats</CardTitle>
                        </CardHeader>
                        <CardContent className="p-4 pt-0">
                          <div className="text-3xl font-bold">
                            {selectedReportData.threatCount}
                          </div>
                        </CardContent>
                      </Card>
                      
                      <Card className="bg-white/5 border-white/10">
                        <CardHeader className="p-4 pb-2">
                          <CardTitle className="text-sm text-red-400">Critical</CardTitle>
                        </CardHeader>
                        <CardContent className="p-4 pt-0">
                          <div className="text-3xl font-bold text-red-400">
                            {selectedReportData.critical}
                          </div>
                        </CardContent>
                      </Card>
                      
                      <Card className="bg-white/5 border-white/10">
                        <CardHeader className="p-4 pb-2">
                          <CardTitle className="text-sm text-orange-400">High</CardTitle>
                        </CardHeader>
                        <CardContent className="p-4 pt-0">
                          <div className="text-3xl font-bold text-orange-400">
                            {selectedReportData.high}
                          </div>
                        </CardContent>
                      </Card>
                      
                      <Card className="bg-white/5 border-white/10">
                        <CardHeader className="p-4 pb-2">
                          <CardTitle className="text-sm text-yellow-400">Medium</CardTitle>
                        </CardHeader>
                        <CardContent className="p-4 pt-0">
                          <div className="text-3xl font-bold text-yellow-400">
                            {selectedReportData.medium}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                    
                    <Card className="bg-white/5 border-white/10">
                      <CardHeader className="p-4 pb-2">
                        <CardTitle className="text-sm">Scan Details</CardTitle>
                      </CardHeader>
                      <CardContent className="p-4 pt-2">
                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Domain</span>
                            <span className="font-medium">{selectedReportData.domain}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Scan Type</span>
                            <span className="font-medium">{selectedReportData.scanType}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Timestamp</span>
                            <span className="font-medium">{new Date(selectedReportData.timestamp).toLocaleString()}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Duration</span>
                            <span className="font-medium">{Math.floor(Math.random() * 10) + 2} minutes</span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                    
                    <div className="grid grid-cols-2 gap-4">
                      <Card className="bg-white/5 border-white/10">
                        <CardHeader className="p-4 pb-2">
                          <CardTitle className="text-sm">Most Common Vulnerabilities</CardTitle>
                        </CardHeader>
                        <CardContent className="p-4 pt-2">
                          <div className="space-y-2">
                            {['XSS Vulnerability', 'SQL Injection', 'CSRF Vulnerability'].map((vuln, i) => (
                              <div key={i} className="flex justify-between items-center">
                                <span className="text-sm">{vuln}</span>
                                <Badge variant="outline" className="text-xs border-white/10 bg-white/5">
                                  {Math.floor(Math.random() * 5) + 1}
                                </Badge>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                      
                      <Card className="bg-white/5 border-white/10">
                        <CardHeader className="p-4 pb-2">
                          <CardTitle className="text-sm">Risk Assessment</CardTitle>
                        </CardHeader>
                        <CardContent className="p-4 pt-2">
                          <div className="space-y-2">
                            <div className="flex justify-between items-center">
                              <span className="text-sm">Overall Risk</span>
                              <Badge variant="outline" className={
                                selectedReportData.critical > 0 ? "text-xs border-red-500/30 bg-red-950/30 text-red-400" :
                                selectedReportData.high > 0 ? "text-xs border-orange-500/30 bg-orange-950/30 text-orange-400" :
                                selectedReportData.medium > 0 ? "text-xs border-yellow-500/30 bg-yellow-950/30 text-yellow-400" :
                                "text-xs border-green-500/30 bg-green-950/30 text-green-400"
                              }>
                                {selectedReportData.critical > 0 ? "Critical" :
                                 selectedReportData.high > 0 ? "High" :
                                 selectedReportData.medium > 0 ? "Medium" : "Low"}
                              </Badge>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm">Data Exposure Risk</span>
                              <Badge variant="outline" className="text-xs border-orange-500/30 bg-orange-950/30 text-orange-400">
                                High
                              </Badge>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-sm">Authentication Risk</span>
                              <Badge variant="outline" className="text-xs border-yellow-500/30 bg-yellow-950/30 text-yellow-400">
                                Medium
                              </Badge>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="findings" className="space-y-4">
                    <div className="bg-white/5 border border-white/10 rounded-md overflow-hidden">
                      <div className="p-3 bg-white/5 flex justify-between items-center border-b border-white/10">
                        <h3 className="font-medium">Detailed Findings</h3>
                        <Button variant="outline" size="sm" className="h-7 text-xs bg-white/5 border-white/10">
                          <FileDown className="h-3.5 w-3.5 mr-1.5" />
                          Export
                        </Button>
                      </div>
                      
                      <ScrollArea className="h-[450px]">
                        <div className="p-3 space-y-4">
                          {selectedReportData.findings.map((finding, i) => (
                            <div key={i} className="bg-white/5 rounded-md p-3 border border-white/10">
                              <div className="flex justify-between items-start">
                                <h4 className="font-medium">{finding.type}</h4>
                                <Badge variant="outline" className={
                                  finding.severity === 'critical' ? "text-xs border-red-500/30 bg-red-950/30 text-red-400" :
                                  finding.severity === 'high' ? "text-xs border-orange-500/30 bg-orange-950/30 text-orange-400" :
                                  finding.severity === 'medium' ? "text-xs border-yellow-500/30 bg-yellow-950/30 text-yellow-400" :
                                  "text-xs border-blue-500/30 bg-blue-950/30 text-blue-400"
                                }>
                                  {finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}
                                </Badge>
                              </div>
                              
                              <div className="text-sm text-muted-foreground mt-2">
                                {finding.details}
                              </div>
                              
                              <div className="mt-2 p-2 bg-background/50 rounded border border-white/5 text-xs font-mono overflow-x-auto">
                                <div className="text-muted-foreground">URL:</div>
                                <div className="text-cyan-400">{finding.url}</div>
                              </div>
                              
                              <div className="mt-3 text-xs">
                                <h5 className="font-medium mb-1">Recommended Fix:</h5>
                                <p className="text-muted-foreground">
                                  {finding.type.includes('XSS') ? 
                                    'Implement proper input validation and output encoding to prevent script injection.' :
                                   finding.type.includes('SQL') ?
                                    'Use prepared statements or parameterized queries to prevent SQL injection attacks.' :
                                   finding.type.includes('CSRF') ?
                                    'Implement anti-CSRF tokens and validate them on form submissions.' :
                                   finding.type.includes('File') ?
                                    'Validate file paths and implement proper access controls to prevent directory traversal.' :
                                    'Sanitize all user inputs and implement proper validation checks.'}
                                </p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="recommendations" className="space-y-4">
                    <Card className="bg-white/5 border-white/10">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-base">Security Recommendations</CardTitle>
                        <CardDescription>
                          Based on the scan results, here are our recommended actions
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          <div className="p-3 border border-red-500/20 bg-red-950/20 rounded-md">
                            <h3 className="text-sm font-medium text-red-400 mb-2">Critical Priority Actions</h3>
                            <ul className="ml-5 space-y-2 text-sm list-disc">
                              <li>Implement input validation for all user-controllable data</li>
                              <li>Use prepared statements for all database queries</li>
                              <li>Fix CSRF vulnerabilities with proper token validation</li>
                            </ul>
                          </div>
                          
                          <div className="p-3 border border-orange-500/20 bg-orange-950/20 rounded-md">
                            <h3 className="text-sm font-medium text-orange-400 mb-2">High Priority Actions</h3>
                            <ul className="ml-5 space-y-2 text-sm list-disc">
                              <li>Implement Content Security Policy (CSP) headers</li>
                              <li>Enable HTTPS across all pages and implement HSTS</li>
                              <li>Sanitize file uploads and validate file extensions</li>
                            </ul>
                          </div>
                          
                          <div className="p-3 border border-yellow-500/20 bg-yellow-950/20 rounded-md">
                            <h3 className="text-sm font-medium text-yellow-400 mb-2">Medium Priority Actions</h3>
                            <ul className="ml-5 space-y-2 text-sm list-disc">
                              <li>Implement proper error handling to prevent information disclosure</li>
                              <li>Use HTTP security headers (X-Content-Type-Options, X-Frame-Options)</li>
                              <li>Implement proper session management and timeout controls</li>
                            </ul>
                          </div>
                          
                          <div className="p-3 border border-blue-500/20 bg-blue-950/20 rounded-md">
                            <h3 className="text-sm font-medium text-blue-400 mb-2">General Recommendations</h3>
                            <ul className="ml-5 space-y-2 text-sm list-disc">
                              <li>Conduct regular security audits and vulnerability scanning</li>
                              <li>Implement a security awareness training program for developers</li>
                              <li>Keep all frameworks and libraries updated to their latest versions</li>
                              <li>Consider implementing a Web Application Firewall (WAF)</li>
                            </ul>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </>
          ) : (
            <div className="flex h-full flex-col items-center justify-center py-16">
              <div className="mx-auto flex max-w-[420px] flex-col items-center justify-center text-center">
                <div className="mb-4 h-16 w-16 rounded-full bg-cyan-950/30 p-4 text-cyan-500">
                  <FileDown className="h-full w-full" />
                </div>
                <h3 className="mt-4 text-lg font-medium">No Report Selected</h3>
                <p className="mb-4 mt-2 text-sm text-muted-foreground">
                  Select a report from the list to view detailed findings and analysis.
                </p>
                <Button variant="outline" className="mt-2 bg-background/50 border-white/10">Browse Reports</Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Reports;
