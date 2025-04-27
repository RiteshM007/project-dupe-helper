
import JSZip from 'jszip';
import { saveAs } from 'file-saver';

interface ScanReport {
  id: string;
  timestamp: string;
  vulnerabilities: any[];
  payloads: string[];
  responses: any[];
  summary: {
    totalScans: number;
    vulnerabilitiesDetected: number;
    securityScore: number;
  };
}

// Mock data generator - in a real app, this would come from an API
const generateMockScanReports = (): ScanReport[] => {
  return Array.from({ length: 3 }, (_, i) => ({
    id: `scan-${Date.now()}-${i}`,
    timestamp: new Date().toISOString(),
    vulnerabilities: [
      { type: 'XSS', severity: 'High', count: Math.floor(Math.random() * 5) },
      { type: 'SQL Injection', severity: 'Critical', count: Math.floor(Math.random() * 3) },
      { type: 'CSRF', severity: 'Medium', count: Math.floor(Math.random() * 7) },
    ],
    payloads: [
      "<script>alert('XSS')</script>",
      "' OR 1=1 --",
      "../../../etc/passwd",
      "admin' --",
    ],
    responses: Array.from({ length: 4 }, (_, j) => ({
      status: [200, 403, 500][Math.floor(Math.random() * 3)],
      body: `Response body ${j}`,
      headers: { 'Content-Type': 'text/html' },
    })),
    summary: {
      totalScans: 25 + Math.floor(Math.random() * 50),
      vulnerabilitiesDetected: 3 + Math.floor(Math.random() * 10),
      securityScore: Math.floor(Math.random() * 100),
    },
  }));
};

// Generate ML dataset
const generateMLDataset = () => {
  return Array.from({ length: 30 }, (_, i) => ({
    payload: `Payload ${i}`,
    response_code: [200, 403, 500][Math.floor(Math.random() * 3)],
    alert_detected: Math.random() > 0.7,
    error_detected: Math.random() > 0.8,
    body_word_count_changed: Math.random() > 0.5,
    vulnerability_type: ['xss', 'sqli', 'lfi', 'rce', 'csrf'][Math.floor(Math.random() * 5)],
    label: ['safe', 'suspicious', 'malicious'][Math.floor(Math.random() * 3)],
    severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
  }));
};

// Generate a summary report
const generateSummaryReport = (scanReports: ScanReport[]) => {
  const totalVulnerabilities = scanReports.reduce(
    (sum, report) => sum + report.summary.vulnerabilitiesDetected,
    0
  );
  
  const averageSecurityScore = scanReports.reduce(
    (sum, report) => sum + report.summary.securityScore,
    0
  ) / scanReports.length;
  
  const vulnerabilityTypes = new Map();
  
  scanReports.forEach(report => {
    report.vulnerabilities.forEach(vuln => {
      const count = vulnerabilityTypes.get(vuln.type) || 0;
      vulnerabilityTypes.set(vuln.type, count + vuln.count);
    });
  });
  
  return {
    generatedAt: new Date().toISOString(),
    scansPeriod: `${scanReports[0].timestamp} to ${scanReports[scanReports.length - 1].timestamp}`,
    totalScans: scanReports.reduce((sum, report) => sum + report.summary.totalScans, 0),
    totalVulnerabilities,
    averageSecurityScore,
    vulnerabilityBreakdown: Array.from(vulnerabilityTypes.entries()).map(([type, count]) => ({
      type,
      count,
    })),
    recommendation: totalVulnerabilities > 10 
      ? "Critical: Immediate remediation recommended" 
      : totalVulnerabilities > 5 
      ? "Warning: Security improvements needed" 
      : "Good: Continue monitoring regularly",
  };
};

// Main function to download scan reports
export const downloadScanReport = async () => {
  const zip = new JSZip();
  
  // Get data - in real app, this would be API calls
  const scanReports = generateMockScanReports();
  const mlDataset = generateMLDataset();
  const summary = generateSummaryReport(scanReports);
  
  // Add individual scan reports
  const reportsFolder = zip.folder("scan_reports");
  scanReports.forEach((report, index) => {
    reportsFolder?.file(`scan_report_${index + 1}.json`, JSON.stringify(report, null, 2));
  });
  
  // Add ML dataset
  zip.file("ml_dataset.json", JSON.stringify(mlDataset, null, 2));
  
  // Add summary report
  zip.file("vulnerability_analysis.json", JSON.stringify(summary, null, 2));
  
  // Add a CSV version of the dataset for easy import
  const csvHeader = "payload,response_code,alert_detected,error_detected,body_word_count_changed,vulnerability_type,label,severity";
  const csvContent = mlDataset.map(item => 
    `"${item.payload}",${item.response_code},${item.alert_detected},${item.error_detected},${item.body_word_count_changed},"${item.vulnerability_type}","${item.label}","${item.severity}"`
  ).join("\n");
  
  zip.file("ml_dataset.csv", csvHeader + "\n" + csvContent);
  
  // Generate and trigger download
  const content = await zip.generateAsync({ type: "blob" });
  saveAs(content, `web_fuzzer_report_${Date.now()}.zip`);
};
