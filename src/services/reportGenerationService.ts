import { supabase } from '@/integrations/supabase/client';
import { backendService } from './backendService';
import JSZip from 'jszip';
import { saveAs } from 'file-saver';

export interface ReportConfig {
  sessionId: string;
  includeCharts: boolean;
  includeExecutiveSummary: boolean;
  includeVulnerabilityDetails: boolean;
  includeTechnicalDetails: boolean;
}

export interface ExecutiveSummary {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityScore: number;
  recommendations: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

class ReportGenerationService {
  async generateExecutiveSummary(sessionId: string): Promise<ExecutiveSummary> {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      // Get session data
      const { data: session } = await supabase
        .from('fuzzing_sessions')
        .select('*')
        .eq('session_id', sessionId)
        .eq('user_id', user.id)
        .single();

      if (!session) throw new Error('Session not found');

      // Get vulnerabilities for this session
      const { data: vulnerabilities } = await supabase
        .from('vulnerability_findings')
        .select('*')
        .eq('fuzzing_session_id', session.id)
        .eq('user_id', user.id);

      if (!vulnerabilities) {
        throw new Error('Failed to fetch vulnerabilities');
      }

      // Calculate summary statistics
      const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
      const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
      const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
      const lowCount = vulnerabilities.filter(v => v.severity === 'low').length;
      const totalVulnerabilities = vulnerabilities.length;

      // Calculate security score (0-100, higher is better)
      let securityScore = 100;
      securityScore -= criticalCount * 25;
      securityScore -= highCount * 15;
      securityScore -= mediumCount * 5;
      securityScore -= lowCount * 1;
      securityScore = Math.max(0, securityScore);

      // Determine risk level
      let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
      if (criticalCount > 0) riskLevel = 'critical';
      else if (highCount > 2) riskLevel = 'high';
      else if (highCount > 0 || mediumCount > 5) riskLevel = 'medium';

      // Generate recommendations
      const recommendations: string[] = [];
      if (criticalCount > 0) {
        recommendations.push('Immediately address all critical vulnerabilities as they pose severe security risks');
      }
      if (highCount > 0) {
        recommendations.push('Prioritize fixing high-severity vulnerabilities within the next sprint');
      }
      if (mediumCount > 3) {
        recommendations.push('Develop a plan to systematically address medium-severity issues');
      }
      if (totalVulnerabilities > 10) {
        recommendations.push('Consider implementing automated security testing in your CI/CD pipeline');
      }
      if (securityScore < 70) {
        recommendations.push('Conduct a comprehensive security audit of the application');
      }

      // Get AI-generated summary from backend
      try {
        const backendSummary = await backendService.generateExecutiveSummary(sessionId);
        if (backendSummary.recommendations) {
          recommendations.push(...backendSummary.recommendations);
        }
      } catch (error) {
        console.warn('Backend executive summary not available:', error);
      }

      return {
        totalVulnerabilities,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        securityScore,
        recommendations: [...new Set(recommendations)], // Remove duplicates
        riskLevel
      };

    } catch (error) {
      console.error('❌ Failed to generate executive summary:', error);
      throw error;
    }
  }

  async prioritizeVulnerabilities(sessionId: string) {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      // Get session vulnerabilities
      const { data: session } = await supabase
        .from('fuzzing_sessions')
        .select('id')
        .eq('session_id', sessionId)
        .eq('user_id', user.id)
        .single();

      if (!session) throw new Error('Session not found');

      const { data: vulnerabilities } = await supabase
        .from('vulnerability_findings')
        .select('*')
        .eq('fuzzing_session_id', session.id)
        .eq('user_id', user.id);

      if (!vulnerabilities) return [];

      // Use backend AI to prioritize vulnerabilities
      try {
        const prioritized = await backendService.prioritizeVulnerabilities(vulnerabilities);
        return prioritized.vulnerabilities || vulnerabilities;
      } catch (error) {
        console.warn('Backend prioritization not available, using local logic:', error);
        
        // Fallback: Local prioritization logic
        return vulnerabilities.sort((a, b) => {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          const aSeverity = severityOrder[a.severity as keyof typeof severityOrder] || 0;
          const bSeverity = severityOrder[b.severity as keyof typeof severityOrder] || 0;
          
          if (aSeverity !== bSeverity) return bSeverity - aSeverity;
          
          // Secondary sort by CVSS score
          const aCvss = a.cvss_score || 0;
          const bCvss = b.cvss_score || 0;
          return bCvss - aCvss;
        });
      }

    } catch (error) {
      console.error('❌ Failed to prioritize vulnerabilities:', error);
      throw error;
    }
  }

  async generatePDFReport(config: ReportConfig): Promise<Blob> {
    try {
      // Try to generate PDF using Python backend
      const pdfBlob = await backendService.generatePDFReport(config.sessionId, config.includeCharts);
      return pdfBlob;

    } catch (error) {
      console.error('❌ Backend PDF generation failed:', error);
      throw new Error('PDF report generation is currently unavailable. Please ensure the Python backend is running.');
    }
  }

  async generateComprehensiveReport(config: ReportConfig) {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      const zip = new JSZip();

      // Get session data
      const { data: session } = await supabase
        .from('fuzzing_sessions')
        .select('*')
        .eq('session_id', config.sessionId)
        .eq('user_id', user.id)
        .single();

      if (!session) throw new Error('Session not found');

      // Get vulnerabilities
      const { data: vulnerabilities } = await supabase
        .from('vulnerability_findings')
        .select('*')
        .eq('fuzzing_session_id', session.id);

      // Generate executive summary
      let executiveSummary = null;
      if (config.includeExecutiveSummary) {
        executiveSummary = await this.generateExecutiveSummary(config.sessionId);
        zip.file('executive-summary.json', JSON.stringify(executiveSummary, null, 2));
      }

      // Generate prioritized vulnerabilities
      const prioritizedVulns = await this.prioritizeVulnerabilities(config.sessionId);
      zip.file('prioritized-vulnerabilities.json', JSON.stringify(prioritizedVulns, null, 2));

      // Add session information
      zip.file('session-info.json', JSON.stringify(session, null, 2));

      // Add detailed vulnerability data
      if (config.includeVulnerabilityDetails && vulnerabilities) {
        zip.file('vulnerability-details.json', JSON.stringify(vulnerabilities, null, 2));
      }

      // Try to generate and include PDF report
      if (config.includeCharts) {
        try {
          const pdfBlob = await this.generatePDFReport(config);
          zip.file('security-report.pdf', pdfBlob);
        } catch (error) {
          console.warn('PDF generation failed, skipping PDF in report:', error);
        }
      }

      // Generate HTML summary report
      const htmlReport = this.generateHTMLReport(session, vulnerabilities || [], executiveSummary, prioritizedVulns);
      zip.file('security-report.html', htmlReport);

      // Generate the zip file
      const zipBlob = await zip.generateAsync({ type: 'blob' });
      
      // Download the comprehensive report
      const timestamp = new Date().toISOString().split('T')[0];
      saveAs(zipBlob, `security-report-${config.sessionId}-${timestamp}.zip`);

      return {
        success: true,
        message: 'Comprehensive report generated successfully'
      };

    } catch (error) {
      console.error('❌ Failed to generate comprehensive report:', error);
      throw error;
    }
  }

  private generateHTMLReport(
    session: any, 
    vulnerabilities: any[], 
    executiveSummary: ExecutiveSummary | null,
    prioritizedVulns: any[]
  ): string {
    const timestamp = new Date().toISOString();
    
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .header { background: #1a1a1a; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vulnerability { background: white; padding: 15px; margin: 10px 0; border-radius: 6px; border-left: 4px solid #ddd; }
        .critical { border-left-color: #dc2626; }
        .high { border-left-color: #ea580c; }
        .medium { border-left-color: #ca8a04; }
        .low { border-left-color: #16a34a; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }
        .badge.critical { background: #dc2626; }
        .badge.high { background: #ea580c; }
        .badge.medium { background: #ca8a04; }
        .badge.low { background: #16a34a; }
        h1, h2, h3 { color: #1a1a1a; }
        .footer { text-align: center; margin-top: 40px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> ${session.target_url}</p>
        <p><strong>Session ID:</strong> ${session.session_id}</p>
        <p><strong>Date:</strong> ${new Date(session.created_at).toLocaleDateString()}</p>
        <p><strong>Report Generated:</strong> ${new Date(timestamp).toLocaleString()}</p>
    </div>

    ${executiveSummary ? `
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Security Score:</strong> ${executiveSummary.securityScore}/100</p>
        <p><strong>Risk Level:</strong> <span class="badge ${executiveSummary.riskLevel}">${executiveSummary.riskLevel.toUpperCase()}</span></p>
        <p><strong>Total Vulnerabilities:</strong> ${executiveSummary.totalVulnerabilities}</p>
        
        <h3>Vulnerability Breakdown</h3>
        <ul>
            <li>Critical: ${executiveSummary.criticalCount}</li>
            <li>High: ${executiveSummary.highCount}</li>
            <li>Medium: ${executiveSummary.mediumCount}</li>
            <li>Low: ${executiveSummary.lowCount}</li>
        </ul>

        <h3>Key Recommendations</h3>
        <ul>
            ${executiveSummary.recommendations.map(rec => `<li>${rec}</li>`).join('')}
        </ul>
    </div>
    ` : ''}

    <div class="summary">
        <h2>Vulnerability Findings (${prioritizedVulns.length} total)</h2>
        ${prioritizedVulns.map((vuln, index) => `
        <div class="vulnerability ${vuln.severity}">
            <h3>#${index + 1} - ${vuln.vulnerability_type}</h3>
            <p><strong>Severity:</strong> <span class="badge ${vuln.severity}">${vuln.severity.toUpperCase()}</span></p>
            <p><strong>Payload:</strong> <code>${vuln.payload}</code></p>
            ${vuln.target_parameter ? `<p><strong>Parameter:</strong> ${vuln.target_parameter}</p>` : ''}
            ${vuln.response_code ? `<p><strong>Response Code:</strong> ${vuln.response_code}</p>` : ''}
            ${vuln.cvss_score ? `<p><strong>CVSS Score:</strong> ${vuln.cvss_score}</p>` : ''}
            ${vuln.remediation_suggestion ? `<p><strong>Remediation:</strong> ${vuln.remediation_suggestion}</p>` : ''}
        </div>
        `).join('')}
    </div>

    <div class="footer">
        <p>This report was generated automatically by the Security Testing Platform</p>
        <p>For questions about this report, please contact your security team</p>
    </div>
</body>
</html>
    `;
  }
}

export const reportGenerationService = new ReportGenerationService();