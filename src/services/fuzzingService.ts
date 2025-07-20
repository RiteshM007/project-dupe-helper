import { supabase } from '@/integrations/supabase/client';

export interface FuzzingSession {
  id: string;
  sessionId: string;
  targetUrl: string;
  fuzzingType: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  totalPayloads: number;
  testedPayloads: number;
  vulnerabilitiesFound: number;
  scanDuration?: number;
  startedAt: string;
  completedAt?: string;
  configuration?: any;
  resultsSummary?: any;
}

export interface VulnerabilityFinding {
  id: string;
  vulnerabilityType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  payload: string;
  targetParameter?: string;
  responseCode?: number;
  responseTime?: number;
  evidence?: any;
  remediationSuggestion?: string;
  cvssScore?: number;
  discoveredAt: string;
}

export interface ThreatReport {
  id: string;
  title: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  threatType: string;
  source: string;
  targetInfo?: any;
  detectionDetails?: any;
  status: 'active' | 'resolved' | 'investigating';
  resolvedAt?: string;
  createdAt: string;
}

// Helper function to get current user
const getCurrentUser = async () => {
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) {
    throw new Error('User not authenticated');
  }
  return user;
};

export const fuzzingService = {
  // Create a new fuzzing session
  createSession: async (targetUrl: string, configuration?: any): Promise<FuzzingSession> => {
    const user = await getCurrentUser();
    const sessionId = `fuzzing_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const sessionData = {
      user_id: user.id,
      session_id: sessionId,
      target_url: targetUrl,
      fuzzing_type: 'web_application',
      status: 'pending',
      total_payloads: 0,
      tested_payloads: 0,
      vulnerabilities_found: 0,
      configuration: configuration || {}
    };

    const { data, error } = await supabase
      .from('fuzzing_sessions')
      .insert(sessionData)
      .select()
      .single();

    if (error) {
      throw new Error(`Failed to create fuzzing session: ${error.message}`);
    }

    return {
      id: data.id,
      sessionId: data.session_id,
      targetUrl: data.target_url,
      fuzzingType: data.fuzzing_type,
      status: data.status as 'pending' | 'running' | 'completed' | 'failed',
      totalPayloads: data.total_payloads,
      testedPayloads: data.tested_payloads,
      vulnerabilitiesFound: data.vulnerabilities_found,
      scanDuration: data.scan_duration,
      startedAt: data.started_at,
      completedAt: data.completed_at,
      configuration: data.configuration,
      resultsSummary: data.results_summary
    };
  },

  // Start fuzzing session
  startSession: async (sessionId: string, payloads: string[]): Promise<void> => {
    const user = await getCurrentUser();

    // Update session status and payload count
    const { error } = await supabase
      .from('fuzzing_sessions')
      .update({
        status: 'running',
        total_payloads: payloads.length,
        started_at: new Date().toISOString()
      })
      .eq('session_id', sessionId)
      .eq('user_id', user.id);

    if (error) {
      throw new Error(`Failed to start fuzzing session: ${error.message}`);
    }
  },

  // Update session progress
  updateSessionProgress: async (sessionId: string, testedPayloads: number, vulnerabilitiesFound: number): Promise<void> => {
    const user = await getCurrentUser();

    const { error } = await supabase
      .from('fuzzing_sessions')
      .update({
        tested_payloads: testedPayloads,
        vulnerabilities_found: vulnerabilitiesFound
      })
      .eq('session_id', sessionId)
      .eq('user_id', user.id);

    if (error) {
      console.error('Failed to update session progress:', error);
    }
  },

  // Complete fuzzing session
  completeSession: async (sessionId: string, resultsSummary: any): Promise<void> => {
    const user = await getCurrentUser();

    const { error } = await supabase
      .from('fuzzing_sessions')
      .update({
        status: 'completed',
        completed_at: new Date().toISOString(),
        results_summary: resultsSummary
      })
      .eq('session_id', sessionId)
      .eq('user_id', user.id);

    if (error) {
      throw new Error(`Failed to complete fuzzing session: ${error.message}`);
    }
  },

  // Get user's fuzzing sessions
  getUserSessions: async (): Promise<FuzzingSession[]> => {
    const user = await getCurrentUser();

    const { data, error } = await supabase
      .from('fuzzing_sessions')
      .select('*')
      .eq('user_id', user.id)
      .order('started_at', { ascending: false });

    if (error) {
      throw new Error(`Failed to fetch sessions: ${error.message}`);
    }

    return data.map(session => ({
      id: session.id,
      sessionId: session.session_id,
      targetUrl: session.target_url,
      fuzzingType: session.fuzzing_type,
      status: session.status as 'pending' | 'running' | 'completed' | 'failed',
      totalPayloads: session.total_payloads,
      testedPayloads: session.tested_payloads,
      vulnerabilitiesFound: session.vulnerabilities_found,
      scanDuration: session.scan_duration,
      startedAt: session.started_at,
      completedAt: session.completed_at,
      configuration: session.configuration,
      resultsSummary: session.results_summary
    }));
  },

  // Record vulnerability finding
  recordVulnerability: async (
    sessionId: string,
    vulnerabilityData: Omit<VulnerabilityFinding, 'id' | 'discoveredAt'>
  ): Promise<VulnerabilityFinding> => {
    const user = await getCurrentUser();

    // Get the session to link the vulnerability
    const { data: session } = await supabase
      .from('fuzzing_sessions')
      .select('id')
      .eq('session_id', sessionId)
      .eq('user_id', user.id)
      .single();

    if (!session) {
      throw new Error('Fuzzing session not found');
    }

    const vulnerabilityInsert = {
      user_id: user.id,
      fuzzing_session_id: session.id,
      vulnerability_type: vulnerabilityData.vulnerabilityType,
      severity: vulnerabilityData.severity,
      payload: vulnerabilityData.payload,
      target_parameter: vulnerabilityData.targetParameter,
      response_code: vulnerabilityData.responseCode,
      response_time: vulnerabilityData.responseTime,
      evidence: vulnerabilityData.evidence,
      remediation_suggestion: vulnerabilityData.remediationSuggestion,
      cvss_score: vulnerabilityData.cvssScore
    };

    const { data, error } = await supabase
      .from('vulnerability_findings')
      .insert(vulnerabilityInsert)
      .select()
      .single();

    if (error) {
      throw new Error(`Failed to record vulnerability: ${error.message}`);
    }

    return {
      id: data.id,
      vulnerabilityType: data.vulnerability_type,
      severity: data.severity as 'low' | 'medium' | 'high' | 'critical',
      payload: data.payload,
      targetParameter: data.target_parameter,
      responseCode: data.response_code,
      responseTime: data.response_time,
      evidence: data.evidence,
      remediationSuggestion: data.remediation_suggestion,
      cvssScore: data.cvss_score,
      discoveredAt: data.discovered_at
    };
  },

  // Get vulnerability findings for a session
  getSessionVulnerabilities: async (sessionId: string): Promise<VulnerabilityFinding[]> => {
    const user = await getCurrentUser();

    const { data, error } = await supabase
      .from('vulnerability_findings')
      .select(`
        *,
        fuzzing_sessions!inner(session_id)
      `)
      .eq('user_id', user.id)
      .eq('fuzzing_sessions.session_id', sessionId);

    if (error) {
      throw new Error(`Failed to fetch vulnerabilities: ${error.message}`);
    }

    return data.map(vuln => ({
      id: vuln.id,
      vulnerabilityType: vuln.vulnerability_type,
      severity: vuln.severity as 'low' | 'medium' | 'high' | 'critical',
      payload: vuln.payload,
      targetParameter: vuln.target_parameter,
      responseCode: vuln.response_code,
      responseTime: vuln.response_time,
      evidence: vuln.evidence,
      remediationSuggestion: vuln.remediation_suggestion,
      cvssScore: vuln.cvss_score,
      discoveredAt: vuln.discovered_at
    }));
  },

  // Create threat report
  createThreatReport: async (reportData: Omit<ThreatReport, 'id' | 'createdAt'>): Promise<ThreatReport> => {
    const user = await getCurrentUser();

    const reportInsert = {
      user_id: user.id,
      title: reportData.title,
      description: reportData.description,
      severity: reportData.severity,
      threat_type: reportData.threatType,
      source: reportData.source,
      target_info: reportData.targetInfo,
      detection_details: reportData.detectionDetails,
      status: reportData.status
    };

    const { data, error } = await supabase
      .from('threat_reports')
      .insert(reportInsert)
      .select()
      .single();

    if (error) {
      throw new Error(`Failed to create threat report: ${error.message}`);
    }

    return {
      id: data.id,
      title: data.title,
      description: data.description,
      severity: data.severity as 'low' | 'medium' | 'high' | 'critical',
      threatType: data.threat_type,
      source: data.source,
      targetInfo: data.target_info,
      detectionDetails: data.detection_details,
      status: data.status as 'active' | 'resolved' | 'investigating',
      resolvedAt: data.resolved_at,
      createdAt: data.created_at
    };
  },

  // Get user's threat reports
  getUserThreatReports: async (): Promise<ThreatReport[]> => {
    const user = await getCurrentUser();

    const { data, error } = await supabase
      .from('threat_reports')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });

    if (error) {
      throw new Error(`Failed to fetch threat reports: ${error.message}`);
    }

    return data.map(report => ({
      id: report.id,
      title: report.title,
      description: report.description,
      severity: report.severity as 'low' | 'medium' | 'high' | 'critical',
      threatType: report.threat_type,
      source: report.source,
      targetInfo: report.target_info,
      detectionDetails: report.detection_details,
      status: report.status as 'active' | 'resolved' | 'investigating',
      resolvedAt: report.resolved_at,
      createdAt: report.created_at
    }));
  }
};