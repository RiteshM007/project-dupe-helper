import { supabase } from '@/integrations/supabase/client';
import { backendService } from './backendService';

export interface FuzzingConfig {
  target_url: string;
  payloads: string[];
  fuzzing_type: 'web_application' | 'api' | 'dvwa';
  max_threads?: number;
  delay_between_requests?: number;
  authentication?: {
    username: string;
    password: string;
  };
}

export interface VulnerabilityFinding {
  vulnerability_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  payload: string;
  target_parameter?: string;
  response_code?: number;
  response_time?: number;
  evidence: any;
  remediation_suggestion?: string;
  cvss_score?: number;
}

class AdvancedFuzzingService {
  async startFuzzingSession(config: FuzzingConfig): Promise<string> {
    try {
      // Get current user
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      // Create fuzzing session in database
      const sessionId = `fuzzing_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      const { error: sessionError } = await supabase
        .from('fuzzing_sessions')
        .insert({
          user_id: user.id,
          session_id: sessionId,
          target_url: config.target_url,
          fuzzing_type: config.fuzzing_type,
          status: 'pending',
          total_payloads: config.payloads.length,
          configuration: config as any
        });

      if (sessionError) throw sessionError;

      // Start fuzzing on Python backend
      const backendResponse = await backendService.startFuzzingSession(config);

      if (!backendResponse.success) {
        throw new Error(backendResponse.error || 'Failed to start fuzzing session');
      }

      // Update session status
      await supabase
        .from('fuzzing_sessions')
        .update({ 
          status: 'running',
          started_at: new Date().toISOString()
        })
        .eq('session_id', sessionId);

      return sessionId;

    } catch (error) {
      console.error('❌ Failed to start fuzzing session:', error);
      throw error;
    }
  }

  async getFuzzingProgress(sessionId: string) {
    try {
      // Get progress from Python backend
      const backendStatus = await backendService.getFuzzingStatus(sessionId);
      
      // Update database with latest progress
      const { data: { user } } = await supabase.auth.getUser();
      if (user) {
        await supabase
          .from('fuzzing_sessions')
          .update({
            tested_payloads: backendStatus.tested_payloads,
            vulnerabilities_found: backendStatus.vulnerabilities_found,
            status: backendStatus.status,
            completed_at: backendStatus.status === 'completed' ? new Date().toISOString() : null
          })
          .eq('session_id', sessionId)
          .eq('user_id', user.id);
      }

      return backendStatus;

    } catch (error) {
      console.error('❌ Failed to get fuzzing progress:', error);
      throw error;
    }
  }

  async stopFuzzingSession(sessionId: string) {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      // Stop fuzzing on backend
      await backendService.stopFuzzingSession(sessionId);

      // Update session status in database
      await supabase
        .from('fuzzing_sessions')
        .update({ 
          status: 'stopped',
          completed_at: new Date().toISOString()
        })
        .eq('session_id', sessionId)
        .eq('user_id', user.id);

      return { success: true };

    } catch (error) {
      console.error('❌ Failed to stop fuzzing session:', error);
      throw error;
    }
  }

  async recordVulnerabilityFinding(sessionId: string, finding: VulnerabilityFinding) {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      // Get fuzzing session
      const { data: session } = await supabase
        .from('fuzzing_sessions')
        .select('id')
        .eq('session_id', sessionId)
        .eq('user_id', user.id)
        .single();

      if (!session) throw new Error('Fuzzing session not found');

      // Record vulnerability finding
      const { error } = await supabase
        .from('vulnerability_findings')
        .insert({
          user_id: user.id,
          fuzzing_session_id: session.id,
          ...finding,
          discovered_at: new Date().toISOString()
        });

      if (error) throw error;

      // Update session vulnerability count - commented out as RPC function needs to be created
      // await supabase.rpc('increment_vulnerability_count', {
      //   session_uuid: session.id
      // });

      return { success: true };

    } catch (error) {
      console.error('❌ Failed to record vulnerability finding:', error);
      throw error;
    }
  }

  async analyzeVulnerabilities(sessionId: string) {
    try {
      // Get vulnerability analysis from Python backend
      const analysis = await backendService.analyzeVulnerabilities(sessionId);
      
      // Store analysis results for each vulnerability
      if (analysis.vulnerabilities) {
        for (const vuln of analysis.vulnerabilities) {
          await this.recordVulnerabilityFinding(sessionId, vuln);
        }
      }

      return analysis;

    } catch (error) {
      console.error('❌ Vulnerability analysis failed:', error);
      throw error;
    }
  }

  async connectToDVWA(dvwaUrl: string, credentials: { username: string; password: string }) {
    try {
      const response = await backendService.connectToDVWA(dvwaUrl, credentials);
      return response;
    } catch (error) {
      console.error('❌ DVWA connection failed:', error);
      throw error;
    }
  }

  async runDVWATests(sessionId: string, testTypes: string[]) {
    try {
      const results = await backendService.runDVWATests(sessionId, testTypes);
      
      // Process and store DVWA test results
      if (results.vulnerabilities) {
        for (const vuln of results.vulnerabilities) {
          await this.recordVulnerabilityFinding(sessionId, vuln);
        }
      }

      return results;
    } catch (error) {
      console.error('❌ DVWA tests failed:', error);
      throw error;
    }
  }

  async getUserFuzzingSessions(limit: number = 50) {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      const { data, error } = await supabase
        .from('fuzzing_sessions')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(limit);

      if (error) throw error;
      return data || [];

    } catch (error) {
      console.error('❌ Failed to get user fuzzing sessions:', error);
      throw error;
    }
  }

  async getSessionVulnerabilities(sessionId: string) {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('User not authenticated');

      // Get session first
      const { data: session } = await supabase
        .from('fuzzing_sessions')
        .select('id')
        .eq('session_id', sessionId)
        .eq('user_id', user.id)
        .single();

      if (!session) throw new Error('Session not found');

      // Get vulnerabilities for this session
      const { data, error } = await supabase
        .from('vulnerability_findings')
        .select('*')
        .eq('fuzzing_session_id', session.id)
        .eq('user_id', user.id)
        .order('discovered_at', { ascending: false });

      if (error) throw error;
      return data || [];

    } catch (error) {
      console.error('❌ Failed to get session vulnerabilities:', error);
      throw error;
    }
  }
}

export const advancedFuzzingService = new AdvancedFuzzingService();