import axios from 'axios';

// Create API instance
const api = axios.create({
  baseURL: 'http://localhost:5000/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request/response interceptors
api.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => {
    console.log(`API Response: ${response.config.url} - Status: ${response.status}`);
    return response;
  },
  (error) => {
    console.error(`API Error: ${error.config?.url} - ${error.message}`);
    return Promise.reject(error);
  }
);

// API Functions
export const apiService = {
  runScan: async (targetUrl: string, scanType: string, payloads: string[]) => {
    try {
      const response = await api.post('/scan', { target_url: targetUrl, scan_type: scanType, payloads: payloads });
      return response.data;
    } catch (error: any) {
      console.error('Error running scan:', error);
      throw new Error(`Scan failed: ${error.message}`);
    }
  },

  stopScan: async (sessionId: string) => {
    try {
      const response = await api.post('/stop-scan', { session_id: sessionId });
      return response.data;
    } catch (error: any) {
      console.error('Error stopping scan:', error);
      throw new Error(`Failed to stop scan: ${error.message}`);
    }
  },

  getScanStatus: async (sessionId: string) => {
    try {
      const response = await api.get(`/scan-status/${sessionId}`);
      return response.data;
    } catch (error: any) {
      console.error('Error getting scan status:', error);
      throw new Error(`Failed to get scan status: ${error.message}`);
    }
  },

  generateReport: async (sessionId: string, reportFormat: string) => {
    try {
      const response = await api.post('/generate-report', { session_id: sessionId, report_format: reportFormat });
      return response.data;
    } catch (error: any) {
      console.error('Error generating report:', error);
      throw new Error(`Failed to generate report: ${error.message}`);
    }
  },

  getSystemInfo: async () => {
    try {
      const response = await api.get('/system-info');
      return response.data;
    } catch (error: any) {
      console.error('Error getting system info:', error);
      throw new Error(`Failed to get system info: ${error.message}`);
    }
  },

  updateSystem: async (updates: any) => {
    try {
      const response = await api.post('/update-system', updates);
      return response.data;
    } catch (error: any) {
      console.error('Error updating system:', error);
      throw new Error(`Failed to update system: ${error.message}`);
    }
  },

  getPayloads: async () => {
    try {
      const response = await api.get('/payloads');
      return response.data;
    } catch (error: any) {
      console.error('Error getting payloads:', error);
      throw new Error(`Failed to get payloads: ${error.message}`);
    }
  },

  addPayload: async (payload: string, category: string) => {
    try {
      const response = await api.post('/add-payload', { payload: payload, category: category });
      return response.data;
    } catch (error: any) {
      console.error('Error adding payload:', error);
      throw new Error(`Failed to add payload: ${error.message}`);
    }
  },

  deletePayload: async (payloadId: string) => {
    try {
      const response = await api.delete(`/delete-payload/${payloadId}`);
      return response.data;
    } catch (error: any) {
      console.error('Error deleting payload:', error);
      throw new Error(`Failed to delete payload: ${error.message}`);
    }
  },

  runFuzzing: async (targetUrl: string, payloads: string[]) => {
    try {
      const response = await api.post('/fuzz', { target_url: targetUrl, payloads: payloads });
      return response.data;
    } catch (error: any) {
      console.error('Error running fuzzing:', error);
      throw new Error(`Fuzzing failed: ${error.message}`);
    }
  },

  getFuzzingStatus: async (sessionId: string) => {
    try {
      const response = await api.get(`/fuzz-status/${sessionId}`);
      return response.data;
    } catch (error: any) {
      console.error('Error getting fuzzing status:', error);
      throw new Error(`Failed to get fuzzing status: ${error.message}`);
    }
  },

  saveSettings: async (settings: any) => {
    try {
      const response = await api.post('/settings', settings);
      return response.data;
    } catch (error: any) {
      console.error('Error saving settings:', error);
      throw new Error(`Failed to save settings: ${error.message}`);
    }
  },

  getSettings: async () => {
    try {
      const response = await api.get('/settings');
      return response.data;
    } catch (error: any) {
      console.error('Error getting settings:', error);
      throw new Error(`Failed to get settings: ${error.message}`);
    }
  },

  analyzeUrl: async (url: string) => {
    try {
      const response = await api.post('/analyze-url', { url: url });
      return response.data;
    } catch (error: any) {
      console.error('Error analyzing URL:', error);
      throw new Error(`URL analysis failed: ${error.message}`);
    }
  },

  getVulnerabilities: async () => {
    try {
      const response = await api.get('/vulnerabilities');
      return response.data;
    } catch (error: any) {
      console.error('Error getting vulnerabilities:', error);
      throw new Error(`Failed to get vulnerabilities: ${error.message}`);
    }
  },

  addVulnerability: async (vulnerability: any) => {
    try {
      const response = await api.post('/vulnerabilities', vulnerability);
      return response.data;
    } catch (error: any) {
      console.error('Error adding vulnerability:', error);
      throw new Error(`Failed to add vulnerability: ${error.message}`);
    }
  },

  deleteVulnerability: async (vulnerabilityId: string) => {
    try {
      const response = await api.delete(`/vulnerabilities/${vulnerabilityId}`);
      return response.data;
    } catch (error: any) {
      console.error('Error deleting vulnerability:', error);
      throw new Error(`Failed to delete vulnerability: ${error.message}`);
    }
  },

  getThreatReports: async () => {
    try {
      const response = await api.get('/threat-reports');
      return response.data;
    } catch (error: any) {
      console.error('Error getting threat reports:', error);
      throw new Error(`Failed to get threat reports: ${error.message}`);
    }
  },

  addThreatReport: async (report: any) => {
    try {
      const response = await api.post('/threat-reports', report);
      return response.data;
    } catch (error: any) {
      console.error('Error adding threat report:', error);
      throw new Error(`Failed to add threat report: ${error.message}`);
    }
  },

  deleteThreatReport: async (reportId: string) => {
    try {
      const response = await api.delete(`/threat-reports/${reportId}`);
      return response.data;
    } catch (error: any) {
      console.error('Error deleting threat report:', error);
      throw new Error(`Failed to delete threat report: ${error.message}`);
    }
  },

  getDashboardData: async () => {
    try {
      const response = await api.get('/dashboard-data');
      return response.data;
    } catch (error: any) {
      console.error('Error getting dashboard data:', error);
      throw new Error(`Failed to get dashboard data: ${error.message}`);
    }
  },
};

export const mlApi = {
  trainClassifier: async (dataset: any[]) => {
    try {
      console.log('🎯 Training classifier model...');
      const response = await api.post('/ml/train-classifier', { dataset });
      console.log('✅ Training response:', response.data);
      return response.data;
    } catch (error: any) {
      console.error('Error training classifier:', error);
      throw new Error(`Classifier training failed: ${error.message}`);
    }
  },

  trainClassifierWithFile: async (file: File) => {
    try {
      const fileContent = await file.text();
      const lines = fileContent.split('\n').filter(line => line.trim());
      
      // Create dataset from file content
      const dataset = lines.slice(0, 100).map((line, index) => ({
        id: index,
        payload: line.trim(),
        label: Math.random() > 0.7 ? 'malicious' : 'safe',
        response_code: Math.random() > 0.8 ? 500 : 200,
        body_word_count_changed: Math.random() > 0.6,
        alert_detected: Math.random() > 0.7,
        error_detected: Math.random() > 0.8
      }));

      return await mlApi.trainClassifier(dataset);
    } catch (error: any) {
      console.error('Error training with file:', error);
      throw new Error(`File training failed: ${error.message}`);
    }
  },

  generatePayloads: async (context?: string, numSamples: number = 5) => {
    try {
      console.log(`🚀 Generating ${numSamples} payloads for context: ${context || 'general'}`);
      const response = await api.post('/ml/generate-payloads', {
        context,
        num_samples: numSamples
      });
      console.log('✅ Generated payloads:', response.data);
      return response.data;
    } catch (error: any) {
      console.error('Error generating payloads:', error);
      throw new Error(`Payload generation failed: ${error.message}`);
    }
  },

  getStatus: async () => {
    try {
      const response = await api.get('/ml/status');
      return response.data;
    } catch (error: any) {
      console.error('Error getting ML status:', error);
      throw new Error(`ML status check failed: ${error.message}`);
    }
  }
};

// Fuzzer API for backend fuzzing operations
export const fuzzerApi = {
  checkHealth: async () => {
    try {
      const response = await api.get('/health');
      return response.data;
    } catch (error: any) {
      console.error('Error checking health:', error);
      throw new Error(`Health check failed: ${error.message}`);
    }
  },

  createFuzzer: async (targetUrl: string) => {
    try {
      const response = await api.post('/fuzzer/create', { target_url: targetUrl });
      return response.data;
    } catch (error: any) {
      console.error('Error creating fuzzer:', error);
      throw new Error(`Fuzzer creation failed: ${error.message}`);
    }
  },

  startFuzzing: async (sessionId: string, vulnTypes: string[], payloads: string[]) => {
    try {
      const response = await api.post('/fuzzer/start', { 
        session_id: sessionId, 
        vulnerability_types: vulnTypes, 
        payloads: payloads 
      });
      return response.data;
    } catch (error: any) {
      console.error('Error starting fuzzing:', error);
      throw new Error(`Fuzzing start failed: ${error.message}`);
    }
  },

  stopFuzzing: async (sessionId: string) => {
    try {
      const response = await api.post('/fuzzer/stop', { session_id: sessionId });
      return response.data;
    } catch (error: any) {
      console.error('Error stopping fuzzing:', error);
      throw new Error(`Fuzzing stop failed: ${error.message}`);
    }
  },

  getFuzzingStatus: async (sessionId: string) => {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/status`);
      return response.data;
    } catch (error: any) {
      console.error('Error getting fuzzing status:', error);
      throw new Error(`Fuzzing status failed: ${error.message}`);
    }
  },

  getFuzzingResults: async (sessionId: string) => {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/results`);
      return response.data;
    } catch (error: any) {
      console.error('Error getting fuzzing results:', error);
      throw new Error(`Fuzzing results failed: ${error.message}`);
    }
  },

  checkDVWAStatus: async (url: string) => {
    try {
      const response = await api.post('/dvwa/status', { url: url });
      return response.data;
    } catch (error: any) {
      console.error('Error checking DVWA status:', error);
      throw new Error(`DVWA status check failed: ${error.message}`);
    }
  },

  connectDVWA: async (url: string, username: string, password: string) => {
    try {
      const response = await api.post('/dvwa/connect', { 
        url: url, 
        username: username, 
        password: password 
      });
      return response.data;
    } catch (error: any) {
      console.error('Error connecting to DVWA:', error);
      throw new Error(`DVWA connection failed: ${error.message}`);
    }
  }
};
