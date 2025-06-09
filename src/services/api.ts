
import axios from 'axios';

// Create a base axios instance with default settings
const api = axios.create({
  baseURL: 'http://localhost:5000/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Remove simulation mode - we want real backend connection
const SIMULATION_MODE = false;

// Add request interceptor for logging
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

// Add response interceptor for logging
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

export const fuzzerApi = {
  // Create a new fuzzer session
  async createFuzzer(targetUrl: string, wordlist: string = 'default_wordlist.txt') {
    try {
      console.log(`Creating fuzzer session for ${targetUrl}`);
      const response = await api.post('/fuzzer/create', {
        targetUrl,
        wordlistFile: wordlist,
      });
      return response.data;
    } catch (error: any) {
      console.error('Error creating fuzzer:', error);
      throw new Error(`Failed to create fuzzer: ${error.message}`);
    }
  },

  // Start the fuzzing process
  async startFuzzing(sessionId: string, vulnerabilityTypes: string[], payloads: string[] = []) {
    try {
      console.log(`Starting fuzzing for session ${sessionId}`);
      const response = await api.post(`/fuzzer/${sessionId}/start`, {
        vulnerabilityTypes,
        customPayloads: payloads,
      });
      return response.data;
    } catch (error: any) {
      console.error('Error starting fuzzing:', error);
      throw new Error(`Failed to start fuzzing: ${error.message}`);
    }
  },

  // Stop an ongoing fuzzing process
  async stopFuzzing(sessionId: string) {
    try {
      console.log(`Stopping fuzzing for session ${sessionId}`);
      const response = await api.post(`/fuzzer/${sessionId}/stop`);
      return response.data;
    } catch (error: any) {
      console.error('Error stopping fuzzing:', error);
      throw new Error(`Failed to stop fuzzing: ${error.message}`);
    }
  },

  // Get the status of a fuzzing session
  async getFuzzingStatus(sessionId: string) {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/status`);
      return response.data;
    } catch (error: any) {
      console.error('Error getting fuzzing status:', error);
      throw new Error(`Failed to get fuzzing status: ${error.message}`);
    }
  },

  // Get results from a fuzzing session
  async getFuzzingResults(sessionId: string) {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/results`);
      return response.data;
    } catch (error: any) {
      console.error('Error getting fuzzing results:', error);
      throw new Error(`Failed to get fuzzing results: ${error.message}`);
    }
  },

  // Check backend health
  async checkHealth() {
    try {
      const response = await api.get('/health');
      return response.data;
    } catch (error: any) {
      console.error('Backend health check failed:', error);
      throw new Error(`Backend not available: ${error.message}`);
    }
  },

  // Connect to DVWA
  async connectDVWA(url: string, username: string = 'admin', password: string = 'password') {
    try {
      console.log(`Connecting to DVWA at ${url}`);
      const response = await api.get('/dvwa/connect', {
        params: { url, username, password }
      });
      return response.data;
    } catch (error: any) {
      console.error('Error connecting to DVWA:', error);
      throw new Error(`Failed to connect to DVWA: ${error.message}`);
    }
  },

  // Check DVWA status
  async checkDVWAStatus(url: string) {
    try {
      const response = await api.get('/dvwa/status', {
        params: { url }
      });
      return response.data;
    } catch (error: any) {
      console.error('Error checking DVWA status:', error);
      throw new Error(`Failed to check DVWA status: ${error.message}`);
    }
  },
};

export const mlApi = {
  // Train classifier with dataset
  async trainClassifier(dataset: any[]) {
    try {
      console.log(`Training classifier with ${dataset.length} samples`);
      const response = await api.post('/ml/train-and-analyze', {
        dataset: dataset
      });
      return response.data;
    } catch (error: any) {
      console.error('Error training classifier:', error);
      throw new Error(`Failed to train classifier: ${error.message}`);
    }
  },

  // Train classifier with uploaded file
  async trainClassifierWithFile(file: File) {
    try {
      console.log(`Training classifier with uploaded file: ${file.name}`);
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await api.post('/ml/train-and-analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return response.data;
    } catch (error: any) {
      console.error('Error training classifier with file:', error);
      throw new Error(`Failed to train classifier: ${error.message}`);
    }
  },

  // Generate enhanced payloads
  async generatePayloads(vulnerabilityType?: string, numSamples: number = 5) {
    try {
      console.log(`Generating ${numSamples} payloads for ${vulnerabilityType || 'general'}`);
      const response = await api.post('/ml/generate-payloads', {
        vulnerability_type: vulnerabilityType,
        num_samples: numSamples
      });
      return response.data;
    } catch (error: any) {
      console.error('Error generating payloads:', error);
      throw new Error(`Failed to generate payloads: ${error.message}`);
    }
  },

  // Train traditional ML models
  async trainModels(dataset: any[]) {
    try {
      console.log(`Training ML models with ${dataset.length} samples`);
      const response = await api.post('/ml/train', {
        dataset: dataset
      });
      return response.data;
    } catch (error: any) {
      console.error('Error training ML models:', error);
      throw new Error(`Failed to train ML models: ${error.message}`);
    }
  },

  // Analyze dataset with clustering
  async analyzeDataset(dataset: any[], options: any = {}) {
    try {
      console.log(`Analyzing dataset with ${dataset.length} samples`);
      const response = await api.post('/ml/analyze', {
        dataset: dataset,
        options: options
      });
      return response.data;
    } catch (error: any) {
      console.error('Error analyzing dataset:', error);
      throw new Error(`Failed to analyze dataset: ${error.message}`);
    }
  },

  // Generate security report
  async generateReport(results: any[], modelInfo: any = {}) {
    try {
      console.log('Generating security report');
      const response = await api.post('/ml/generate-report', {
        results: results,
        modelInfo: modelInfo
      });
      return response.data;
    } catch (error: any) {
      console.error('Error generating report:', error);
      throw new Error(`Failed to generate report: ${error.message}`);
    }
  }
};

export default api;
