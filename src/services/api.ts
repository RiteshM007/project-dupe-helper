
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

// Enhanced ML API with production-grade endpoints
export const mlApi = {
  // Run complete ML analysis pipeline
  async runAnalysis() {
    try {
      console.log('🧠 Starting complete ML analysis pipeline...');
      const response = await api.post('/ml/analyze');
      return response.data;
    } catch (error: any) {
      console.error('Error running ML analysis:', error);
      throw new Error(`ML analysis failed: ${error.message}`);
    }
  },

  // Train ML models with dataset
  async trainModels(dataset?: any[]) {
    try {
      console.log('🎯 Training ML models...');
      const response = await api.post('/ml/train', { dataset });
      return response.data;
    } catch (error: any) {
      console.error('Error training ML models:', error);
      throw new Error(`Model training failed: ${error.message}`);
    }
  },

  // Train classifier with dataset (alias for backward compatibility)
  async trainClassifier(dataset?: any[]) {
    try {
      console.log('🎯 Training classifier model...');
      const response = await api.post('/ml/train-classifier', { dataset });
      return response.data;
    } catch (error: any) {
      console.error('Error training classifier:', error);
      throw new Error(`Classifier training failed: ${error.message}`);
    }
  },

  // Generate payloads using ML
  async generatePayloads(context?: string, numSamples: number = 5) {
    try {
      console.log(`🚀 Generating ${numSamples} ML payloads${context ? ` for: ${context}` : ''}...`);
      const response = await api.post('/ml/generate-payloads', {
        context,
        num_samples: numSamples
      });
      return response.data;
    } catch (error: any) {
      console.error('Error generating ML payloads:', error);
      throw new Error(`ML payload generation failed: ${error.message}`);
    }
  },

  // Analyze dataset patterns
  async analyzeDataset(dataset: any[]) {
    try {
      console.log('📊 Analyzing dataset patterns...');
      const response = await api.post('/ml/analyze-dataset', { dataset });
      return response.data;
    } catch (error: any) {
      console.error('Error analyzing dataset:', error);
      throw new Error(`Dataset analysis failed: ${error.message}`);
    }
  },

  // Get ML model status
  async getModelStatus() {
    try {
      const response = await api.get('/ml/status');
      return response.data;
    } catch (error: any) {
      console.error('Error getting model status:', error);
      throw new Error(`Model status check failed: ${error.message}`);
    }
  },

  // Save generated payloads
  async savePayloads(payloads: string[]) {
    try {
      console.log(`💾 Saving ${payloads.length} ML-generated payloads...`);
      const response = await api.post('/ml/save-payloads', { payloads });
      return response.data;
    } catch (error: any) {
      console.error('Error saving payloads:', error);
      throw new Error(`Payload saving failed: ${error.message}`);
    }
  },

  // Load existing models
  async loadModels() {
    try {
      console.log('📁 Loading existing ML models...');
      const response = await api.post('/ml/load-models');
      return response.data;
    } catch (error: any) {
      console.error('Error loading models:', error);
      throw new Error(`Model loading failed: ${error.message}`);
    }
  },

  // Get ExploitDB integration
  async getExploitDBPayloads(keywords: string[], limit: number = 10) {
    try {
      console.log('🔍 Fetching ExploitDB payloads...');
      const response = await api.post('/ml/exploitdb', { keywords, limit });
      return response.data;
    } catch (error: any) {
      console.error('Error fetching ExploitDB payloads:', error);
      throw new Error(`ExploitDB integration failed: ${error.message}`);
    }
  },

  // Train classifier with file upload
  async trainClassifierWithFile(file: File) {
    try {
      console.log(`📁 Training classifier with uploaded file: ${file.name}`);
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await api.post('/ml/train-classifier', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return response.data;
    } catch (error: any) {
      console.error('Error training classifier with file:', error);
      throw new Error(`Classifier training failed: ${error.message}`);
    }
  },

  // Generate security report
  async generateReport(results: any[], modelInfo: any = {}) {
    try {
      console.log('📄 Generating ML security report...');
      const response = await api.post('/ml/generate-report', {
        results,
        modelInfo
      });
      return response.data;
    } catch (error: any) {
      console.error('Error generating ML report:', error);
      throw new Error(`Report generation failed: ${error.message}`);
    }
  }
};

export default api;
