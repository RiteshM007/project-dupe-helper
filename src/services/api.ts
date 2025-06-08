
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

export default api;
