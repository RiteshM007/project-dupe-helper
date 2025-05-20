
import axios from 'axios';

// Create a base axios instance with default settings
const api = axios.create({
  baseURL: 'http://localhost:5000/api', // Adjust this to your server URL
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
  allowAbsoluteUrls: true, // Allow absolute URLs 
});

export const fuzzerApi = {
  // Create a new fuzzer session
  async createFuzzer(targetUrl: string, wordlist: string) {
    try {
      const response = await api.post('/fuzzer/create', {
        target_url: targetUrl,
        wordlist_file: wordlist,
      });
      return response.data;
    } catch (error) {
      console.error('Error creating fuzzer:', error);
      return { 
        success: false, 
        message: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  },

  // Upload custom payloads to an existing fuzzer session
  async uploadPayloads(sessionId: string, payloads: string[]) {
    try {
      const response = await api.post(`/fuzzer/${sessionId}/payloads`, {
        payloads,
      });
      return response.data;
    } catch (error) {
      console.error('Error uploading payloads:', error);
      return { 
        success: false, 
        message: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  },

  // Start the fuzzing process
  async startFuzzing(sessionId: string, vulnerabilityTypes: string[], payloads: string[] = []) {
    try {
      const response = await api.post(`/fuzzer/${sessionId}/start`, {
        vulnerabilityTypes,
        customPayloads: payloads, // Include payloads directly in case server needs them
      });
      return response.data;
    } catch (error) {
      console.error('Error starting fuzzing:', error);
      return { 
        success: false, 
        message: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  },

  // Stop an ongoing fuzzing process
  async stopFuzzing(sessionId: string) {
    try {
      const response = await api.post(`/fuzzer/${sessionId}/stop`);
      return response.data;
    } catch (error) {
      console.error('Error stopping fuzzing:', error);
      return { 
        success: false, 
        message: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  },

  // Get the status of a fuzzing session
  async getFuzzingStatus(sessionId: string) {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/status`);
      return response.data;
    } catch (error) {
      console.error('Error getting fuzzing status:', error);
      return { 
        success: false, 
        message: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  },

  // Get results from a fuzzing session
  async getFuzzingResults(sessionId: string) {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/results`);
      return response.data;
    } catch (error) {
      console.error('Error getting fuzzing results:', error);
      return { 
        success: false, 
        message: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  },
};

export default api;
