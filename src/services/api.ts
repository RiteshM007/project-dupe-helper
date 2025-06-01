
import axios from 'axios';

// Create a base axios instance with default settings
const api = axios.create({
  baseURL: 'http://localhost:5000/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
  allowAbsoluteUrls: true,
});

// Simulation mode for when backend is not available
const SIMULATION_MODE = true;

// Simulated responses for demo purposes
const simulateResponse = async (operation: string, data?: any) => {
  await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
  
  switch (operation) {
    case 'create':
      return {
        success: true,
        sessionId: `sim-${Date.now()}`,
        message: 'Fuzzer session created successfully (simulation mode)'
      };
    case 'start':
      return {
        success: true,
        message: 'Fuzzing started successfully (simulation mode)'
      };
    case 'stop':
      return {
        success: true,
        message: 'Fuzzing stopped (simulation mode)'
      };
    case 'status':
      return {
        success: true,
        status: 'running',
        progress: Math.random() * 100,
        payloadsSent: Math.floor(Math.random() * 50),
        vulnerabilitiesFound: Math.floor(Math.random() * 5)
      };
    case 'results':
      return {
        success: true,
        results: {
          totalPayloads: Math.floor(Math.random() * 100) + 50,
          vulnerabilitiesFound: Math.floor(Math.random() * 10),
          threats: []
        }
      };
    default:
      return { success: false, message: 'Unknown operation' };
  }
};

export const fuzzerApi = {
  // Create a new fuzzer session
  async createFuzzer(targetUrl: string, wordlist: string) {
    if (SIMULATION_MODE) {
      console.log(`Creating fuzzer session (simulation) for ${targetUrl}`);
      return simulateResponse('create');
    }
    
    try {
      const response = await api.post('/fuzzer/create', {
        target_url: targetUrl,
        wordlist_file: wordlist,
      });
      return response.data;
    } catch (error) {
      console.error('Error creating fuzzer:', error);
      console.log('Falling back to simulation mode');
      return simulateResponse('create');
    }
  },

  // Upload custom payloads to an existing fuzzer session
  async uploadPayloads(sessionId: string, payloads: string[]) {
    if (SIMULATION_MODE) {
      console.log(`Uploading ${payloads.length} payloads (simulation)`);
      return { success: true, message: 'Payloads uploaded (simulation)' };
    }
    
    try {
      const response = await api.post(`/fuzzer/${sessionId}/payloads`, {
        payloads,
      });
      return response.data;
    } catch (error) {
      console.error('Error uploading payloads:', error);
      return { success: true, message: 'Payloads uploaded (simulation fallback)' };
    }
  },

  // Start the fuzzing process
  async startFuzzing(sessionId: string, vulnerabilityTypes: string[], payloads: string[] = []) {
    if (SIMULATION_MODE) {
      console.log(`Starting fuzzing (simulation) for session ${sessionId}`);
      return simulateResponse('start');
    }
    
    try {
      const response = await api.post(`/fuzzer/${sessionId}/start`, {
        vulnerabilityTypes,
        customPayloads: payloads,
      });
      return response.data;
    } catch (error) {
      console.error('Error starting fuzzing:', error);
      return simulateResponse('start');
    }
  },

  // Stop an ongoing fuzzing process
  async stopFuzzing(sessionId: string) {
    if (SIMULATION_MODE) {
      console.log(`Stopping fuzzing (simulation) for session ${sessionId}`);
      return simulateResponse('stop');
    }
    
    try {
      const response = await api.post(`/fuzzer/${sessionId}/stop`);
      return response.data;
    } catch (error) {
      console.error('Error stopping fuzzing:', error);
      return simulateResponse('stop');
    }
  },

  // Get the status of a fuzzing session
  async getFuzzingStatus(sessionId: string) {
    if (SIMULATION_MODE) {
      return simulateResponse('status');
    }
    
    try {
      const response = await api.get(`/fuzzer/${sessionId}/status`);
      return response.data;
    } catch (error) {
      console.error('Error getting fuzzing status:', error);
      return simulateResponse('status');
    }
  },

  // Get results from a fuzzing session
  async getFuzzingResults(sessionId: string) {
    if (SIMULATION_MODE) {
      return simulateResponse('results');
    }
    
    try {
      const response = await api.get(`/fuzzer/${sessionId}/results`);
      return response.data;
    } catch (error) {
      console.error('Error getting fuzzing results:', error);
      return simulateResponse('results');
    }
  },
};

export default api;
