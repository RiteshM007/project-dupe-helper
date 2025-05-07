import axios from 'axios';

// Determine the appropriate API base URL based on the environment
const determineApiBaseUrl = () => {
  // Check if we're in a deployed environment (Lovable app)
  const isDeployed = window.location.hostname.includes('lovable.app');
  
  if (isDeployed) {
    // For deployed app, use a mock API that will work in the browser
    console.log('Using mock API for deployment environment');
    return '/api'; // Relative path that will be intercepted for mocking
  } else {
    // For local development, use localhost
    console.log('Using localhost API for development environment');
    return 'http://localhost:5000/api';
  }
};

const API_BASE_URL = determineApiBaseUrl();

// Create axios instance with timeout
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  },
  timeout: 30000 // 30 second timeout
});

// Add response interceptor for better error handling
api.interceptors.response.use(
  response => response,
  error => {
    if (error.response) {
      // The request was made and the server responded with a status code
      console.error('API Error Response:', error.response.status, error.response.data);
    } else if (error.request) {
      // The request was made but no response was received
      console.error('API No Response:', error.request);
    } else {
      // Something happened in setting up the request
      console.error('API Request Error:', error.message);
    }
    return Promise.reject(error);
  }
);

// Add request interceptor to handle mock responses in deployed environment
api.interceptors.request.use(
  async config => {
    // Check if we're in a deployed environment
    const isDeployed = window.location.hostname.includes('lovable.app');
    
    if (isDeployed) {
      // This is where we'll intercept requests and return mock responses
      console.log(`Mock API request for: ${config.method?.toUpperCase()} ${config.url}`);
      
      // Create a promise that resolves with mock data after a small delay
      return new Promise((resolve) => {
        setTimeout(() => {
          const mockResponse = generateMockResponse(config);
          
          // Modify the config to prevent actual HTTP request
          // and prepare it for our mock response handler
          config.adapter = () => {
            return Promise.resolve({
              data: mockResponse.data,
              status: mockResponse.status,
              statusText: mockResponse.statusText,
              headers: config.headers,
              config: config,
              request: {}
            });
          };
          
          resolve(config);
        }, 500); // Simulate network delay
      });
    }
    
    return config;
  },
  error => Promise.reject(error)
);

// Generate mock responses for different API endpoints
const generateMockResponse = (config: any) => {
  const { url, method, data } = config;
  const parsedData = data ? JSON.parse(data) : {};
  
  // Generate a random session ID for consistency
  const sessionId = `mock_session_${Date.now()}`;
  
  // Handle different API endpoints
  if (url?.includes('/fuzzer/create') && method === 'post') {
    return {
      status: 200,
      statusText: 'OK',
      data: {
        success: true,
        session_id: sessionId,
        message: 'Fuzzer session created successfully'
      }
    };
  }
  
  if (url?.includes('/custom-payloads') && method === 'post') {
    return {
      status: 200,
      statusText: 'OK',
      data: {
        success: true,
        message: `Added ${parsedData.payloads?.length || 0} custom payloads successfully`
      }
    };
  }
  
  if (url?.includes('/start') && method === 'post') {
    return {
      status: 200,
      statusText: 'OK',
      data: {
        success: true,
        message: 'Fuzzing started successfully'
      }
    };
  }
  
  if (url?.includes('/status') && method === 'get') {
    return {
      status: 200,
      statusText: 'OK',
      data: {
        status: 'running',
        progress: Math.floor(Math.random() * 100),
        payloads_processed: Math.floor(Math.random() * 50),
        vulnerabilities_found: Math.floor(Math.random() * 5)
      }
    };
  }
  
  if (url?.includes('/stop') && method === 'post') {
    return {
      status: 200,
      statusText: 'OK',
      data: {
        success: true,
        message: 'Fuzzing stopped successfully'
      }
    };
  }
  
  // Default mock response
  return {
    status: 200,
    statusText: 'OK',
    data: {
      success: true,
      message: 'Mock response generated'
    }
  };
};

// Fuzzer API
export const fuzzerApi = {
  createFuzzer: async (targetUrl: string, wordlistFile: string = 'default_wordlist.txt') => {
    try {
      console.log('Creating fuzzer with target URL:', targetUrl);
      // Make sure the endpoint matches what's expected on the backend
      const response = await api.post('/fuzzer/create', { 
        targetUrl, 
        wordlistFile 
      });
      console.log('Fuzzer created:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error creating fuzzer:', error);
      throw error;
    }
  },
  
  uploadPayloads: async (sessionId: string, payloads: string[]) => {
    try {
      if (!sessionId) {
        throw new Error("Cannot upload payloads: session ID is undefined");
      }
      console.log(`Uploading ${payloads.length} payloads to session ${sessionId}`);
      
      // Update to match the expected method name in the server-side WebFuzzer class
      const response = await api.post(`/fuzzer/${sessionId}/custom-payloads`, { 
        payloads: payloads 
      });
      console.log('Payloads uploaded successfully:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error uploading payloads:', error);
      throw error;
    }
  },
  
  startFuzzing: async (sessionId: string, vulnerabilityTypes: string[] = [], customPayloads: string[] = []) => {
    try {
      if (!sessionId) {
        throw new Error("Cannot start fuzzing: session ID is undefined");
      }
      console.log(`Starting fuzzing for session ${sessionId}`);
      console.log('Vulnerability types:', vulnerabilityTypes);
      console.log('Custom payloads count:', customPayloads.length);
      
      // Make sure we're sending the data in the format the backend expects
      const response = await api.post(`/fuzzer/${sessionId}/start`, { 
        vulnerabilityTypes,
        customPayloads
      });
      console.log('Fuzzing started successfully:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error starting fuzzing:', error);
      throw error;
    }
  },
  
  getFuzzerStatus: async (sessionId: string) => {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/status`);
      return response.data;
    } catch (error) {
      console.error('Error getting fuzzer status:', error);
      throw error;
    }
  },
  
  stopFuzzing: async (sessionId: string) => {
    try {
      const response = await api.post(`/fuzzer/${sessionId}/stop`);
      return response.data;
    } catch (error) {
      console.error('Error stopping fuzzing:', error);
      throw error;
    }
  },
  
  getDataset: async (sessionId: string) => {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/dataset`);
      return response.data;
    } catch (error) {
      console.error('Error getting dataset:', error);
      throw error;
    }
  },
  
  saveResults: async (sessionId: string, results: any) => {
    try {
      const response = await api.post(`/fuzzer/${sessionId}/results`, { results });
      return response.data;
    } catch (error) {
      console.error('Error saving results:', error);
      throw error;
    }
  },
  
  exportResults: async (sessionId: string, format: string = 'json') => {
    try {
      const response = await api.get(`/fuzzer/${sessionId}/export?format=${format}`);
      return response.data;
    } catch (error) {
      console.error('Error exporting results:', error);
      throw error;
    }
  }
};

// Machine Learning API
export const mlApi = {
  trainModels: async (dataset: any[], options: any = {}) => {
    try {
      const response = await api.post('/ml/train', { dataset, options });
      return response.data;
    } catch (error) {
      console.error('Error training models:', error);
      throw error;
    }
  },
  
  analyzeDataset: async (dataset: any[], options: any = {}) => {
    try {
      const response = await api.post('/ml/analyze', { dataset, options });
      return response.data;
    } catch (error) {
      console.error('Error analyzing dataset:', error);
      throw error;
    }
  },
  
  generateReport: async (results: any[], modelInfo: any) => {
    try {
      const response = await api.post('/ml/generate-report', { results, modelInfo });
      return response.data;
    } catch (error) {
      console.error('Error generating report:', error);
      throw error;
    }
  },
  
  performClustering: async (dataset: any[], clusterCount: number = 3) => {
    try {
      const response = await api.post('/ml/cluster', { dataset, clusterCount });
      return response.data;
    } catch (error) {
      console.error('Error performing clustering:', error);
      throw error;
    }
  },
  
  generateSignatures: async (dataset: any[]) => {
    try {
      const response = await api.post('/ml/generate-signatures', { dataset });
      return response.data;
    } catch (error) {
      console.error('Error generating signatures:', error);
      throw error;
    }
  },
  
  predictSample: async (sample: any, modelType: string = 'isolation_forest') => {
    try {
      const response = await api.post('/ml/predict', { sample, modelType });
      return response.data;
    } catch (error) {
      console.error('Error predicting sample:', error);
      throw error;
    }
  },
  
  getModelInfo: async () => {
    try {
      const response = await api.get('/ml/models-info');
      return response.data;
    } catch (error) {
      console.error('Error getting model info:', error);
      throw error;
    }
  },
  
  runBenchmark: async (options: any = {}) => {
    try {
      const response = await api.post('/ml/benchmark', { options });
      return response.data;
    } catch (error) {
      console.error('Error running benchmark:', error);
      throw error;
    }
  },
  
  exportModel: async (modelType: string, format: string = 'joblib') => {
    try {
      const response = await api.get(`/ml/export-model?type=${modelType}&format=${format}`);
      return response.data;
    } catch (error) {
      console.error('Error exporting model:', error);
      throw error;
    }
  }
};

// System management API
export const systemApi = {
  getStatus: async () => {
    try {
      const response = await api.get('/health');
      return response.data;
    } catch (error) {
      console.error('Error getting system status:', error);
      throw { message: 'Server unavailable', originalError: error };
    }
  },
  
  cleanupSessions: async () => {
    try {
      const response = await api.post('/fuzzer/cleanup');
      return response.data;
    } catch (error) {
      console.error('Error cleaning up sessions:', error);
      throw error;
    }
  }
};

export default {
  fuzzer: fuzzerApi,
  ml: mlApi,
  system: systemApi
};
