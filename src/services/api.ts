
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Fuzzer API
export const fuzzerApi = {
  createFuzzer: async (targetUrl: string, wordlistFile: string = 'default_wordlist.txt') => {
    try {
      const response = await api.post('/fuzzer/create', { targetUrl, wordlistFile });
      return response.data;
    } catch (error) {
      console.error('Error creating fuzzer:', error);
      throw error;
    }
  },
  
  startFuzzing: async (sessionId: string, vulnerabilityTypes: string[] = [], customPayloads: string[] = []) => {
    try {
      const response = await api.post(`/fuzzer/${sessionId}/start`, { 
        vulnerabilityTypes,
        customPayloads
      });
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
  
  uploadPayloads: async (sessionId: string, payloads: string[]) => {
    try {
      const response = await api.post(`/fuzzer/${sessionId}/payloads`, { payloads });
      return response.data;
    } catch (error) {
      console.error('Error uploading payloads:', error);
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
      throw error;
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
