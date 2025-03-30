
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
  
  startFuzzing: async (sessionId: string) => {
    try {
      const response = await api.post(`/fuzzer/${sessionId}/start`);
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
  }
};

// Machine Learning API
export const mlApi = {
  trainModels: async (dataset: any[]) => {
    try {
      const response = await api.post('/ml/train', { dataset });
      return response.data;
    } catch (error) {
      console.error('Error training models:', error);
      throw error;
    }
  },
  
  analyzeDataset: async (dataset: any[]) => {
    try {
      const response = await api.post('/ml/analyze', { dataset });
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
  }
};

export default {
  fuzzer: fuzzerApi,
  ml: mlApi
};
