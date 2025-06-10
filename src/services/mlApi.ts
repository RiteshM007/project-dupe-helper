
import axios from 'axios';

// Create ML-specific API instance
const mlApi = axios.create({
  baseURL: 'http://localhost:5000/api/ml',
  timeout: 60000, // Longer timeout for ML operations
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request/response interceptors
mlApi.interceptors.request.use(
  (config) => {
    console.log(`ML API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('ML API Request Error:', error);
    return Promise.reject(error);
  }
);

mlApi.interceptors.response.use(
  (response) => {
    console.log(`ML API Response: ${response.config.url} - Status: ${response.status}`);
    return response;
  },
  (error) => {
    console.error(`ML API Error: ${error.config?.url} - ${error.message}`);
    return Promise.reject(error);
  }
);

export interface MLAnalysisResult {
  status: 'success' | 'error';
  message: string;
  payloads?: string[];
  patterns?: string[];
  model_performance?: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
  };
  anomaly_detection_rate?: number;
  generated_payloads_count?: number;
  exploitdb_payloads_count?: number;
  timestamp?: string;
}

export interface PayloadGenerationResult {
  status: 'success' | 'error';
  message: string;
  payloads: string[];
  count: number;
  context?: string;
}

export interface DatasetAnalysisResult {
  status: 'success' | 'error';
  message: string;
  patterns: Record<string, number>;
  class_distribution: Record<string, number>;
  total_samples: number;
  successful_payloads: number;
}

// ML API Functions
export const mlApiService = {
  // Run complete ML analysis pipeline
  async runAnalysis(): Promise<MLAnalysisResult> {
    try {
      console.log('🧠 Starting ML analysis pipeline...');
      const response = await mlApi.post('/analyze');
      return response.data;
    } catch (error: any) {
      console.error('Error running ML analysis:', error);
      throw new Error(`ML analysis failed: ${error.message}`);
    }
  },

  // Train ML models
  async trainModels(dataset?: any[]): Promise<MLAnalysisResult> {
    try {
      console.log('🎯 Training ML models...');
      const response = await mlApi.post('/train', { dataset });
      return response.data;
    } catch (error: any) {
      console.error('Error training models:', error);
      throw new Error(`Model training failed: ${error.message}`);
    }
  },

  // Generate payloads using ML
  async generatePayloads(context?: string, numSamples: number = 5): Promise<PayloadGenerationResult> {
    try {
      console.log(`🚀 Generating ${numSamples} ML payloads for context: ${context || 'general'}`);
      const response = await mlApi.post('/generate-payloads', {
        context,
        num_samples: numSamples
      });
      return response.data;
    } catch (error: any) {
      console.error('Error generating payloads:', error);
      throw new Error(`Payload generation failed: ${error.message}`);
    }
  },

  // Analyze dataset patterns
  async analyzeDataset(dataset: any[]): Promise<DatasetAnalysisResult> {
    try {
      console.log('📊 Analyzing dataset patterns...');
      const response = await mlApi.post('/analyze-dataset', { dataset });
      return response.data;
    } catch (error: any) {
      console.error('Error analyzing dataset:', error);
      throw new Error(`Dataset analysis failed: ${error.message}`);
    }
  },

  // Get model status
  async getModelStatus(): Promise<any> {
    try {
      const response = await mlApi.get('/status');
      return response.data;
    } catch (error: any) {
      console.error('Error getting model status:', error);
      throw new Error(`Model status check failed: ${error.message}`);
    }
  },

  // Save generated payloads
  async savePayloads(payloads: string[]): Promise<any> {
    try {
      console.log(`💾 Saving ${payloads.length} payloads...`);
      const response = await mlApi.post('/save-payloads', { payloads });
      return response.data;
    } catch (error: any) {
      console.error('Error saving payloads:', error);
      throw new Error(`Payload saving failed: ${error.message}`);
    }
  }
};

export default mlApiService;
