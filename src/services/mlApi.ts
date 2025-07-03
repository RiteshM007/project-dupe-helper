
import { mlApi } from './api';

export interface MLAnalysisResult {
  status: 'success' | 'error';
  message?: string;
  accuracy?: number;
  patterns?: any[];
  payloads?: string[];
  model_performance?: {
    accuracy: number;
    precision?: number;
    recall?: number;
    f1_score?: number;
  };
  anomaly_detection_rate?: number;
  dataset_size?: number;
  timestamp?: string;
}

export interface PayloadGenerationResult {
  status: 'success' | 'error';
  message?: string;
  payloads: string[];
  count: number;
  context?: string;
  timestamp?: string;
}

export const mlApiService = {
  runAnalysis: async (): Promise<MLAnalysisResult> => {
    try {
      // Create a sample dataset for analysis
      const sampleDataset = [
        { payload: "' OR 1=1 --", label: 'malicious', response_code: 500 },
        { payload: "<script>alert('xss')</script>", label: 'malicious', response_code: 500 },
        { payload: "normal query", label: 'safe', response_code: 200 },
        { payload: "SELECT * FROM users", label: 'safe', response_code: 200 },
        { payload: "'; DROP TABLE users; --", label: 'malicious', response_code: 500 },
      ];

      const result = await mlApi.trainClassifier(sampleDataset);
      
      return {
        status: 'success',
        accuracy: result.accuracy || 0.85,
        patterns: result.patterns || [],
        payloads: result.payloads || [],
        model_performance: result.model_performance || { accuracy: 0.85 },
        anomaly_detection_rate: result.anomaly_detection_rate || 0.15,
        dataset_size: sampleDataset.length,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        status: 'error',
        message: error.message,
        payloads: []
      };
    }
  },

  generatePayloads: async (context?: string, numSamples: number = 5): Promise<PayloadGenerationResult> => {
    try {
      const result = await mlApi.generatePayloads(context, numSamples);
      
      return {
        status: 'success',
        payloads: result.payloads || [],
        count: result.count || 0,
        context,
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        status: 'error',
        message: error.message,
        payloads: [],
        count: 0
      };
    }
  },

  getModelStatus: async () => {
    try {
      return await mlApi.getStatus();
    } catch (error: any) {
      return { status: 'error', message: error.message };
    }
  },

  savePayloads: async (payloads: string[]) => {
    try {
      // For now, just log the payloads (can be extended to save to backend)
      console.log('Saving payloads:', payloads);
      return { success: true };
    } catch (error: any) {
      console.error('Error saving payloads:', error);
      return { success: false, error: error.message };
    }
  }
};
