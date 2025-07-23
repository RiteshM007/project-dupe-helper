import axios from 'axios';

// Python Flask backend configuration
const PYTHON_BACKEND_URL = 'http://localhost:5000';

class BackendService {
  private baseURL: string;

  constructor() {
    this.baseURL = PYTHON_BACKEND_URL;
  }

  // ML Training Endpoints
  async trainClassifier(dataset: any[]) {
    const response = await axios.post(`${this.baseURL}/train_classifier`, {
      dataset,
      model_type: 'random_forest'
    });
    return response.data;
  }

  async trainClassifierWithFile(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('model_type', 'random_forest');

    const response = await axios.post(`${this.baseURL}/train_classifier_file`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
    return response.data;
  }

  // Payload Generation
  async generatePayloads(vulnerabilityType?: string, count: number = 10) {
    const response = await axios.post(`${this.baseURL}/generate_payloads`, {
      vulnerability_type: vulnerabilityType,
      count
    });
    return response.data;
  }

  // Advanced Fuzzing Engine
  async startFuzzingSession(config: {
    target_url: string;
    payloads: string[];
    fuzzing_type: string;
    max_threads?: number;
    delay_between_requests?: number;
  }) {
    const response = await axios.post(`${this.baseURL}/start_fuzzing`, config);
    return response.data;
  }

  async getFuzzingStatus(sessionId: string) {
    const response = await axios.get(`${this.baseURL}/fuzzing_status/${sessionId}`);
    return response.data;
  }

  async stopFuzzingSession(sessionId: string) {
    const response = await axios.post(`${this.baseURL}/stop_fuzzing/${sessionId}`);
    return response.data;
  }

  // Vulnerability Detection
  async analyzeVulnerabilities(sessionId: string) {
    const response = await axios.get(`${this.baseURL}/analyze_vulnerabilities/${sessionId}`);
    return response.data;
  }

  // DVWA Integration
  async connectToDVWA(dvwaUrl: string, credentials: { username: string; password: string }) {
    const response = await axios.post(`${this.baseURL}/connect_dvwa`, {
      dvwa_url: dvwaUrl,
      credentials
    });
    return response.data;
  }

  async runDVWATests(sessionId: string, testTypes: string[]) {
    const response = await axios.post(`${this.baseURL}/run_dvwa_tests`, {
      session_id: sessionId,
      test_types: testTypes
    });
    return response.data;
  }

  // Report Generation
  async generatePDFReport(sessionId: string, includeCharts: boolean = true) {
    const response = await axios.post(`${this.baseURL}/generate_pdf_report`, {
      session_id: sessionId,
      include_charts: includeCharts
    }, {
      responseType: 'blob'
    });
    return response.data;
  }

  async generateExecutiveSummary(sessionId: string) {
    const response = await axios.get(`${this.baseURL}/executive_summary/${sessionId}`);
    return response.data;
  }

  async prioritizeVulnerabilities(vulnerabilities: any[]) {
    const response = await axios.post(`${this.baseURL}/prioritize_vulnerabilities`, {
      vulnerabilities
    });
    return response.data;
  }

  // Health check
  async checkHealth() {
    try {
      const response = await axios.get(`${this.baseURL}/health`);
      return response.data;
    } catch (error) {
      throw new Error('Python backend is not available');
    }
  }
}

export const backendService = new BackendService();