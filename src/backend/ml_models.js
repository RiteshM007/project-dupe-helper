
// Machine Learning Model Simulation
// This is a frontend simulation of the provided Python code

export const trainIsolationForest = async (dataset, contamination = 0.1) => {
  // Simulate training time
  await new Promise(resolve => setTimeout(resolve, 2000));
  console.log("Isolation Forest model trained with contamination:", contamination);
  return {
    type: "IsolationForest",
    trained: true,
    contamination,
    timestamp: new Date().toISOString()
  };
};

export const trainRandomForest = async (dataset, nEstimators = 100) => {
  // Simulate training time
  await new Promise(resolve => setTimeout(resolve, 2500));
  console.log("Random Forest classifier trained with n_estimators:", nEstimators);
  return {
    type: "RandomForest",
    trained: true,
    nEstimators,
    timestamp: new Date().toISOString()
  };
};

export const predictAnomaly = (features, model) => {
  // Simulate anomaly detection
  // -1 for anomaly, 1 for normal
  // For simulation, detect anomaly if response code >= 400 or word count change is significant
  const [responseCode, wordCountChange] = features;
  
  if (responseCode >= 400 || wordCountChange > 10) {
    return -1; // Anomaly
  }
  return 1; // Normal
};

export const predictEffectiveness = (features, model) => {
  // Simulate classification prediction
  // 1 for effective payload, 0 for ineffective
  // For simulation, consider effective if response code >= 500 or word count change is significant
  const [responseCode, wordCountChange] = features;
  
  if (responseCode >= 500 || wordCountChange > 5) {
    return 1; // Effective payload
  }
  return 0; // Ineffective payload
};

export const generateReport = async (results, modelInfo) => {
  // Simulate report generation
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  return {
    title: "Vulnerability Analysis Report",
    timestamp: new Date().toISOString(),
    modelInfo,
    results,
    summary: {
      totalSamples: results.length,
      anomalies: results.filter(r => r.anomaly === -1).length,
      effectivePayloads: results.filter(r => r.effective === 1).length
    }
  };
};

export const getSampleDataset = () => {
  // Generate sample dataset for demonstration
  const sampleData = [];
  const payloads = [
    "<script>alert(1)</script>",
    "' OR 1=1 --",
    "../../etc/passwd",
    "; DROP TABLE users;",
    "<img src=x onerror=alert('XSS')>",
    "admin' --",
    "1'; SELECT * FROM users; --",
    "%00../../../etc/passwd"
  ];
  
  for (let i = 0; i < 50; i++) {
    const payload = payloads[Math.floor(Math.random() * payloads.length)];
    const responseCode = Math.random() > 0.7 
      ? Math.floor(Math.random() * 100) + 400 
      : Math.floor(Math.random() * 100) + 200;
    const alertDetected = Math.random() > 0.7;
    const errorDetected = responseCode >= 500;
    const bodyWordCountChanged = Math.random() > 0.5;
    
    // Determine label based on the logic in the Python code
    let label = "safe";
    if (responseCode >= 500 || errorDetected) {
      label = "malicious";
    } else if (alertDetected) {
      label = "suspicious";
    }
    
    sampleData.push({
      label,
      payload,
      response_code: responseCode,
      alert_detected: alertDetected,
      error_detected: errorDetected,
      body_word_count_changed: bodyWordCountChanged,
      timestamp: Date.now() - Math.floor(Math.random() * 1000000)
    });
  }
  
  return sampleData;
};
