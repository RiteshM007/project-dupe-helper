
// ML Models simulation for the frontend
// This simulates Python ML code functionality

// Sample dataset for training and testing
export const getSampleDataset = () => {
  const sampleData = [];
  
  // Generate 50 sample data points
  for (let i = 0; i < 50; i++) {
    // Mix of benign and malicious payloads
    const isMalicious = Math.random() > 0.7;
    const alertDetected = isMalicious && Math.random() > 0.3;
    const errorDetected = isMalicious && Math.random() > 0.5;
    const bodyWordCountChanged = Math.random() > 0.4;
    
    let payload;
    let label;
    
    if (isMalicious) {
      // Generate malicious payload
      const payloads = [
        "<script>alert(1)</script>",
        "' OR 1=1 --",
        "../../etc/passwd",
        "; DROP TABLE users;",
        "<img src=x onerror=alert('XSS')>",
        "admin' --",
        "1'; SELECT * FROM users; --",
        "UNION SELECT username, password FROM users",
        "%00../../../etc/passwd",
        "' UNION SELECT NULL, version() --"
      ];
      payload = payloads[Math.floor(Math.random() * payloads.length)];
      
      if (errorDetected) {
        label = "malicious";
      } else if (alertDetected) {
        label = "suspicious";
      } else {
        label = Math.random() > 0.7 ? "malicious" : "safe";
      }
    } else {
      // Generate benign payload
      const payloads = [
        "normal_user",
        "valid_input",
        "12345",
        "example.com",
        "john.doe@example.com",
        "password123",
        "1234-5678-9012-3456",
        "John Doe",
        "2023-09-15",
        "+1 (555) 123-4567"
      ];
      payload = payloads[Math.floor(Math.random() * payloads.length)];
      label = "safe";
    }
    
    sampleData.push({
      label,
      payload,
      response_code: isMalicious ? (Math.random() > 0.6 ? 500 : 200) : 200,
      alert_detected: alertDetected,
      error_detected: errorDetected,
      body_word_count_changed: bodyWordCountChanged,
      timestamp: Date.now() - Math.floor(Math.random() * 86400000) // Random time in last 24h
    });
  }
  
  return sampleData;
};

// Isolation Forest Model Training
export const trainIsolationForest = async (dataset) => {
  console.log("Training Isolation Forest model...");
  
  // Simulate training delay
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Return mock model
  return {
    type: "IsolationForest",
    timestamp: new Date().toISOString(),
    contamination: 0.1,
    features: ["response_code", "body_word_count_changed"],
    isTrained: true,
    predictFn: (features) => Math.random() > 0.8 ? -1 : 1
  };
};

// Random Forest Model Training
export const trainRandomForest = async (dataset) => {
  console.log("Training Random Forest model...");
  
  // Simulate training delay
  await new Promise(resolve => setTimeout(resolve, 2500));
  
  // Extract some statistics for feature importance
  const featureImportance = {
    "response_code": 0.72,
    "body_word_count_changed": 0.68,
    "alert_detected": 0.45,
    "error_detected": 0.32
  };
  
  // Return mock model
  return {
    type: "RandomForest",
    timestamp: new Date().toISOString(),
    n_estimators: 100,
    feature_importance: featureImportance,
    features: ["response_code", "body_word_count_changed", "alert_detected", "error_detected"],
    isTrained: true,
    predictFn: (features) => Math.random() > 0.7 ? 1 : 0
  };
};

// Predict using Isolation Forest (anomaly detection)
export const predictAnomaly = (features, model) => {
  if (!model || model.type !== "IsolationForest" || !model.isTrained) {
    console.error("Invalid or untrained Isolation Forest model");
    return null;
  }
  
  // For simulation, we'll use the mock predict function from the model
  // In a real implementation, this would use the actual ML model's prediction
  return model.predictFn(features);
};

// Predict using Random Forest (classification)
export const predictEffectiveness = (features, model) => {
  if (!model || model.type !== "RandomForest" || !model.isTrained) {
    console.error("Invalid or untrained Random Forest model");
    return null;
  }
  
  // For simulation, we'll use the mock predict function from the model
  // In a real implementation, this would use the actual ML model's prediction
  return model.predictFn(features);
};

// Generate analysis report based on results
export const generateReport = async (results, modelInfo) => {
  console.log("Generating report from analysis results...");
  
  // Simulate report generation delay
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  // Count findings by severity
  const severityCounts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0
  };
  
  results.forEach(result => {
    severityCounts[result.severity]++;
  });
  
  // Generate mock report
  const report = {
    title: "Vulnerability Analysis Report",
    timestamp: new Date().toISOString(),
    summary: {
      totalSamples: results.length,
      anomalies: results.filter(r => r.anomaly === -1).length,
      effectivePayloads: results.filter(r => r.effective === 1).length,
      severityCounts
    },
    results: results,
    modelInfo: modelInfo,
    recommendations: [
      "Address all Critical and High severity findings immediately",
      "Implement proper input validation and output encoding",
      "Review and enhance access control mechanisms",
      "Implement secure coding practices and developer training",
      "Consider implementing a Web Application Firewall (WAF)"
    ]
  };
  
  return report;
};

// Simulate clustering analysis
export const performClustering = async (dataset, clusterCount = 3) => {
  console.log(`Performing clustering with ${clusterCount} clusters...`);
  
  // Simulate clustering delay
  await new Promise(resolve => setTimeout(resolve, 1800));
  
  // Create mock cluster assignments
  const clusterAssignments = dataset.map(item => {
    // Random cluster assignment for simulation
    return {
      ...item,
      cluster: Math.floor(Math.random() * clusterCount)
    };
  });
  
  return {
    clusterCount,
    clusters: clusterAssignments,
    clusterCenters: Array(clusterCount).fill(0).map((_, i) => ({
      id: i,
      response_code: 200 + (i * 100),
      body_word_count_changed: i % 2
    }))
  };
};

// Simulate attack signature generation
export const generateAttackSignatures = (dataset) => {
  console.log("Generating attack signatures from dataset...");
  
  // Mock signatures for different attack types
  const signatures = {
    sql_injection: {
      pattern: "(?i)(?:\\b(?:select|union|insert|update|delete|drop|alter)\\b|'\\s*or\\s*[\\d\\w]+=\\s*[\\d\\w]+\\s*--|'\\s*or\\s*'\\s*'\\s*=\\s*'|\\b(?:--\\s*|#|;\\/\\*))",
      description: "Detects SQL injection attempts including UNION, OR conditions, and comment markers",
      severity: "high"
    },
    xss: {
      pattern: "(?i)(?:<[^>]*script\\b[^>]*>|\\bon\\w+\\s*=|javascript:\\s*|<[^>]*\\bimg\\b[^>]*\\bonerror\\b[^>]*>)",
      description: "Detects Cross-Site Scripting (XSS) attempts using script tags, event handlers, or javascript URIs",
      severity: "high"
    },
    path_traversal: {
      pattern: "(?:(?:\\/|\\\\)\\.\\.(?:\\/|\\\\)|\\b(?:etc|var|usr|root|home|www)(?:\\/|\\\\)|(?:%2e%2e|\\.\\.)(?:%2f|\\/|\\\\))",
      description: "Detects directory traversal attempts using relative paths",
      severity: "high"
    },
    command_injection: {
      pattern: "(?:;\\s*[\\w\\d\\s_\\-/\\\\]+|`[^`]*`|\\$\\([^)]*\\)|\\|\\s*[\\w\\d\\s_\\-/\\\\]+)",
      description: "Detects command injection attempts using shell command separators",
      severity: "critical"
    }
  };
  
  return signatures;
};
