# Web Fuzzer Python implementation

import time
import random
import json
import os
import requests
from urllib.parse import urljoin

class WebFuzzer:
    def __init__(self, target_url, wordlist_file):
        self.target_url = target_url
        self.wordlist_file = wordlist_file
        self.wordlist = []
        self.logs = []
        self.reports = []
        self.dataset = []
        self.scan_active = False
        self.scan_progress = 0
        self.payloads_processed = 0
        self.total_payloads = 0
        self.dvwa_session = None
        self.dvwa_url = None
        self.dvwa_cookie = None
        self.security_level = "low"
        self.custom_payloads = []
        self.vulnerability_types = []  # Added to store vulnerability types

    def setVulnerabilityTypes(self, vuln_types):
        """Set the vulnerability types to test for"""
        self.vulnerability_types = vuln_types
        self.logActivity(f"Set vulnerability types: {', '.join(vuln_types) if vuln_types else 'all'}")

    def logActivity(self, message):
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "message": message,
            "type": "activity"
        }
        self.logs.append(log_entry)
        print(f"[Activity] {message}")
        return log_entry

    def logReport(self, report_data):
        report_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "data": report_data,
            "type": "report"
        }
        self.reports.append(report_entry)
        print(f"[Report] New report added")
        return report_entry

    def connectToDVWA(self, dvwa_url, username, password, security_level):
        """Connect to DVWA and establish a session for testing"""
        self.logActivity(f"Attempting to connect to DVWA at {dvwa_url}")
        self.dvwa_url = dvwa_url.rstrip('/')
        self.security_level = security_level
        
        try:
            # Create a session to maintain cookies
            session = requests.Session()
            
            # Get initial CSRF token from login page
            login_response = session.get(f"{self.dvwa_url}/login.php")
            
            # You would typically parse the HTML to extract the CSRF token
            # For this example, we'll simulate a successful login
            
            # Simulate login POST request
            login_data = {
                'username': username,
                'password': password,
                'Login': 'Login',
                # 'user_token': csrf_token  # In a real implementation you would include this
            }
            
            login_result = session.post(f"{self.dvwa_url}/login.php", data=login_data)
            
            if "Login failed" in login_result.text:
                self.logActivity("DVWA login failed - invalid credentials")
                return {"success": False, "message": "Login failed - invalid credentials"}
            
            # Set security level
            security_response = session.get(f"{self.dvwa_url}/security.php")
            
            security_data = {
                'security': security_level,
                'seclev_submit': 'Submit',
                # 'user_token': new_csrf_token  # Would be extracted from the security page
            }
            
            session.post(f"{self.dvwa_url}/security.php", data=security_data)
            
            # Store session cookies for future requests
            self.dvwa_cookie = session.cookies.get_dict()
            self.dvwa_session = session
            
            self.logActivity(f"Successfully connected to DVWA as {username}")
            self.logActivity(f"Security level set to: {security_level}")
            
            return {
                "success": True,
                "url": self.dvwa_url,
                "session": str(session.cookies.get_dict()),
                "message": "Successfully connected to DVWA"
            }
            
        except Exception as e:
            self.logActivity(f"DVWA connection error: {str(e)}")
            return {"success": False, "message": f"Connection error: {str(e)}"}

    def addCustomPayloads(self, payloads):
        """Add custom payloads to the wordlist"""
        if not payloads or not isinstance(payloads, list):
            self.logActivity("Error: No valid payloads provided")
            return False
            
        self.logActivity(f"Adding {len(payloads)} custom payloads")
        self.custom_payloads.extend(payloads)
        
        # Also add to wordlist if it's already loaded
        if self.wordlist:
            self.wordlist.extend(payloads)
            self.total_payloads = len(self.wordlist)
            self.logActivity(f"Wordlist updated, now contains {self.total_payloads} payloads")
        
        return True

    def loadWordlist(self):
        # Load wordlist from file
        self.logActivity(f"Loading wordlist from {self.wordlist_file}...")
        
        try:
            if os.path.exists(self.wordlist_file):
                with open(self.wordlist_file, 'r') as file:
                    self.wordlist = [line.strip() for line in file if line.strip()]
            else:
                # Fallback to sample payloads for testing
                self.wordlist = [
                    "<script>alert(1)</script>",
                    "' OR 1=1 --",
                    "../../etc/passwd",
                    "; DROP TABLE users;",
                    "<img src=x onerror=alert('XSS')>",
                    # XSS Payloads
                    "<script>alert('XSS')</script>",
                    "<img src='x' onerror='alert(\"XSS\")'>",
                    "<body onload='alert(\"XSS\")'>",
                    "<svg/onload=alert('XSS')>",
                    "<iframe src=\"javascript:alert('XSS');\"></iframe>",
                    
                    # SQL Injection Payloads
                    "' OR '1'='1",
                    "' OR 1=1 -- -",
                    "admin'--",
                    "1'; DROP TABLE users; --",
                    "' UNION SELECT username, password FROM users--",
                    
                    # LFI/Path Traversal Payloads
                    "../../../etc/passwd",
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "../../windows/win.ini",
                    "/etc/passwd",
                    "file:///etc/passwd",
                    
                    # Command Injection Payloads
                    "& ls -la",
                    "| cat /etc/passwd",
                    "; ls -la",
                    "$(cat /etc/passwd)",
                    "`cat /etc/passwd`",
                    
                    # CSRF Payloads
                    "<form action='http://victim/change_password' method='POST'><input type='hidden' name='new_password' value='hacked'></form>",
                    "<img src='http://victim/api?action=delete_account'>",
                    
                    # Auth Bypass Payloads
                    "admin' #",
                    "' OR username='admin'--",
                    "admin'/**/OR/**/1=1--",
                ]
            
            # Add any custom payloads that were added before loading the wordlist
            if self.custom_payloads:
                self.wordlist.extend(self.custom_payloads)
                
            self.total_payloads = len(self.wordlist)
            self.logActivity(f"Loaded {self.total_payloads} payloads from wordlist.")
            return self.wordlist
        except Exception as e:
            self.logActivity(f"Error loading wordlist: {str(e)}")
            raise

    def initializeDataset(self):
        self.dataset = []
        self.logActivity("Dataset initialized.")

    def getPayloadsForVulnerability(self, vuln_type):
        """Return a subset of payloads targeting a specific vulnerability type"""
        # Filter payloads based on vulnerability type
        if vuln_type == 'xss':
            return [p for p in self.wordlist if '<script>' in p.lower() or 'alert' in p.lower() or 'onerror' in p.lower()]
        elif vuln_type == 'sqli':
            return [p for p in self.wordlist if "'" in p or "--" in p or "UNION" in p.upper() or "SELECT" in p.upper()]
        elif vuln_type == 'lfi':
            return [p for p in self.wordlist if "../" in p or "etc/passwd" in p or "file:" in p]
        elif vuln_type == 'rce':
            return [p for p in self.wordlist if ";" in p or "|" in p or "$(" in p or "`" in p]
        elif vuln_type == 'csrf':
            return [p for p in self.wordlist if "<form" in p.lower() or "method=" in p.lower()]
        elif vuln_type == 'auth':
            return [p for p in self.wordlist if "admin" in p.lower() or "password" in p.lower() or "login" in p.lower()]
        else:
            # Return all payloads if no specific type or 'all' is selected
            return self.wordlist

    def saveToDataset(self, payload, response_code, alert_detected, error_detected, body_word_count_changed, vulnerability_type):
        # Assign label based on conditions
        label = "safe"
        severity = "low"
        
        if response_code >= 500 or error_detected:
            label = "malicious"
            severity = "high" if response_code >= 500 else "medium"
        elif alert_detected:
            label = "suspicious"
            severity = "medium"
        
        if "<script>" in payload and alert_detected:
            severity = "critical"
        
        data_entry = {
            "label": label,
            "severity": severity,
            "payload": payload,
            "response_code": response_code,
            "alert_detected": alert_detected,
            "error_detected": error_detected,
            "body_word_count_changed": body_word_count_changed,
            "vulnerability_type": vulnerability_type,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        }
        
        self.dataset.append(data_entry)
        self.logActivity(f"Data saved: {label}, {severity}, {payload}, {response_code}, {alert_detected}, {error_detected}, {body_word_count_changed}, {vulnerability_type}")
        return data_entry

    def testVulnerability(self, vulnerability_type, payload):
        """Test a specific vulnerability with a payload"""
        self.logActivity(f"Testing {vulnerability_type} with payload: {payload}")
        
        # For now, simulate response characteristics
        # In a real implementation, this would send actual requests to the target
        
        # Simulate different behaviors based on vulnerability type and payload
        if vulnerability_type == 'xss' and ('<script>' in payload.lower() or 'onerror' in payload.lower()):
            response_code = 200
            alert_detected = True
            error_detected = False
            body_word_count_changed = True
        elif vulnerability_type == 'sqli' and ("'" in payload or "--" in payload):
            response_code = random.choice([200, 500])
            alert_detected = random.random() > 0.7
            error_detected = response_code >= 500
            body_word_count_changed = True
        elif vulnerability_type == 'lfi' and ("../" in payload or "etc/passwd" in payload):
            response_code = random.choice([200, 403, 404])
            alert_detected = False
            error_detected = response_code >= 400
            body_word_count_changed = response_code == 200
        else:
            # Generic simulation for other cases
            response_code = random.choice([200, 302, 400, 403, 404, 500])
            alert_detected = random.random() > 0.8
            error_detected = response_code >= 500
            body_word_count_changed = random.random() > 0.5
        
        # Log details about the payload test
        if alert_detected:
            self.logActivity(f"Alert detected for payload: {payload}")
        
        if error_detected:
            self.logActivity(f"Error detected for payload: {payload}")
        
        if body_word_count_changed:
            self.logActivity(f"Body content changed for payload: {payload}")
        
        # Generate a unique ID for this test
        unique_id = f"test_{int(time.time())}_{random.randint(0, 1000)}"
        
        # Prepare report data
        report_data = '\n'.join([
            f"Unique ID: {unique_id}",
            f"Vulnerability Type: {vulnerability_type}",
            f"Payload: {payload}",
            f"Response Code: {response_code}",
            f"Alert Detected: {'Yes' if alert_detected else 'No'}",
            f"Unexpected Error Detected: {'Yes' if error_detected else 'No'}",
            f"Body Word Count Changed: {'Yes' if body_word_count_changed else 'No'}",
            '-' * 50
        ])
        
        # Log the report
        self.logReport(report_data)
        
        # Save result to dataset
        result = self.saveToDataset(payload, response_code, alert_detected, error_detected, body_word_count_changed, vulnerability_type)
        
        return {
            "uniqueId": unique_id,
            "payload": payload,
            "responseCode": response_code,
            "alertDetected": alert_detected,
            "errorDetected": error_detected,
            "bodyWordCountChanged": body_word_count_changed,
            "vulnerabilityType": vulnerability_type,
            "result": result
        }

    def processPayload(self, payload, vulnerability_type="general"):
        """Process a single payload (backward compatibility)"""
        return self.testVulnerability(vulnerability_type, payload)

    def startFuzzing(self, selected_vulnerabilities=None):
        """Start the fuzzing process for selected vulnerability types"""
        if selected_vulnerabilities is None:
            selected_vulnerabilities = ['all']
            
        self.scan_active = True
        self.scan_progress = 0
        self.payloads_processed = 0
        
        self.loadWordlist()
        self.initializeDataset()
        
        self.logActivity("Starting fuzzing process...")
        self.logActivity(f"Target URL: {self.target_url}")
        
        # If 'all' is selected, test all vulnerability types
        vuln_types_to_test = ['xss', 'sqli', 'lfi', 'rce', 'csrf', 'auth'] if 'all' in selected_vulnerabilities else selected_vulnerabilities
        
        self.logActivity(f"Testing vulnerability types: {', '.join(vuln_types_to_test)}")
        
        total_tests_planned = 0
        for v_type in vuln_types_to_test:
            payloads = self.getPayloadsForVulnerability(v_type)
            total_tests_planned += len(payloads)
        
        tests_completed = 0
        
        # Run tests for each vulnerability type
        for v_type in vuln_types_to_test:
            if not self.scan_active:
                self.logActivity("Fuzzing process stopped.")
                break
                
            self.logActivity(f"Starting tests for {v_type}")
            payloads = self.getPayloadsForVulnerability(v_type)
            
            for payload in payloads:
                if not self.scan_active:
                    break
                    
                self.testVulnerability(v_type, payload)
                tests_completed += 1
                self.payloads_processed = tests_completed
                self.scan_progress = (tests_completed / total_tests_planned) * 100
                
                # Simulate processing time
                time.sleep(0.1)
            
            self.logActivity(f"Completed tests for {v_type}")
        
        self.scan_active = False
        self.logActivity("Fuzzing process completed.")
        
        return {
            "success": True,
            "total_tests": tests_completed,
            "dataset": self.dataset,
            "logs": self.logs,
            "reports": self.reports
        }

    def stopScan(self):
        if self.scan_active:
            self.scan_active = False
            self.logActivity("Fuzzing process stopped.")
            return True
        return False

    def pauseScan(self):
        if self.scan_active:
            self.scan_active = False
            self.logActivity("Fuzzing process paused.")
            return True
        return False

    def resumeScan(self):
        if not self.scan_active and self.payloads_processed < self.total_payloads:
            self.scan_active = True
            self.logActivity("Fuzzing process resumed.")
            return True
        return False

    def getDataset(self):
        return self.dataset

    def getLogs(self):
        return self.logs

    def getReports(self):
        return self.reports

    def getFullURL(self, path):
        """Gets the full URL for a DVWA path"""
        if self.dvwa_url:
            return urljoin(self.dvwa_url, path)
        return self.target_url
