
# Web Fuzzer Python implementation
# This is a skeleton - replace with your actual Python WebFuzzer code

import time
import random
import json
import os

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
                    # ... Add more sample payloads from your JavaScript simulation
                ]
            
            self.total_payloads = len(self.wordlist)
            self.logActivity(f"Loaded {self.total_payloads} payloads from wordlist.")
            return self.wordlist
        except Exception as e:
            self.logActivity(f"Error loading wordlist: {str(e)}")
            raise

    def initializeDataset(self):
        self.dataset = []
        self.logActivity("Dataset initialized.")

    def saveToDataset(self, payload, response_code, alert_detected, error_detected, body_word_count_changed):
        # Assign label based on conditions
        label = "safe"
        if response_code >= 500 or error_detected:
            label = "malicious"
        elif alert_detected:
            label = "suspicious"

        data_entry = {
            "label": label,
            "payload": payload,
            "response_code": response_code,
            "alert_detected": alert_detected,
            "error_detected": error_detected,
            "body_word_count_changed": body_word_count_changed,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        }
        
        self.dataset.append(data_entry)
        self.logActivity(f"Data saved: {label}, {payload}, {response_code}, {alert_detected}, {error_detected}, {body_word_count_changed}")
        return data_entry

    def processPayload(self, payload):
        # Process a single payload
        self.logActivity(f"Processing payload: {payload}")
        
        # TODO: Replace with actual fuzzing logic
        # For now, simulate response characteristics
        response_code = 500 if random.random() > 0.7 else 200 + random.randint(0, 100)
        alert_detected = random.random() > 0.7
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
        result = self.saveToDataset(payload, response_code, alert_detected, error_detected, body_word_count_changed)
        
        return {
            "uniqueId": unique_id,
            "payload": payload,
            "responseCode": response_code,
            "alertDetected": alert_detected,
            "errorDetected": error_detected,
            "bodyWordCountChanged": body_word_count_changed,
            "result": result
        }

    def startFuzzing(self):
        # This method will be called via API endpoints and status polled separately
        self.scan_active = True
        self.scan_progress = 0
        self.payloads_processed = 0
        
        self.logActivity("Starting fuzzing process...")
        self.logActivity(f"Target URL: {self.target_url}")
        
        # The actual processing happens asynchronously or in a separate thread

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
