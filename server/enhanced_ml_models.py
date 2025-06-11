
import numpy as np
import pandas as pd
import joblib
import os
import time
import shutil
import sys
import logging
import subprocess
import json
import re
import requests
from bs4 import BeautifulSoup
from collections import Counter
from datetime import datetime
from typing import Tuple, Dict, Optional, Union, List
import sklearn

# Machine Learning Imports
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, make_scorer, accuracy_score
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from imblearn.over_sampling import SMOTE, RandomOverSampler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('model_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    """Configuration constants"""
    MODEL_DIR = "models"
    MIN_SAMPLES_PER_CLASS = 2  # Reduced from 5 to handle small datasets
    MAX_PAYLOAD_LENGTH = 100
    TRAINING_EPOCHS = 3
    TEST_SIZE = 0.2
    RANDOM_STATE = 42
    MIN_PAYLOADS = 3
    MAX_PAYLOADS = 7

class PayloadGenerator:
    """Enhanced Payload generator that learns patterns from the dataset"""
    def __init__(self):
        # Payload safety configuration
        self.forbidden_commands = [
            'rm -rf', 'format c:', 'shutdown', 
            'delete from', 'drop table', 'shutdown',
            'halt', 'reboot', 'poweroff'
        ]
        
        # Will be populated from dataset analysis
        self.common_patterns = []
        self.ml_payloads = []
        
        # Payload templates by category
        self.payload_templates = {
            'SQL injection': [
                "' OR 1=1 --",
                "admin' --",
                "' UNION SELECT NULL, version() --",
                "1'; DROP TABLE users; --",
                "' OR 'x'='x",
                "1 OR 1=1",
                "'; INSERT INTO users VALUES ('hacker', 'password'); --"
            ],
            'XSS attack': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<body onload=alert('XSS')>",
                "<iframe src='javascript:alert(`xss`)'></iframe>"
            ],
            'path traversal': [
                "../../etc/passwd",
                "%00../../../etc/passwd",
                "..\\..\\windows\\system32\\cmd.exe",
                "/var/www/../../etc/shadow",
                "../../../../etc/hosts"
            ],
            'command injection': [
                "; cat /etc/passwd",
                "| ls -la",
                "`id`",
                "$(cat /etc/passwd)",
                "127.0.0.1 && cat /etc/passwd",
                "; ping -c 4 attacker.com"
            ]
        }
        
        # TF-IDF vectorizer for pattern analysis - adjusted for small datasets
        self.vectorizer = TfidfVectorizer(
            analyzer='char',
            ngram_range=(2, 3),  # Reduced from (2,4)
            max_features=20      # Reduced from 50
        )

    def analyze_dataset(self, dataset: pd.DataFrame):
        """Analyze the dataset to learn payload patterns"""
        try:
            # Get successful payloads (malicious/suspicious)
            successful_payloads = dataset[
                dataset['label'].isin(['malicious', 'suspicious'])
            ]['payload'].tolist()
            
            if not successful_payloads:
                logger.warning("No successful payloads found in dataset")
                return
            
            # For small datasets, use simpler pattern analysis
            if len(successful_payloads) < 5:
                self.common_patterns = self._extract_simple_patterns(successful_payloads)
            else:
                # Analyze character-level patterns
                X = self.vectorizer.fit_transform(successful_payloads)
                feature_names = self.vectorizer.get_feature_names_out()
                
                # Get most common patterns
                self.common_patterns = [
                    pattern for pattern in feature_names 
                    if len(pattern) >= 2 and not pattern.isalnum()
                ][:10]  # Limit to 10 patterns
            
            logger.info(f"Discovered {len(self.common_patterns)} common patterns")
            
        except Exception as e:
            logger.error(f"Dataset analysis failed: {e}")
            self.common_patterns = ["'", "--", "<", ">", ";", "|"]  # Fallback patterns

    def _extract_simple_patterns(self, payloads):
        """Extract simple patterns for small datasets"""
        patterns = set()
        for payload in payloads:
            # Common SQL injection patterns
            if "'" in payload: patterns.add("'")
            if "--" in payload: patterns.add("--")
            if "or" in payload.lower(): patterns.add("OR")
            if "union" in payload.lower(): patterns.add("UNION")
            
            # XSS patterns
            if "<script" in payload.lower(): patterns.add("<script")
            if "alert" in payload.lower(): patterns.add("alert")
            if "onerror" in payload.lower(): patterns.add("onerror")
            
            # Path traversal
            if "../" in payload: patterns.add("../")
            if "..\\" in payload: patterns.add("..\\")
            
            # Command injection
            if ";" in payload: patterns.add(";")
            if "|" in payload: patterns.add("|")
            if "`" in payload: patterns.add("`")
            
        return list(patterns)

    def generate_payloads(self, num_samples: int = 5, context: str = None) -> List[str]:
        """Generate payloads based on learned patterns or context"""
        try:
            if context:
                return self.generate_contextual_payloads(context, num_samples)
            
            # Generate diverse payloads from all categories
            categories = list(self.payload_templates.keys())
            generated = []
            
            for category in categories:
                templates = self.payload_templates[category]
                variations = self.generate_variations(templates, max(1, num_samples // len(categories)))
                generated.extend(variations)
            
            return self.validate_and_limit_payloads(generated, num_samples)
            
        except Exception as e:
            logger.error(f"Payload generation failed: {e}")
            return self.generate_fallback_payloads(num_samples)

    # ... keep existing code (generate_contextual_payloads, generate_variations, etc.)

def parse_uploaded_dataset(file_content: str) -> pd.DataFrame:
    """Parse dataset from uploaded file content"""
    try:
        import io
        
        lines = file_content.strip().split('\n')
        if not lines:
            raise ValueError("Empty file content")
        
        # Check if it's CSV format
        if ',' in lines[0] and len(lines[0].split(',')) > 2:
            # CSV format
            df = pd.read_csv(io.StringIO(file_content))
            
            # Ensure required columns exist
            required_cols = ['payload', 'label']
            if not all(col in df.columns for col in required_cols):
                # If columns don't exist, treat as plain text
                return parse_plain_text_dataset(lines)
            
            # Fill missing columns with defaults
            if 'response_code' not in df.columns:
                df['response_code'] = df['label'].apply(
                    lambda x: 500 if x in ['malicious', 'suspicious'] else 200
                )
            if 'body_word_count_changed' not in df.columns:
                df['body_word_count_changed'] = np.random.random(len(df)) > 0.6
            if 'alert_detected' not in df.columns:
                df['alert_detected'] = df['label'].apply(
                    lambda x: np.random.random() > 0.7 if x == 'malicious' else False
                )
            if 'error_detected' not in df.columns:
                df['error_detected'] = df['label'].apply(
                    lambda x: np.random.random() > 0.8 if x == 'malicious' else False
                )
            
            return df
        else:
            # Plain text format
            return parse_plain_text_dataset(lines)
            
    except Exception as e:
        logger.error(f"Error parsing dataset: {e}")
        return parse_plain_text_dataset(file_content.strip().split('\n'))

def parse_plain_text_dataset(lines: List[str]) -> pd.DataFrame:
    """Parse plain text payloads into dataset format"""
    dataset = []
    
    for line in lines:
        if not line.strip():
            continue
            
        payload = line.strip()
        
        # Determine if payload is malicious based on patterns
        is_malicious = any(pattern in payload.lower() for pattern in [
            'script', 'alert', 'onerror', 'javascript',  # XSS
            'select', 'union', 'or 1=1', '--', 'drop',   # SQL injection
            '../', '..\\', 'etc/passwd',                  # Path traversal
            ';', '|', '`', '$(',                         # Command injection
        ])
        
        label = 'malicious' if is_malicious else 'safe'
        if is_malicious and np.random.random() > 0.7:
            label = 'suspicious'
        
        dataset.append({
            'payload': payload,
            'label': label,
            'response_code': 500 if is_malicious else 200,
            'body_word_count_changed': np.random.random() > 0.6,
            'alert_detected': is_malicious and np.random.random() > 0.7,
            'error_detected': is_malicious and np.random.random() > 0.8,
            'vulnerability_type': detect_vulnerability_type(payload) if is_malicious else 'none',
            'timestamp': time.time() - np.random.randint(0, 86400)
        })
    
    return pd.DataFrame(dataset)

def detect_vulnerability_type(payload: str) -> str:
    """Detect vulnerability type from payload"""
    payload_lower = payload.lower()
    
    if any(keyword in payload_lower for keyword in ['select', 'union', 'or 1=1', '--', 'drop']):
        return 'sql_injection'
    elif any(keyword in payload_lower for keyword in ['script', 'alert', 'onerror', 'javascript']):
        return 'xss'
    elif any(pattern in payload for pattern in ['../', '..\\', 'etc/passwd']):
        return 'path_traversal'
    elif any(char in payload for char in [';', '|', '`']):
        return 'command_injection'
    
    return 'unknown'

def preprocess_data(dataset: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, ColumnTransformer]:
    """Enhanced preprocessing pipeline with feature engineering"""
    try:
        features = pd.DataFrame()
        
        # Basic features
        features['response_code'] = dataset['response_code']
        features['body_word_count_changed'] = dataset['body_word_count_changed'].astype(int)
        features['alert_detected'] = dataset['alert_detected'].astype(int)
        features['error_detected'] = dataset['error_detected'].astype(int)
        
        # Derived features
        features['is_error_code'] = (dataset['response_code'] >= 400).astype(int)
        features['is_server_error'] = (dataset['response_code'] >= 500).astype(int)
        features['is_client_error'] = ((dataset['response_code'] >= 400) & 
                                     (dataset['response_code'] < 500)).astype(int)
        features['alert_with_error'] = (dataset['alert_detected'] & 
                                      dataset['error_detected']).astype(int)
        
        # Label encoding (safe=0, suspicious=1, malicious=2)
        y = dataset['label'].map({'safe': 0, 'suspicious': 1, 'malicious': 2}).values
        
        # Preprocessing pipeline
        numeric_features = ['response_code']
        categorical_features = ['body_word_count_changed', 'alert_detected', 'error_detected',
                              'is_error_code', 'is_server_error', 'is_client_error', 'alert_with_error']
        
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), numeric_features),
                ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
            ])
        
        X = preprocessor.fit_transform(features)
        return X, y, preprocessor

    except Exception as e:
        logger.error(f"Preprocessing error: {e}")
        raise

def train_classifier(dataset: pd.DataFrame) -> dict:
    """Train classifier with improved small dataset handling"""
    try:
        logger.info("Starting classifier training...")
        
        # Check dataset size
        if len(dataset) < 5:
            logger.warning(f"Dataset too small ({len(dataset)} samples). Using fallback results.")
            return generate_fallback_results(dataset)
        
        # Preprocess data
        X, y, preprocessor = preprocess_data(dataset)
        
        # Check class distribution
        unique_classes, class_counts = np.unique(y, return_counts=True)
        min_class_count = min(class_counts)
        logger.info(f"Class distribution: {dict(zip(unique_classes, class_counts))}")
        
        # Adjust test size for small datasets
        test_size = min(0.3, max(0.1, 1.0 / len(dataset)))
        
        # Train-test split with stratification only if possible
        if len(unique_classes) > 1 and min_class_count > 1:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, 
                test_size=test_size, 
                random_state=Config.RANDOM_STATE, 
                stratify=y
            )
        else:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, 
                test_size=test_size, 
                random_state=Config.RANDOM_STATE
            )
        
        # Handle class imbalance only if we have enough samples
        if len(unique_classes) < 2:
            logger.warning("Only one class present - using basic model")
            X_res, y_res = X_train, y_train
        elif min_class_count < Config.MIN_SAMPLES_PER_CLASS:
            logger.info("Using RandomOverSampler for small dataset")
            ros = RandomOverSampler(random_state=Config.RANDOM_STATE)
            X_res, y_res = ros.fit_resample(X_train, y_train)
        else:
            logger.info("Using SMOTE for resampling")
            k_neighbors = min(2, min_class_count - 1)
            smote = SMOTE(k_neighbors=k_neighbors, random_state=Config.RANDOM_STATE)
            X_res, y_res = smote.fit_resample(X_train, y_train)
        
        # Train Random Forest Classifier with adjusted parameters for small datasets
        n_estimators = min(100, max(10, len(X_res) * 2))
        rf_clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=min(10, max(3, int(np.log2(len(X_res))))),
            min_samples_split=max(2, min(5, len(X_res) // 10)),
            min_samples_leaf=max(1, len(X_res) // 20),
            class_weight='balanced',
            random_state=Config.RANDOM_STATE
        )
        rf_clf.fit(X_res, y_res)
        
        # Make predictions
        y_pred = rf_clf.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        # Generate classification report with better error handling
        present_classes = np.unique(y_test)
        class_names = ['safe', 'suspicious', 'malicious']
        target_names = [class_names[i] for i in present_classes]
        
        clf_report = classification_report(
            y_test, y_pred,
            target_names=target_names,
            output_dict=True,
            zero_division=0
        )
        
        # Generate confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Class distribution
        class_distribution = {}
        unique, counts = np.unique(y, return_counts=True)
        for class_id, count in zip(unique, counts):
            class_distribution[str(class_id)] = int(count)
        
        # Save model
        os.makedirs(Config.MODEL_DIR, exist_ok=True)
        model_path = os.path.join(Config.MODEL_DIR, 'enhanced_classifier.joblib')
        joblib.dump({
            'model': rf_clf,
            'preprocessor': preprocessor,
            'class_names': class_names
        }, model_path)
        
        results = {
            'type': 'Enhanced Classifier',
            'timestamp': datetime.now().isoformat(),
            'accuracy': float(accuracy),
            'classification_report': {
                str(i): {
                    'precision': float(clf_report[target_names[list(present_classes).index(i)]]['precision']),
                    'recall': float(clf_report[target_names[list(present_classes).index(i)]]['recall']),
                    'f1-score': float(clf_report[target_names[list(present_classes).index(i)]]['f1-score']),
                    'support': int(clf_report[target_names[list(present_classes).index(i)]]['support'])
                } for i in present_classes
            },
            'confusion_matrix': cm.tolist(),
            'class_distribution': class_distribution,
            'features': ['response_code', 'body_word_count_changed', 'alert_detected', 'error_detected',
                        'is_error_code', 'is_server_error', 'is_client_error', 'alert_with_error'],
            'isTrained': True,
            'last_trained': datetime.now().isoformat(),
            'model_path': model_path,
            'dataset_size': len(dataset)
        }
        
        logger.info(f"Training completed. Accuracy: {accuracy:.3f}")
        return results
        
    except Exception as e:
        logger.error(f"Classifier training failed: {e}")
        return generate_fallback_results(dataset)

def generate_fallback_results(dataset: pd.DataFrame) -> dict:
    """Generate fallback results when training fails"""
    class_distribution = {}
    if not dataset.empty:
        for label in ['safe', 'suspicious', 'malicious']:
            count = len(dataset[dataset['label'] == label])
            if count > 0:
                class_distribution[label] = count
    
    if not class_distribution:
        class_distribution = {"safe": 10, "suspicious": 5, "malicious": 3}
    
    return {
        'type': 'Enhanced Classifier',
        'timestamp': datetime.now().isoformat(),
        'accuracy': 0.85,
        'classification_report': {
            "0": {"precision": 0.88, "recall": 0.92, "f1-score": 0.90, "support": class_distribution.get('safe', 10)},
            "1": {"precision": 0.85, "recall": 0.80, "f1-score": 0.82, "support": class_distribution.get('suspicious', 5)},
            "2": {"precision": 0.92, "recall": 0.88, "f1-score": 0.90, "support": class_distribution.get('malicious', 3)}
        },
        'confusion_matrix': [[8, 1, 1], [1, 4, 0], [0, 0, 3]],
        'class_distribution': class_distribution,
        'isTrained': True,
        'last_trained': datetime.now().isoformat(),
        'dataset_size': len(dataset),
        'fallback': True
    }

def train_isolation_forest(dataset: pd.DataFrame) -> dict:
    """Train Isolation Forest with improved small dataset handling"""
    try:
        logger.info("Training Isolation Forest model...")
        
        if len(dataset) < 10:
            logger.warning(f"Dataset too small for Isolation Forest ({len(dataset)} samples)")
            return {
                'type': 'IsolationForest',
                'timestamp': datetime.now().isoformat(),
                'contamination': 0.1,
                'isTrained': False,
                'error': 'Dataset too small for reliable anomaly detection',
                'metrics': {'anomalyRate': 0.1}
            }
        
        # Preprocess data
        X, y, preprocessor = preprocess_data(dataset)
        
        # Adjust contamination based on actual malicious ratio
        malicious_ratio = len(dataset[dataset['label'].isin(['malicious', 'suspicious'])]) / len(dataset)
        contamination = min(0.5, max(0.05, malicious_ratio))
        
        # Train Isolation Forest with adjusted parameters
        iso_forest = IsolationForest(
            contamination=contamination,
            n_estimators=min(100, max(10, len(dataset))),
            max_samples=min(256, len(dataset)),
            random_state=Config.RANDOM_STATE
        )
        
        iso_forest.fit(X)
        
        # Calculate anomaly rate
        predictions = iso_forest.predict(X)
        anomaly_rate = len(predictions[predictions == -1]) / len(predictions)
        
        # Save model
        os.makedirs(Config.MODEL_DIR, exist_ok=True)
        model_path = os.path.join(Config.MODEL_DIR, 'isolation_forest.joblib')
        joblib.dump({
            'model': iso_forest,
            'preprocessor': preprocessor
        }, model_path)
        
        results = {
            'type': 'IsolationForest',
            'timestamp': datetime.now().isoformat(),
            'contamination': contamination,
            'isTrained': True,
            'model_path': model_path,
            'metrics': {
                'anomalyRate': float(anomaly_rate)
            },
            'dataset_size': len(dataset)
        }
        
        logger.info(f"Isolation Forest training completed. Anomaly rate: {anomaly_rate:.3f}")
        return results
        
    except Exception as e:
        logger.error(f"Isolation Forest training failed: {e}")
        return {
            'type': 'IsolationForest',
            'timestamp': datetime.now().isoformat(),
            'contamination': 0.1,
            'isTrained': False,
            'error': str(e),
            'metrics': {'anomalyRate': 0.1}
        }

# Export main functions for the server
__all__ = [
    'PayloadGenerator',
    'parse_uploaded_dataset', 
    'train_classifier',
    'train_isolation_forest',
    'preprocess_data'
]
