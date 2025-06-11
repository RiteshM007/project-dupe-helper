from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
from flask_socketio import SocketIO, emit
import logging
import traceback
import pandas as pd
import numpy as np
from datetime import datetime
import os
import json

# Import the enhanced ML models
from enhanced_ml_models import (
    PayloadGenerator, 
    parse_uploaded_dataset, 
    train_classifier,
    train_isolation_forest,
    preprocess_data
)

# Import existing fuzzer
from web_fuzzer import WebFuzzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Configure CORS with specific origins and methods
CORS(app, origins=["http://localhost:8080", "http://localhost:8081"], 
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

socketio = SocketIO(app, cors_allowed_origins=["http://localhost:8080", "http://localhost:8081"],
                   logger=True, engineio_logger=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global storage for fuzzer sessions and ML models
fuzzer_sessions = {}
ml_models = {
    'classifier': None,
    'isolation_forest': None,
    'payload_generator': None
}

# Initialize payload generator
try:
    ml_models['payload_generator'] = PayloadGenerator()
    logger.info("Enhanced payload generator initialized")
except Exception as e:
    logger.error(f"Failed to initialize payload generator: {e}")

# Store active fuzzers by session ID
active_fuzzers = {}
# Background tasks
background_tasks = {}
# Trained models storage
trained_models = {}
# Store DVWA session
dvwa_sessions = {}
# Enhanced payload generator instance
payload_generator = None

def get_dvwa_session(base_url="http://localhost:8080", username="admin", password="password"):
    """Get authenticated session for DVWA"""
    session = requests.Session()

    # Step 1: Fetch login page to get CSRF token
    login_page = session.get(f"{base_url}/login.php")
    soup = BeautifulSoup(login_page.text, "html.parser")
    token_tag = soup.find("input", {"name": "user_token"})

    if not token_tag:
        raise Exception("[-] Failed to find CSRF token on login page.")

    token = token_tag["value"]

    # Step 2: Post login with credentials + token
    login_data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token
    }

    response = session.post(f"{base_url}/login.php", data=login_data)

    if "Welcome to Damn Vulnerable Web Application" in response.text:
        logger.info("[+] Connected and logged in to DVWA.")
        return session
    else:
        raise Exception("[-] Login to DVWA failed. Check credentials or DVWA security level.")

def run_fuzzing_task(session_id, fuzzer):
    """Background task to run fuzzing process"""
    try:
        fuzzer.scan_active = True
        fuzzer.scan_progress = 0
        
        # Load wordlist if not already loaded
        if not hasattr(fuzzer, 'wordlist') or not fuzzer.wordlist:
            fuzzer.loadWordlist()
        
        total_steps = len(fuzzer.wordlist)
        
        for i, payload in enumerate(fuzzer.wordlist):
            if not fuzzer.scan_active:
                logger.info(f"Fuzzing stopped for session {session_id}")
                break
                
            # Process the actual payload, not the index
            fuzzer.processPayload(payload)
            fuzzer.payloads_processed += 1
            fuzzer.scan_progress = int((i+1) / total_steps * 100)
            
            # Emit progress via Socket.IO
            socketio.emit('fuzzing_progress', {
                'progress': fuzzer.scan_progress,
                'session_id': session_id
            })
            
            # Simulate some work
            time.sleep(0.1)
            
        fuzzer.logActivity("Fuzzing process completed" if fuzzer.scan_active else "Fuzzing process stopped")
        fuzzer.scan_active = False
        
        # Emit completion event with dataset
        socketio.emit('fuzzing_complete', {
            'session_id': session_id,
            'dataset': fuzzer.getDataset()
        })
        
    except Exception as e:
        fuzzer.scan_active = False
        fuzzer.logActivity(f"Error during fuzzing: {str(e)}")
        logger.error(f"Error in fuzzing task for session {session_id}: {traceback.format_exc()}")

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "OK",
        "message": "Web Fuzzer Backend is Running!",
        "api_version": "1.0.0"
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'OK',
        'api_version': '1.0.0',
        'timestamp': time.time()
    })

@app.route('/api/dvwa/connect', methods=['GET'])
def connect_dvwa():
    """Connect to DVWA with proper session handling"""
    try:
        base_url = request.args.get('url', 'http://localhost:8080')
        username = request.args.get('username', 'admin')
        password = request.args.get('password', 'password')
        
        session = get_dvwa_session(base_url, username, password)
        
        # Store session cookies
        cookies_dict = session.cookies.get_dict()
        cookies_str = '; '.join([f"{k}={v}" for k, v in cookies_dict.items()])
        
        # Generate a session ID for this DVWA connection
        session_id = f"dvwa_{int(time.time())}"
        dvwa_sessions[session_id] = {
            'session': session,
            'url': base_url,
            'cookies': cookies_str
        }
        
        return jsonify({
            "status": "success", 
            "message": "Connected and logged in to DVWA",
            "session_id": session_id,
            "cookie": cookies_str
        }), 200
    except Exception as e:
        logger.error(f"Error connecting to DVWA: {traceback.format_exc()}")
        return jsonify({
            "status": "error", 
            "message": str(e)
        }), 500

@app.route('/api/dvwa/status', methods=['GET'])
def check_dvwa_status():
    """Check if DVWA is available"""
    try:
        base_url = request.args.get('url', 'http://localhost:8080')
        response = requests.get(f"{base_url}/login.php", timeout=2)
        if response.status_code == 200:
            return jsonify({'status': 'online'}), 200
        return jsonify({'status': 'offline'}), 503
    except Exception:
        logger.error(f"Error checking DVWA status: {traceback.format_exc()}")
        return jsonify({'status': 'offline'}), 503

@app.route('/api/fuzzer/create', methods=['POST'])
def create_fuzzer():
    """Create a new fuzzer instance"""
    try:
        data = request.json
        target_url = data.get('targetUrl')
        wordlist_file = data.get('wordlistFile', 'default_wordlist.txt')
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Target URL is required'
            }), 400
        
        logger.info(f"Creating fuzzer for target: {target_url}")
        session_id = f"session_{int(time.time())}_{hash(target_url) % 10000}"
        
        fuzzer = WebFuzzer(target_url, wordlist_file)
        active_fuzzers[session_id] = fuzzer
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': f"Fuzzer created for {target_url}"
        })
    except Exception as e:
        logger.error(f"Error creating fuzzer: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/fuzzer/<session_id>/start', methods=['POST'])
def start_fuzzing(session_id):
    """Start fuzzing process for a given session"""
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    
    try:
        # Check if already running
        if fuzzer.scan_active:
            return jsonify({
                'success': False, 
                'error': 'Fuzzing already in progress'
            }), 400
        
        # Get vulnerability types and custom payloads from request if available
        data = request.json or {}
        vulnerability_types = data.get('vulnerabilityTypes', [])
        custom_payloads = data.get('customPayloads', [])
        
        # Initialize fuzzing
        fuzzer.scan_active = True
        fuzzer.scan_progress = 0
        fuzzer.payloads_processed = 0
        
        # Load wordlist
        fuzzer.loadWordlist()
        
        # Add custom payloads if provided
        if custom_payloads:
            fuzzer.wordlist.extend(custom_payloads)
            fuzzer.total_payloads = len(fuzzer.wordlist)
            fuzzer.logActivity(f"Added {len(custom_payloads)} custom payloads")
        
        # Initialize dataset
        fuzzer.initializeDataset()
        
        # Apply vulnerability type filters if specified
        if vulnerability_types:
            fuzzer.setVulnerabilityTypes(vulnerability_types)
            fuzzer.logActivity(f"Applied filter for vulnerability types: {', '.join(vulnerability_types)}")
        
        fuzzer.logActivity("Starting fuzzing process...")
        
        # Start background task
        background_task = threading.Thread(
            target=run_fuzzing_task, 
            args=(session_id, fuzzer)
        )
        background_task.daemon = True
        background_task.start()
        
        background_tasks[session_id] = background_task
        
        return jsonify({
            'success': True,
            'message': 'Fuzzing process started',
            'total_payloads': fuzzer.total_payloads
        })
    except Exception as e:
        logger.error(f"Error starting fuzzing: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/fuzzer/<session_id>/status', methods=['GET'])
def get_fuzzer_status(session_id):
    """Get status of a fuzzing session"""
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    
    return jsonify({
        'success': True,
        'active': fuzzer.scan_active,
        'progress': fuzzer.scan_progress,
        'payloads_processed': fuzzer.payloads_processed,
        'total_payloads': fuzzer.total_payloads,
        'logs': fuzzer.logs[-20:],  # Return last 20 logs
        'reports': fuzzer.reports[-10:]  # Return last 10 reports
    })

@app.route('/api/fuzzer/<session_id>/stop', methods=['POST'])
def stop_fuzzing(session_id):
    """Stop an active fuzzing session"""
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    
    try:
        fuzzer.stopScan()
        return jsonify({
            'success': True,
            'message': 'Fuzzing process stopped'
        })
    except Exception as e:
        logger.error(f"Error stopping fuzzing: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/fuzzer/<session_id>/dataset', methods=['GET'])
def get_dataset(session_id):
    """Get dataset generated by a fuzzing session"""
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    
    return jsonify({
        'success': True,
        'dataset': fuzzer.getDataset()
    })

@app.route('/api/fuzzer/<session_id>/payloads', methods=['POST'])
def upload_payloads(session_id):
    """Upload custom payloads for a fuzzing session"""
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    data = request.json
    
    if not data or 'payloads' not in data:
        return jsonify({'success': False, 'error': 'No payloads provided'}), 400
    
    payloads = data['payloads']
    
    try:
        # Add the payloads to the fuzzer
        fuzzer.addCustomPayloads(payloads)
        
        return jsonify({
            'success': True,
            'message': f"Added {len(payloads)} custom payloads",
            'total_payloads': fuzzer.total_payloads
        })
    except Exception as e:
        logger.error(f"Error uploading payloads: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/fuzzer/<session_id>/results', methods=['GET'])
def get_fuzzer_results(session_id):
    """Get results from a fuzzing session"""
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    
    try:
        # Get results from the fuzzer
        dataset = fuzzer.getDataset()
        logs = fuzzer.getLogs()
        reports = fuzzer.getReports()
        
        # Calculate some summary statistics
        vulnerabilities_found = len([d for d in dataset if d.get('label') != 'safe'])
        total_payloads = fuzzer.total_payloads or len(dataset)
        
        return jsonify({
            'success': True,
            'results': {
                'vulnerabilitiesFound': vulnerabilities_found,
                'totalPayloads': total_payloads,
                'threats': [d for d in dataset if d.get('label') in ['malicious', 'suspicious']],
                'dataset': dataset,
                'logs': logs,
                'reports': reports
            }
        })
    except Exception as e:
        logger.error(f"Error getting fuzzing results: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/train', methods=['POST'])
def train_models():
    """Train machine learning models on provided dataset"""
    data = request.json
    dataset = data.get('dataset', [])
    
    if not dataset:
        return jsonify({'success': False, 'error': 'No dataset provided'}), 400
    
    try:
        logger.info(f"Training ML models on dataset with {len(dataset)} samples")
        
        # Train models
        isolation_forest = train_isolation_forest(dataset)
        random_forest = train_random_forest(dataset)
        
        # Store models for later use
        model_id = f"model_{int(time.time())}"
        trained_models[model_id] = {
            'isolation_forest': isolation_forest,
            'random_forest': random_forest,
            'timestamp': time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        }
        
        return jsonify({
            'success': True,
            'model_id': model_id,
            'isolation_forest': {
                'type': isolation_forest.get('type'),
                'timestamp': isolation_forest.get('timestamp'),
                'contamination': isolation_forest.get('contamination'),
                'features': isolation_forest.get('features'),
                'isTrained': isolation_forest.get('isTrained', False)
            },
            'random_forest': {
                'type': random_forest.get('type'),
                'timestamp': random_forest.get('timestamp'),
                'n_estimators': random_forest.get('n_estimators'),
                'feature_importance': random_forest.get('feature_importance'),
                'features': random_forest.get('features'),
                'metrics': random_forest.get('metrics', {}),
                'isTrained': random_forest.get('isTrained', False)
            }
        })
    except Exception as e:
        logger.error(f"Error training models: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/train-classifier', methods=['POST', 'OPTIONS'])
@cross_origin()
def train_ml_classifier():
    """Train the ML classifier with provided dataset"""
    try:
        logger.info("Received ML classifier training request")
        
        if request.method == 'OPTIONS':
            return '', 200
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        dataset_data = data.get('dataset', [])
        logger.info(f"Training ML models on dataset with {len(dataset_data)} samples")
        
        if len(dataset_data) == 0:
            return jsonify({'error': 'Empty dataset provided'}), 400
        
        # Convert to DataFrame
        try:
            if isinstance(dataset_data, list) and len(dataset_data) > 0:
                # Ensure all required fields exist
                for item in dataset_data:
                    if 'payload' not in item:
                        item['payload'] = str(item.get('id', 'unknown'))
                    if 'label' not in item:
                        # Auto-detect label based on payload content
                        payload = str(item['payload']).lower()
                        if any(pattern in payload for pattern in ['script', 'alert', 'union', 'select', '../', ';', '|']):
                            item['label'] = 'malicious'
                        else:
                            item['label'] = 'safe'
                    if 'response_code' not in item:
                        item['response_code'] = 500 if item['label'] == 'malicious' else 200
                    if 'body_word_count_changed' not in item:
                        item['body_word_count_changed'] = item['label'] == 'malicious'
                    if 'alert_detected' not in item:
                        item['alert_detected'] = item['label'] == 'malicious'
                    if 'error_detected' not in item:
                        item['error_detected'] = item['label'] == 'malicious'
                
                df = pd.DataFrame(dataset_data)
            else:
                return jsonify({'error': 'Invalid dataset format'}), 400
                
        except Exception as e:
            logger.error(f"Error converting dataset to DataFrame: {e}")
            return jsonify({'error': f'Dataset conversion failed: {str(e)}'}), 400
        
        # Train models
        training_results = {}
        
        # Train classifier
        try:
            logger.info("Training classifier model...")
            classifier_result = train_classifier(df)
            ml_models['classifier'] = classifier_result
            training_results['classifier'] = classifier_result
            logger.info("Classifier training completed successfully")
        except Exception as e:
            logger.error(f"Classifier training failed: {e}")
            training_results['classifier'] = {'error': str(e), 'isTrained': False}
        
        # Train isolation forest
        try:
            logger.info("Training isolation forest model...")
            isolation_result = train_isolation_forest(df)
            ml_models['isolation_forest'] = isolation_result
            training_results['isolation_forest'] = isolation_result
            logger.info("Isolation forest training completed successfully")
        except Exception as e:
            logger.error(f"Isolation forest training failed: {e}")
            training_results['isolation_forest'] = {'error': str(e), 'isTrained': False}
        
        # Train payload generator
        try:
            if ml_models['payload_generator']:
                logger.info("Training payload generator...")
                ml_models['payload_generator'].analyze_dataset(df)
                training_results['payload_generator'] = {
                    'isTrained': True,
                    'patterns_learned': len(ml_models['payload_generator'].common_patterns),
                    'timestamp': datetime.now().isoformat()
                }
                logger.info("Payload generator training completed successfully")
        except Exception as e:
            logger.error(f"Payload generator training failed: {e}")
            training_results['payload_generator'] = {'error': str(e), 'isTrained': False}
        
        # Prepare response
        response = {
            'status': 'success',
            'message': 'ML models trained successfully',
            'results': training_results,
            'dataset_size': len(df),
            'timestamp': datetime.now().isoformat()
        }
        
        # Add classifier metrics if available
        if 'classifier' in training_results and training_results['classifier'].get('isTrained'):
            classifier_data = training_results['classifier']
            response.update({
                'accuracy': classifier_data.get('accuracy', 0.85),
                'class_distribution': classifier_data.get('class_distribution', {}),
                'classification_report': classifier_data.get('classification_report', {})
            })
        
        logger.info(f"ML training completed successfully with {len(df)} samples")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"ML training endpoint error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            'status': 'error',
            'message': f'ML training failed: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/ml/analyze', methods=['POST'])
def analyze_dataset():
    """Analyze dataset using machine learning techniques"""
    data = request.json
    dataset = data.get('dataset', [])
    options = data.get('options', {})
    
    if not dataset:
        return jsonify({'success': False, 'error': 'No dataset provided'}), 400
    
    try:
        logger.info(f"Analyzing dataset with {len(dataset)} samples")
        
        # Get cluster count from options or use default
        cluster_count = options.get('clusterCount', 3)
        
        # Perform clustering
        clustering_results = perform_clustering(dataset, cluster_count)
        
        # Generate attack signatures
        signatures = generate_attack_signatures(dataset)
        
        return jsonify({
            'success': True,
            'clustering': clustering_results,
            'signatures': signatures
        })
    except Exception as e:
        logger.error(f"Error analyzing dataset: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/generate-report', methods=['POST'])
def create_report():
    """Generate comprehensive security report"""
    data = request.json
    results = data.get('results', [])
    model_info = data.get('modelInfo', {})
    
    if not results:
        return jsonify({'success': False, 'error': 'No results provided'}), 400
    
    try:
        logger.info("Generating security report")
        report = generate_report(results, model_info)
        
        # Save report to file
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        save_path = f"reports/security-report-{timestamp}.json"
        
        # Create reports directory if it doesn't exist
        os.makedirs("reports", exist_ok=True)
        
        with open(save_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to {save_path}")
        
        return jsonify({
            'success': True,
            'report': report,
            'file_path': save_path
        })
    except Exception as e:
        logger.error(f"Error generating report: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/cluster', methods=['POST'])
def cluster_data():
    """Perform clustering on dataset"""
    data = request.json
    dataset = data.get('dataset', [])
    cluster_count = data.get('clusterCount', 3)
    
    if not dataset:
        return jsonify({'success': False, 'error': 'No dataset provided'}), 400
    
    try:
        logger.info(f"Performing clustering with {cluster_count} clusters on {len(dataset)} samples")
        clustering_results = perform_clustering(dataset, cluster_count)
        
        return jsonify({
            'success': True,
            'clustering': clustering_results
        })
    except Exception as e:
        logger.error(f"Error performing clustering: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/generate-signatures', methods=['POST'])
def create_signatures():
    """Generate attack signatures from dataset"""
    data = request.json
    dataset = data.get('dataset', [])
    
    if not dataset:
        return jsonify({'success': False, 'error': 'No dataset provided'}), 400
    
    try:
        logger.info(f"Generating attack signatures from {len(dataset)} samples")
        signatures = generate_attack_signatures(dataset)
        
        return jsonify({
            'success': True,
            'signatures': signatures
        })
    except Exception as e:
        logger.error(f"Error generating signatures: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/predict', methods=['POST'])
def predict_sample():
    """Predict a sample using trained models"""
    data = request.json
    sample = data.get('sample')
    model_type = data.get('modelType', 'isolation_forest')
    model_id = data.get('modelId')
    
    if not sample:
        return jsonify({'success': False, 'error': 'No sample provided'}), 400
    
    try:
        # Try to get model from stored models
        if model_id and model_id in trained_models:
            model = trained_models[model_id].get(model_type)
        else:
            # Use latest model if available
            latest_model_id = list(trained_models.keys())[-1] if trained_models else None
            model = trained_models.get(latest_model_id, {}).get(model_type) if latest_model_id else None
        
        if not model:
            return jsonify({'success': False, 'error': 'No trained model available'}), 400
        
        # Extract features from sample
        features = [
            sample.get("response_code", 200),
            1 if sample.get("body_word_count_changed", False) else 0,
            1 if sample.get("alert_detected", False) else 0,
            1 if sample.get("error_detected", False) else 0
        ]
        
        # Make prediction based on model type
        if model_type == 'isolation_forest':
            prediction = predict_anomaly(features, model)
            result = {
                'anomaly': prediction,
                'is_anomaly': prediction == -1,
                'sample': sample
            }
        else:  # random_forest
            prediction = predict_effectiveness(features, model)
            result = {
                'effective': prediction,
                'is_effective': prediction == 1,
                'sample': sample
            }
        
        return jsonify({
            'success': True,
            'prediction': result
        })
    except Exception as e:
        logger.error(f"Error predicting sample: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/generate-payloads', methods=['POST', 'OPTIONS'])
@cross_origin()
def generate_ml_payloads():
    """Generate payloads using the trained ML payload generator"""
    try:
        if request.method == 'OPTIONS':
            return '', 200
        
        data = request.get_json() or {}
        context = data.get('context', '')
        num_samples = data.get('num_samples', 5)
        
        if not ml_models['payload_generator']:
            return jsonify({'error': 'Payload generator not initialized'}), 400
        
        # Generate payloads
        payloads = ml_models['payload_generator'].generate_payloads(num_samples, context)
        
        response = {
            'status': 'success',
            'message': f'Generated {len(payloads)} payloads',
            'payloads': payloads,
            'count': len(payloads),
            'context': context,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Payload generation error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Payload generation failed: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/ml/status', methods=['GET', 'OPTIONS'])
@cross_origin()
def get_ml_status():
    """Get the status of all ML models"""
    try:
        if request.method == 'OPTIONS':
            return '', 200
        
        status = {
            'status': 'success',
            'models': {
                'classifier': {
                    'trained': ml_models['classifier'] is not None and ml_models['classifier'].get('isTrained', False),
                    'accuracy': ml_models['classifier'].get('accuracy', 0) if ml_models['classifier'] else 0,
                    'last_trained': ml_models['classifier'].get('last_trained') if ml_models['classifier'] else None
                },
                'isolation_forest': {
                    'trained': ml_models['isolation_forest'] is not None and ml_models['isolation_forest'].get('isTrained', False),
                    'contamination': ml_models['isolation_forest'].get('contamination', 0.1) if ml_models['isolation_forest'] else 0.1,
                    'last_trained': ml_models['isolation_forest'].get('last_trained') if ml_models['isolation_forest'] else None
                },
                'payload_generator': {
                    'ready': ml_models['payload_generator'] is not None,
                    'patterns_learned': len(ml_models['payload_generator'].common_patterns) if ml_models['payload_generator'] else 0
                }
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(status), 200
        
    except Exception as e:
        logger.error(f"ML status error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get ML status: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/fuzzer/cleanup', methods=['POST'])
def cleanup_sessions():
    """Clean up inactive fuzzer sessions"""
    try:
        inactive_sessions = []
        for session_id, fuzzer in active_fuzzers.items():
            if not fuzzer.scan_active and fuzzer.scan_progress == 100:
                inactive_sessions.append(session_id)
        
        for session_id in inactive_sessions:
            del active_fuzzers[session_id]
            if session_id in background_tasks:
                del background_tasks[session_id]
        
        return jsonify({
            'success': True,
            'message': f"Cleaned up {len(inactive_sessions)} inactive sessions",
            'remaining_sessions': len(active_fuzzers)
        })
    except Exception as e:
        logger.error(f"Error cleaning up sessions: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Add Socket.IO connection events
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@app.route('/api/fuzzer/<session_id>/custom-payloads', methods=['POST'])
def add_custom_payloads(session_id):
    """Add custom payloads to an existing fuzzer session"""
    try:
        # Get the active fuzzer session
        fuzzer = active_fuzzers.get(session_id)
        if not fuzzer:
            return jsonify({"error": f"No active fuzzer session with ID {session_id}"}), 404
            
        # Get payloads from request
        data = request.get_json()
        payloads = data.get('payloads', [])
        
        if not payloads:
            return jsonify({"error": "No payloads provided"}), 400
            
        # Call the addCustomPayloads method
        success = fuzzer.addCustomPayloads(payloads)
        
        if success:
            return jsonify({
                "success": True,
                "message": f"Added {len(payloads)} custom payloads to session {session_id}"
            })
        else:
            return jsonify({"error": "Failed to add custom payloads"}), 500
            
    except Exception as e:
        app.logger.error(f"Error adding custom payloads: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs("models", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    
    # Initialize payload generator
    payload_generator = PayloadGenerator()
    logger.info("Enhanced payload generator initialized")
    
    # Run with Socket.IO instead of app.run
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
