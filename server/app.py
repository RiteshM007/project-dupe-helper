
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import time
import os
import sys
import logging
import threading
import traceback
from web_fuzzer import WebFuzzer
from ml_models import (
    train_isolation_forest,
    train_random_forest,
    predict_anomaly,
    predict_effectiveness,
    generate_report,
    perform_clustering,
    generate_attack_signatures
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Store active fuzzers by session ID
active_fuzzers = {}
# Background tasks
background_tasks = {}

def run_fuzzing_task(session_id, fuzzer):
    """Background task to run fuzzing process"""
    try:
        fuzzer.scan_active = True
        fuzzer.scan_progress = 0
        
        # Simulate fuzzing process (replace with actual implementation)
        total_steps = len(fuzzer.wordlist) if hasattr(fuzzer, 'wordlist') and fuzzer.wordlist else 100
        
        for i in range(total_steps):
            if not fuzzer.scan_active:
                logger.info(f"Fuzzing stopped for session {session_id}")
                break
                
            # Process a payload
            fuzzer.processPayload(i)
            fuzzer.payloads_processed += 1
            fuzzer.scan_progress = int((i+1) / total_steps * 100)
            
            # Simulate some work
            time.sleep(0.1)
            
        fuzzer.logActivity("Fuzzing process completed" if fuzzer.scan_active else "Fuzzing process stopped")
        fuzzer.scan_active = False
        
    except Exception as e:
        fuzzer.scan_active = False
        fuzzer.logActivity(f"Error during fuzzing: {str(e)}")
        logger.error(f"Error in fuzzing task for session {session_id}: {traceback.format_exc()}")

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'OK',
        'api_version': '1.0.0',
        'timestamp': time.time()
    })

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
        
        # Initialize fuzzing
        fuzzer.scan_active = True
        fuzzer.scan_progress = 0
        fuzzer.payloads_processed = 0
        
        # Load wordlist
        fuzzer.loadWordlist()
        
        # Initialize dataset
        fuzzer.initializeDataset()
        
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
            'message': 'Fuzzing process started'
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
        
        return jsonify({
            'success': True,
            'isolation_forest': {
                'type': isolation_forest.get('type'),
                'timestamp': isolation_forest.get('timestamp'),
                'features': isolation_forest.get('features')
            },
            'random_forest': {
                'type': random_forest.get('type'),
                'timestamp': random_forest.get('timestamp'),
                'feature_importance': random_forest.get('feature_importance'),
                'features': random_forest.get('features')
            }
        })
    except Exception as e:
        logger.error(f"Error training models: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/analyze', methods=['POST'])
def analyze_dataset():
    """Analyze dataset using machine learning techniques"""
    data = request.json
    dataset = data.get('dataset', [])
    
    if not dataset:
        return jsonify({'success': False, 'error': 'No dataset provided'}), 400
    
    try:
        logger.info(f"Analyzing dataset with {len(dataset)} samples")
        
        # Perform clustering
        clustering_results = perform_clustering(dataset)
        
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
        
        return jsonify({
            'success': True,
            'report': report
        })
    except Exception as e:
        logger.error(f"Error generating report: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
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

# Update Python dependencies in requirements.txt
<lov-write file_path="server/requirements.txt">
flask==2.0.1
flask-cors==3.0.10
scikit-learn==1.0.2
numpy==1.22.3
pandas==1.4.2
matplotlib==3.5.1
requests==2.27.1
python-dotenv==0.20.0
tqdm==4.64.0
colorama==0.4.4
