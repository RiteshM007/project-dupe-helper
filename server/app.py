
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import time
import os
import sys
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

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Store active fuzzers by session ID
active_fuzzers = {}

@app.route('/api/fuzzer/create', methods=['POST'])
def create_fuzzer():
    data = request.json
    target_url = data.get('targetUrl')
    wordlist_file = data.get('wordlistFile', 'default_wordlist.txt')
    
    session_id = f"session_{int(time.time())}_{hash(target_url)}"
    
    try:
        fuzzer = WebFuzzer(target_url, wordlist_file)
        active_fuzzers[session_id] = fuzzer
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': f"Fuzzer created for {target_url}"
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/fuzzer/<session_id>/start', methods=['POST'])
def start_fuzzing(session_id):
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    
    try:
        # Start fuzzing in a non-blocking way
        # For a real implementation, you might use threading or Celery
        fuzzer.scan_active = True
        fuzzer.scan_progress = 0
        fuzzer.payloads_processed = 0
        
        # Load wordlist
        fuzzer.loadWordlist()
        
        # Initialize dataset
        fuzzer.initializeDataset()
        
        fuzzer.logActivity("Starting fuzzing process...")
        
        return jsonify({
            'success': True,
            'message': 'Fuzzing process started'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/fuzzer/<session_id>/status', methods=['GET'])
def get_fuzzer_status(session_id):
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    
    return jsonify({
        'success': True,
        'active': fuzzer.scan_active,
        'progress': fuzzer.scan_progress,
        'payloads_processed': fuzzer.payloads_processed,
        'total_payloads': fuzzer.total_payloads,
        'logs': fuzzer.logs[-10:],  # Return last 10 logs
        'reports': fuzzer.reports[-5:]  # Return last 5 reports
    })

@app.route('/api/fuzzer/<session_id>/stop', methods=['POST'])
def stop_fuzzing(session_id):
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
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/fuzzer/<session_id>/dataset', methods=['GET'])
def get_dataset(session_id):
    if session_id not in active_fuzzers:
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 404
    
    fuzzer = active_fuzzers[session_id]
    
    return jsonify({
        'success': True,
        'dataset': fuzzer.getDataset()
    })

@app.route('/api/ml/train', methods=['POST'])
def train_models():
    data = request.json
    dataset = data.get('dataset', [])
    
    if not dataset:
        return jsonify({'success': False, 'error': 'No dataset provided'}), 400
    
    try:
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
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/analyze', methods=['POST'])
def analyze_dataset():
    data = request.json
    dataset = data.get('dataset', [])
    
    if not dataset:
        return jsonify({'success': False, 'error': 'No dataset provided'}), 400
    
    try:
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
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ml/generate-report', methods=['POST'])
def create_report():
    data = request.json
    results = data.get('results', [])
    model_info = data.get('modelInfo', {})
    
    if not results:
        return jsonify({'success': False, 'error': 'No results provided'}), 400
    
    try:
        report = generate_report(results, model_info)
        
        return jsonify({
            'success': True,
            'report': report
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
