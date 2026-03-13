import os
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from backend.modules.hash_checker import calculate_hashes
from backend.modules.log_analyzer import parse_auth_log
from backend.modules.timeline_generator import generate_timeline
from backend.modules.db_manager import init_db, save_evidence, get_all_evidence
from backend.modules.pcap_analyzer import analyze_pcap

app = Flask(__name__)

# Configure the temporary upload folder for PCAP files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

init_db()

@app.route('/')
def home():
    saved_evidence = get_all_evidence()
    return render_template('index.html', saved_evidence=saved_evidence)

@app.route('/hash', methods=['POST'])
def hash_file():
    if 'file' not in request.files:
        return "No file uploaded", 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    file_content = file.read()
    
    hashes = calculate_hashes(file_content)
    save_evidence(filename, hashes['MD5'], hashes['SHA256'])
    
    saved_evidence = get_all_evidence()
    return render_template('index.html', hashes=hashes, filename=filename, saved_evidence=saved_evidence)

@app.route('/analyze-log', methods=['POST'])
def analyze_log():
    if 'file' not in request.files:
        return "No file uploaded", 400
    file = request.files['file']
    log_content = file.read()
    
    suspicious_activity = parse_auth_log(log_content)
    timeline = generate_timeline(log_content)
    
    saved_evidence = get_all_evidence()
    return render_template('index.html', logs=suspicious_activity, timeline=timeline, saved_evidence=saved_evidence)

# --- NEW ROUTE FOR PCAP ANALYZER ---
@app.route('/analyze-pcap', methods=['POST'])
def analyze_pcap_route():
    if 'file' not in request.files:
        return "No file uploaded", 400
    
    file = request.files['file']
    filename = secure_filename(file.filename)
    
    # Save the file temporarily so Scapy can read it
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    # Run the analysis
    suspicious_ips, alerts = analyze_pcap(filepath)
    
    # Clean up the file after analysis to save space
    if os.path.exists(filepath):
        os.remove(filepath)
        
    saved_evidence = get_all_evidence()
    return render_template('index.html', pcap_ips=suspicious_ips, pcap_alerts=alerts, saved_evidence=saved_evidence)

if __name__ == '__main__':
    app.run(debug=True)