from flask import Flask, render_template, request
from backend.modules.hash_checker import calculate_hashes
from backend.modules.log_analyzer import parse_auth_log
from backend.modules.timeline_generator import generate_timeline
from backend.modules.db_manager import init_db, save_evidence, get_all_evidence

app = Flask(__name__)

# Initialize the database when the app starts
init_db()

@app.route('/')
def home():
    # Fetch all stored evidence to display on the home page
    saved_evidence = get_all_evidence()
    return render_template('index.html', saved_evidence=saved_evidence)

@app.route('/hash', methods=['POST'])
def hash_file():
    if 'file' not in request.files:
        return "No file uploaded", 400
    
    file = request.files['file']
    filename = file.filename
    file_content = file.read()
    
    hashes = calculate_hashes(file_content)
    
    # NEW: Save the results to our SQLite database
    save_evidence(filename, hashes['MD5'], hashes['SHA256'])
    
    saved_evidence = get_all_evidence()
    return render_template('index.html', hashes=hashes, filename=filename, saved_evidence=saved_evidence)

@app.route('/analyze-log', methods=['POST'])
def analyze_log():
    if 'file' not in request.files:
        return "No file uploaded", 400
    
    file = request.files['file']
    log_content = file.read()
    
    # We now run BOTH the log analyzer and the timeline generator
    suspicious_activity = parse_auth_log(log_content)
    timeline = generate_timeline(log_content)
    
    saved_evidence = get_all_evidence()
    return render_template('index.html', logs=suspicious_activity, timeline=timeline, saved_evidence=saved_evidence)

if __name__ == '__main__':
    app.run(debug=True)