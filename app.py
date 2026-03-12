from flask import Flask, render_template, request
from backend.modules.hash_checker import calculate_hashes
from backend.modules.log_analyzer import parse_auth_log

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/hash', methods=['POST'])
def hash_file():
    if 'file' not in request.files:
        return "No file uploaded", 400
    
    file = request.files['file']
    file_content = file.read()
    
    hashes = calculate_hashes(file_content)
    return render_template('index.html', hashes=hashes)

@app.route('/analyze-log', methods=['POST'])
def analyze_log():
    if 'file' not in request.files:
        return "No file uploaded", 400
    
    file = request.files['file']
    log_content = file.read()
    
    suspicious_activity = parse_auth_log(log_content)
    return render_template('index.html', logs=suspicious_activity)

if __name__ == '__main__':
    app.run(debug=True)