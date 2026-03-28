import csv
import os
from datetime import datetime
from flask import Flask, request, jsonify, render_template

# Custom Modules
from features import extract_features
from rules import rule_check
from isolation_forest import detect_anomaly, force_learn_request
from ewma import ewma_engine
from rule_generator import generate_waf_rule

app = Flask(__name__)

LOG_FILE = "logs.csv"
WEIGHT_RULE = 0.5       # Rule Engine Weight (50 percentage)
WEIGHT_ML = 0.5         # ML Engine Weight (50 percentage)

# CHANGED: Default Threshold set to 0.50 as requested
BLOCKING_THRESHOLD = 0.50 

# --- DASHBOARD GLOBALS ---
stats = {"total_requests": 0, "blocked": 0, "anomalies": 0}
logs = []
request_log = {} 

# --- HELPERS ---

def log_event(ip, attack_type, risk_score, rule_desc):
    """Saves event to both RAM (Dashboard) and Disk (CSV)"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Update In-Memory List (Dashboard)
    logs.insert(0, {
        "time": timestamp,
        "ip": ip,
        "type": attack_type,
        "score": f"{risk_score:.2f}",
        "rule": rule_desc
    })
    if len(logs) > 50: logs.pop()

    # 2. Append to CSV (Persistence)
    file_needs_header = not os.path.exists(LOG_FILE)
    
    try:
        with open(LOG_FILE, mode='a', newline='') as file:
            writer = csv.writer(file)
            if file_needs_header:
                writer.writerow(["Timestamp", "IP", "Attack Type", "Risk Score", "Rule"])
            
            writer.writerow([timestamp, ip, attack_type, f"{risk_score:.2f}", rule_desc])
    except Exception as e:
        print(f"[ERROR] Writing to CSV failed: {e}")

# --- ROUTES ---

@app.route("/")
def dashboard():
    return render_template("dashboard.html", stats=stats, logs=logs)

# ======================================================
#  DYNAMIC CONFIG ENDPOINT
# ======================================================
@app.route("/config", methods=["GET", "POST"])
def config_update():
    global BLOCKING_THRESHOLD
    
    # 1. UPDATE Threshold (POST)
    if request.method == "POST":
        data = request.get_json()
        new_threshold = data.get("threshold")
        
        if new_threshold is not None:
            try:
                BLOCKING_THRESHOLD = float(new_threshold)
                return jsonify({
                    "message": f"Threshold updated to {BLOCKING_THRESHOLD}", 
                    "threshold": BLOCKING_THRESHOLD
                })
            except ValueError:
                return jsonify({"error": "Invalid float value"}), 400

    # 2. GET Current Threshold (GET)
    return jsonify({"threshold": BLOCKING_THRESHOLD})

# ======================================================
#  DETECTION ENDPOINT
# ======================================================
@app.route("/detect", methods=["POST", "GET"])
def detect():
    try:
        stats["total_requests"] += 1
        
        # 0. BOT DETECTION: Calculate Request Rate
        current_time = datetime.now().timestamp()
        client_ip = request.remote_addr or "unknown"

        if client_ip not in request_log:
            request_log[client_ip] = []

        # Remove requests older than 60 seconds
        request_log[client_ip] = [t for t in request_log[client_ip] if current_time - t < 60]

        # Add current request
        request_log[client_ip].append(current_time)
        current_rate = len(request_log[client_ip])

        # 1. Feature Extraction
        features = extract_features(request, request_rate=current_rate)
        
        # Safe Payload Extraction
        if request.is_json:
            data = request.get_json(silent=True) or {}
            payload = data.get('msg', '')
        else:
            payload = request.args.get('msg', '') or request.form.get('msg', '')

        #  CONSTRAINT CHECK
        if len(payload) > 2000: 
            stats["blocked"] += 1
            rules = generate_waf_rule(client_ip, "Buffer Overflow Attempt", 1.0)
            log_event(client_ip, "Buffer Overflow", 1.0, rules["iptables"])
            
            return jsonify({
                "decision": "BLOCK",
                "risk_score": 1.0,
                "reason": f"Payload length ({len(payload)}) exceeds safety limit (2000)",
                "suggested_rules": rules
            })

        # 2. Rules Engine
        rule_hit, rule_reason = rule_check(features)
        rule_score = 1.0 if rule_hit else 0.0

        # 3. ML Engine
        ml_anomaly, raw_score = detect_anomaly(features)
        anomaly_strength = 1.0 if ml_anomaly else 0.0
        ml_score = ewma_engine.update(client_ip, anomaly_strength)
        
        # 4. Final Scoring
        final_risk_score = (rule_score * WEIGHT_RULE) + (ml_score * WEIGHT_ML)

        # --- DECISION LOGIC ---
        # Uses the DYNAMIC global variable BLOCKING_THRESHOLD
        if final_risk_score > BLOCKING_THRESHOLD:
            stats["blocked"] += 1
            
            if rule_score > 0 and ml_score > 0.1:
                attack_type = "Hybrid Attack"
                reason = f"{rule_reason} + Anomalous"
            elif rule_score > 0:
                attack_type = "Known Attack (Rule)"
                reason = rule_reason
            else:
                attack_type = "Zero-Day Anomaly"
                reason = "Deviated from baseline"
                stats["anomalies"] += 1

            generated_rules = generate_waf_rule(client_ip, attack_type, final_risk_score)
            log_event(client_ip, attack_type, final_risk_score, generated_rules["iptables"])

            return jsonify({
                "decision": "BLOCK",
                "risk_score": final_risk_score,
                "reason": reason,
                "suggested_rules": generated_rules
            })

        else:
            log_event(client_ip, "Normal Traffic", final_risk_score, "Allowed")
            return jsonify({
                "decision": "ALLOW",
                "risk_score": final_risk_score,
                "reason": "Risk below threshold"
            })

    except Exception as e:
        print(f"[CRITICAL ERROR] App Crashed: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

# ======================================================
#  FEEDBACK LOOP ENDPOINT
# ======================================================
@app.route("/feedback", methods=["POST"])
def feedback():
    try:
        data = request.get_json()
        payload = data.get('msg', '')
        
        class MockRequest:
            def __init__(self, data):
                self.data = data
                self.method = "POST"
                self.path = "/feedback"
                self.remote_addr = "127.0.0.1"
                self.headers = {"User-Agent": "AdminFeedback/1.0"}
            def get_data(self, as_text=True):
                return self.data
        
        mock_req = MockRequest(payload)
        features = extract_features(mock_req)
        
        success = force_learn_request(features)
        
        if success:
            return jsonify({"status": "Model Updated", "message": "Feedback received. Retraining started."})
        else:
            return jsonify({"status": "Error", "message": "Failed to update model."}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ======================================================
#  RESET ENDPOINT (NEW: For Demo Smoothness)
# ======================================================
@app.route("/reset_stats", methods=["POST"])
def reset_stats():
    """
    Clears the rate-limit counter for the requesting IP.
    Call this between 'Training' and 'Testing' phases.
    """
    global request_log
    client_ip = request.remote_addr or "unknown"
    
    if client_ip in request_log:
        request_log[client_ip] = [] # Wipe the history
        
    return jsonify({"status": "Reset Successful", "message": "Rate limit counters cleared."})

if __name__ == "__main__":
   
    app.run(debug=True, port=5000, host='0.0.0.0', ssl_context=('../certs/cert.pem', '../certs/key.pem'))