import numpy as np
import threading
import joblib
import os
from sklearn.ensemble import IsolationForest

model = None
baseline_buffer = []
BUFFER_SIZE = 50
RETRAIN_INTERVAL = 50
MODEL_PATH = "../models/waf_model.pkl"
lock = threading.Lock()

def initialize_model():
    """Create a new Isolation Forest instance with standard params"""
    return IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )

def feature_vector(features):
    """Extracts numerical vector from feature dictionary"""
    return [
        features.get("payload_size", 0),
        features.get("payload_entropy", 0),
        features.get("user_agent_length", 0),
        features.get("request_rate", 0)
    ]

def ensure_model_directory():
    directory = os.path.dirname(MODEL_PATH)
    if not os.path.exists(directory):
        os.makedirs(directory)
def train_model_async(snapshot):
    """Train model on snapshot of baseline buffer in background"""
    global model
    try:
        new_model =initialize_model()
        new_model.fit(np.array(snapshot))
        
        with lock:
            model = new_model
            joblib.dump(model, MODEL_PATH)
        
        print("[INFO] Isolation Forest retrained and saved.")
    except Exception as e:
        print(f"[ERROR] Training failed: {e}")

# ======================================================
# NEW: AUTO-TRAIN / BOOTSTRAP LOGIC
# ======================================================
def bootstrap_model_if_needed():
    """Generates synthetic normal traffic to pre-train model if file is missing"""
    global model
    
    # If model file exists, we are good.
    if os.path.exists(MODEL_PATH):
        return

    print("[WARNING] No model found! Bootstrapping with synthetic data...")
    dummy_data = []
    
    # Create 50 fake "normal" requests to teach the AI what "Safe" looks like
    for _ in range(BUFFER_SIZE + 10):
        vec = [
            np.random.randint(10, 50),     
            np.random.uniform(3.0, 4.5), 
            np.random.randint(50, 120),   
            1.0                           
        ]
        dummy_data.append(vec)
    clf=initialize_model()
    clf.fit(dummy_data)
    with lock:
        model = clf
        joblib.dump(model, MODEL_PATH)
    
    print("[SUCCESS] Model bootstrapped and saved to disk.")

# ======================================================
# FEEDBACK LOOP
# ======================================================
def force_learn_request(features):
    """Manually teaches the model that this specific request is SAFE."""
    global model
    vector=feature_vector(features)
    
    with lock:
        baseline_buffer.append(vector)
        snapshot = baseline_buffer.copy()
        
    print("[INFO] Feedback received. Forcing retraining...")
    
    # Run training in background so we don't freeze the server
    threading.Thread(
        target=train_model_async,
        args=(snapshot,),
        daemon=True
    ).start()
    
    return True

# ======================================================
#  MAIN DETECTION LOGIC
# ======================================================
def detect_anomaly(features):
    global model
    vector = feature_vector(features)
    if model is None:
        if os.path.exists(MODEL_PATH):
            with lock:
                try:
                    if model is None:
                        model =    joblib.load(MODEL_PATH)
                except:
                    bootstrap_model_if_needed()
        else:
            bootstrap_model_if_needed()
            
            
            with lock:
                model =    joblib.load(MODEL_PATH)

    is_anomaly= False
    anomaly_score = 0.0
    should_train = False

    with lock:
        if model is None:
            baseline_buffer.append(vector)
            if len(baseline_buffer)>=BUFFER_SIZE:
                snapshot = baseline_buffer.copy()
                should_train = True
        else:
            X = np.array([vector])
            prediction = model.predict(X)[0]
            score = model.decision_function(X)[0]
            is_anomaly = prediction == -1
            anomaly_score = abs(score)
            if prediction == 1:
                baseline_buffer.append(vector)
                MAX_BUFFER_SIZE = 5000 
                if len(baseline_buffer) > MAX_BUFFER_SIZE:
                    baseline_buffer.pop(0)
                if len(baseline_buffer) % RETRAIN_INTERVAL == 0:
                    snapshot = baseline_buffer.copy()
                    should_train = True

 
    if should_train:
        threading.Thread(target=train_model_async, args=(snapshot,), daemon=True).start()

   
    if model is None:
        return False, 0.0

    return is_anomaly, anomaly_score