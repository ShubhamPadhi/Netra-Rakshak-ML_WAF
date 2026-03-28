import requests
import time
import random
import string
import urllib3

# Suppress "InsecureRequestWarning" since we are testing localhost with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CHANGED: Switched to HTTPS
URL = "https://localhost:5000/detect"
RESET_URL = "https://localhost:5000/reset_stats" # <--- New Endpoint for resetting

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def send_request(name, data, expected_decision):
    try:
        start = time.time()
        response = requests.post(URL, json={"msg": data}, timeout=2, verify=False)
        elapsed = (time.time() - start) * 1000
        try:
            result = response.json()
        except ValueError:
            print(f"[{name}] ERROR: Backend returned invalid JSON. Check app.py.")
            return None

        decision = result.get("decision", "UNKNOWN")
        score = result.get("risk_score", 0)
        
        status = "PASS" if decision == expected_decision else "❌ FAIL"
        print(f"[{name}] {status} | Decision: {decision} | Score: {score:.2f} | Time: {elapsed:.0f}ms")
        return result
    except Exception as e:
        print(f"[{name}] Connection Error: {e}")

# ==========================================
# PHASE 1: TRAINING (Normal Traffic)
# ==========================================
print("\n PHASE 1: Training ML Model (50 Requests) ---")
print("Sending diversified normal traffic so the model learns the baseline...")
normal_templates = [
    "user=admin", "user=alice", "user=bob", "user=test_user",
    "action=login", "action=logout", "action=register", "action=update",
    "page=home", "page=about", "page=contact", "page=dashboard", "page=profile",
    "search=products", "search=shoes", "search=laptops", "search=books",
    "category=electronics", "category=clothing", "category=kitchen",
    "view=list", "view=grid", "sort=price_asc", "sort=newest",
    "session_id=12345", "token=abcde12345", "lang=en-US", "theme=dark"
]
for i in range(50):
    base = random.choice(normal_templates)
    if "id" in base or "token" in base:
        payload = base.split("=")[0] + "=" + str(random.randint(1000, 99999))
    else:
        payload = base
    send_request(f"Train-{i+1}", payload, "ALLOW")
    time.sleep(0.3)

# ==========================================
# PHASE 2: STATIC RULES (Known Attacks)
# ==========================================
print("\nPHASE 2: Testing Static Rules ---")
send_request("SQL Injection", "user=admin' OR 1=1 --", "BLOCK")
send_request("XSS Attack", "<script>alert(1)</script>", "BLOCK")
# Test 3: Bad Method on Login
# Note: In a real curl this would be a GET request, but here we simulate the payload trigger
# For this specific rule to fire in your app.py, the endpoint needs to match. 
# Our test script sends to /detect, so we rely on the payload rules here.

# ==========================================
# PHASE 3: ML ANOMALIES (Unknown Attacks)
# ==========================================
print("\nPHASE 3: Testing ML Anomalies ---")
high_entropy_payload = generate_random_string(200) 
send_request("High Entropy", high_entropy_payload, "BLOCK")
massive_payload = "A" * 6000
send_request("Large Payload", massive_payload, "BLOCK")

print("\n--- Training & Basic Tests Complete. Check dashboard at https://localhost:5000 ---")

# ==========================================
# 🛑 AUTOMATIC RESET (Prepare for test.py)
# ==========================================
print("\n🧹 Resetting Rate Limit counters on Backend to prepare for test.py...")
try:
    # This calls the reset endpoint we added to app.py
    requests.post(RESET_URL, verify=False, timeout=2)
    print("✅ Backend Reset Successful! You can run test.py IMMEDIATELY.")
except Exception as e:
    print(f"⚠️ Failed to reset backend: {e}")