import requests
import time
import random
import string
import statistics
import urllib3

# ==========================================
# CONFIGURATION
# ==========================================
TARGET_URL = "https://127.0.0.1:5000/detect"
HEADERS = {"Content-Type": "application/json"}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
results = {
    "passed": 0,
    "failed": 0,
    "latencies": []
}
def log(message, color=RESET):
    print(f"{color}{message}{RESET}")

def send_request(payload, expected_decision, description, sleep_time=1.0, custom_headers=None):
    """
    Helper function to send a request and validate the outcome.
    """
    time.sleep(sleep_time)
    
    start_time = time.time()
    try:
        req_headers = custom_headers if custom_headers else HEADERS
       
        response = requests.post(
            TARGET_URL, 
            json={"msg": payload}, 
            headers=req_headers,
            timeout=5,
            verify=False 
        )
        latency = (time.time() - start_time) * 1000 # to ms
        results["latencies"].append(latency)
        
        data = response.json()
        decision = data.get("decision", "UNKNOWN")
        score = data.get("risk_score", 0.0)

        
        status_icon = "?"
        is_pass = False
        
        if expected_decision == "ALLOW" and decision == "ALLOW":
            status_icon = "✅"
            is_pass = True
        elif expected_decision == "BLOCK" and decision == "BLOCK":
            status_icon = "🛡️" # Shield for successful block
            is_pass = True
        else:
            status_icon = "❌"
            is_pass = False

        if is_pass:
            results["passed"] += 1
            log(f"{status_icon} [PASS] {description} | Score: {score:.2f} | {latency:.0f}ms", GREEN)
        else:
            results["failed"] += 1
            log(f"{status_icon} [FAIL] {description} | Expected: {expected_decision} | Got: {decision} (Score: {score:.2f})", RED)

    except Exception as e:
        results["failed"] += 1
        log(f" [ERROR] Request failed: {e}", YELLOW)

# ==========================================
# SECTION 4.1: BASELINE TRAFFIC SCENARIOS
# ==========================================
def test_baseline_traffic():
    log("\n--- 4.1 Testing Baseline Traffic (Legitimate) ---", CYAN)
    
    legit_payloads = [
        ("user=john_doe&action=login", "Simple Login"),
        ("search_query=nike+shoes&sort=price_asc", "Search Query"),
        ("product_id=5521&action=add_to_cart", "Add to Cart"),
        ("page=about_us", "Static Page Access"),
        ("category=electronics&filter=onsale", "Category Filter")
    ]

    for payload, desc in legit_payloads:
        send_request(payload, "ALLOW", desc, sleep_time=1.0)

def test_complex_legit_strings():
    log("\n--- 4.1 Testing Complex Legitimate Strings ---", CYAN)
    # These contain special chars but are NOT attacks
    complex_payloads = [
        ("email=user+test@gmail.com&newsletter=yes", "Email with + symbol"),
        ("comment=I%20love%20C++%20and%20C#", "Comment with encoded chars"),
        ("math_query=2+2=4", "Math equation (often False Positive)")
    ]
    for payload, desc in complex_payloads:
        send_request(payload, "ALLOW", desc, sleep_time=1.5)

# ==========================================
# SECTION 4.3: ZERO-DAY & ATTACK SCENARIOS
# ==========================================
def test_attack_scenarios():
    log("\n--- 4.3 Testing Known & Zero-Day Attacks ---", CYAN)
    
    attacks = [
        ("UNION SELECT * FROM users", "SQL Injection (Classic)"),
        ("<script>alert('XSS')</script>", "XSS Script Tag"),
        ("../../../etc/passwd", "Path Traversal"),
        ("eval(base64_decode('...'))", "PHP Code Injection"), 
        ("%3Cscript%3E", "Obfuscated XSS (URL Encoded)") # Zero-Day style bypass attempt
    ]

    for payload, desc in attacks:
        send_request(payload, "BLOCK", desc, sleep_time=1.0)

def test_fuzzing_anomaly():
    log("\n--- 4.3 Testing Fuzzing (Junk Data) ---", CYAN)
    # Generate 1000 random characters
    junk_data = ''.join(random.choices(string.ascii_letters + string.digits, k=1000))
    send_request(junk_data, "BLOCK", "Massive Random String (Fuzzing)", sleep_time=1.0)

# ==========================================
# SECTION 4.4: API ABUSE & BOT SCENARIOS
# ==========================================
def test_bot_behavior():
    log("\n--- 4.4 Testing Behavioral Attacks (Burst) ---", CYAN)
    log("Sending 70 requests rapidly (Burst/DoS Simulation)...", YELLOW)
   
    burst_count = 0
    for i in range(70):
        try:
           
            requests.post(TARGET_URL, json={"msg": "user=bot&action=scrape"}, timeout=1, verify=False)
            burst_count += 1
            print(".", end="", flush=True)
        except:
            pass
    print(" Done.")
    
    # The NEXT request should be blocked due to high rate
    send_request("user=normal", "BLOCK", "Check if Rate Limiting triggered", sleep_time=0.1)

def test_bad_headers():
    log("\n--- 4.4 Testing Bad User Agents ---", CYAN)
    custom_headers = {
        "Content-Type": "application/json",
        "User-Agent": "sqlmap/1.4.7" # Known hacker tool
    }
    # Note: Your backend needs to check User-Agent for this to pass. 
    # If ML only checks body, this might fail (ALLOW).
    send_request("user=test", "BLOCK", "Malicious User-Agent Header", custom_headers=custom_headers)

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    log(" STARTING MASTER TEST SUITE", CYAN)
    log(f"Target: {TARGET_URL}\n", CYAN)

    # 1. Baseline
    test_baseline_traffic()
    
    # Cool down to prevent handover effect
    log("\n  Cooling down for 3 seconds...", YELLOW)
    time.sleep(3)

    # 2. Complex Legit
    test_complex_legit_strings()

    # 3. Attacks
    test_attack_scenarios()
    
    # 4. Anomalies
    test_fuzzing_anomaly()

    # 5. Bots
    test_bot_behavior()

    # ==========================================
    # SECTION 5.1: EVALUATION & SCORING
    # ==========================================
    log("\n" + "="*40, CYAN)
    log(" FINAL EVALUATION REPORT", CYAN)
    log("="*40, CYAN)
    
    total = results["passed"] + results["failed"]
    avg_latency = statistics.mean(results["latencies"]) if results["latencies"] else 0
    
    log(f"Total Tests Run: {total}")
    log(f"Passed: {results['passed']}", GREEN)
    log(f"Failed: {results['failed']}", RED)
    log(f"Avg Latency: {avg_latency:.2f}ms", YELLOW)

    if results["failed"] == 0:
        log("\n RESULT: EXCELLENT. System passed all gates.", GREEN)
    else:
        log("\n RESULT: ATTENTION REQUIRED. Check failed scenarios.", RED)