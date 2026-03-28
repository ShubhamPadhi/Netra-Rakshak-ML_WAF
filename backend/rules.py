import urllib.parse 
def rule_check(features):
    """
    Rule-based detection for known web attacks
    Returns:
      (attack_detected: bool, reason: str)
    """

    payload_size = features.get("payload_size", 0)
    method = features.get("method", "")
    endpoint = features.get("endpoint", "")
    request_rate = features.get("request_rate", 0)
    
    # ORIGINAL RAW PAYLOAD
    payload = features.get("payload", "").lower()
    payload_entropy = features.get("payload_entropy", 0)

    try:
        decoded_payload = urllib.parse.unquote(payload)
    except:
        decoded_payload = payload

    # Rule 1: Abnormally large payload
    if payload_size > 5000:
        return True, "Abnormally large payload detected"

    # Rule 2: Invalid method usage on sensitive endpoint
    sensitive_endpoints = ["/login", "/admin", "/signin", "/auth"]
    if any(x in endpoint for x in sensitive_endpoints) and method != "POST":
       return True, "Invalid HTTP method used for sensitive endpoint"

    # Rule 3: High request rate (UPDATED THRESHOLD) I selected 60req/min as threshold,for fast training if you want you can change it back to 100
    if request_rate > 70:
        return True, "Possible bot or API abuse detected due to high request rate"

    # Rule 4: High-entropy payload
    if payload_entropy > 4.5:
        return True, "High-entropy payload detected (possible obfuscation)"

    # Rule 5: XSS keyword detection
    xss_keywords = ["<script>", "javascript:", "onerror=", "onload=", "alert("]
    for keyword in xss_keywords:
        if keyword in payload or keyword in decoded_payload:
            return True, "Possible XSS payload detected"

    # Rule 6: SQL injection keyword detection
    sql_keywords = [
        "union select", 
        "or 1=1", 
        "or '1'='1", 
        "or '1'=='1'",  
        "' or 1=1", 
        "--", 
        "';", 
        "select * from" 
    ]
    for keyword in sql_keywords:
        if keyword in payload or keyword in decoded_payload:
            return True, "Possible SQL injection detected"


    # Rule 7: Path Traversal Detection
    traversal_keywords=["../", "..\\", "/etc/passwd", "windows/win.ini", "..%2f"]
    for keyword in traversal_keywords:
        if keyword in payload or keyword in decoded_payload:
            return True, "Path Traversal attack detected"

    # Rule 8: PHP Code Injection
    php_keywords = ["eval(", "base64_decode(", "system(", "exec(", "shell_exec(", "<?php"]
    for keyword in php_keywords:
        if keyword in payload or keyword in decoded_payload:
            return True, "PHP Code Injection detected"
    return False, "No rule-based attack detected"