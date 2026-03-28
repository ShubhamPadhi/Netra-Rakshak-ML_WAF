from datetime import datetime
import math

def payload_entropy(payload):
    if not payload:
        return 0
    freq= {}
    for c in payload:
        freq[c]= freq.get(c, 0) + 1
    entropy = 0
    for count in freq.values():
        p=count / len(payload)
        entropy -=p * math.log2(p)
    return entropy
def extract_features(request, request_rate=1):
    payload=request.get_data(as_text=True) or ""

    features={}
    features["payload"]=payload
    features["method"]=request.method
    features["endpoint"]=request.path
    features["payload_size"]= len(payload)
    features["payload_entropy"]=payload_entropy(payload)
    features["ip"]=request.remote_addr
    features["user_agent_length"]=len(
        request.headers.get("User-Agent", "")
    )
    features["timestamp"]=datetime.utcnow().timestamp()

    features["request_rate"]=request_rate

    return features
