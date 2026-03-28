import time
from collections import defaultdict


ALPHA = 0.3         
THRESHOLD = 0.6      
RESET_TIME = 60      

class EWMADetector:
    def __init__(self):
        
        self.ip_states = defaultdict(lambda: {'score': 0.0, 'last_update': time.time()})

    def update(self, ip, anomaly_strength):
        current_time = time.time()
        state = self.ip_states[ip]

       
        if current_time - state['last_update'] > RESET_TIME:
            state['score'] = 0.0

       
        state['score'] = (ALPHA * anomaly_strength) + ((1 - ALPHA) * state['score'])
        state['last_update'] = current_time

        return state['score']


ewma_engine = EWMADetector() 