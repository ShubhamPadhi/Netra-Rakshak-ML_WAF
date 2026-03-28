#!/bin/bash

# 1. Start the Flask Backend in the background (&)
# We run from root, so the path is backend/app.py
echo "Starting ML-based WAF Backend..."
python backend/app.py &

# 2. Wait 5 seconds to ensure Backend is ready
sleep 5

# 3. Start the Streamlit Dashboard in the foreground
echo "Starting Dashboard..."
streamlit run dashboard/dashboard.py --server.port=8501 --server.address=0.0.0.0