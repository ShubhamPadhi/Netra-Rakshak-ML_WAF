import streamlit as st
import pandas as pd
import requests
import time
import plotly.express as px
import urllib3  # <--- NEW: Required to suppress SSL warnings
from streamlit_option_menu import option_menu
from streamlit_lottie import st_lottie
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(
    page_title="🛡️ ML-WAF Live Monitor",
    page_icon="🛡️",
    layout="wide"
)

# ==============================
# HELPER: Load Lottie Animations (FIXED)
# ==============================
@st.cache_data
def load_lottieurl(url: str):
    try:
        # Note: External URLs (lottiefiles) should still use standard verification
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

# Load Assets
lottie_shield = load_lottieurl("https://lottie.host/4b684564-9980-4d8b-821f-0e83b4b606a5/1X75S6C6kI.json")
lottie_coding = load_lottieurl("https://assets5.lottiefiles.com/packages/lf20_fcfjwiyb.json")
lottie_alert = load_lottieurl("https://assets10.lottiefiles.com/packages/lf20_2xaF97.json")

# ==============================
#  CSS: Custom Animations & Anti-Blink
# ==============================
st.markdown("""
<style>
    /* ANTI-BLINK FIX: Hide the 'Running' status widget */
    div[data-testid="stStatusWidget"] {
        visibility: hidden;
    }

    /* Fade in animation for metrics */
    div[data-testid="stMetric"] {
        background-color: #1E1E1E;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #333;
        transition: transform 0.2s ease-in-out, box-shadow 0.2s;
        animation: fadeIn 0.5s;
    }
    
    div[data-testid="stMetric"]:hover {
        transform: translateY(-5px);
        box-shadow: 0 4px 15px rgba(255, 75, 75, 0.4);
    }

    @keyframes fadeIn {
        0% { opacity: 0; transform: translateY(10px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    
    .critical-status {
        animation: pulse-red 2s infinite;
        color: #FF4B4B !important;
        font-weight: bold;
    }
    
    @keyframes pulse-red {
        0% { transform: scale(1); text-shadow: 0 0 0 rgba(255, 75, 75, 0.7); }
        70% { transform: scale(1.05); text-shadow: 0 0 10px rgba(255, 75, 75, 0); }
        100% { transform: scale(1); text-shadow: 0 0 0 rgba(255, 75, 75, 0); }
    }
</style>
""", unsafe_allow_html=True)

# ==============================
# 1. Global Data Loading
# ==============================
 #BACKEND_URL = "https://127.0.0.1:5000"
BACKEND_URL = os.getenv("BACKEND_URL", "https://127.0.0.1:5000")
LOG_FILE = "../backend/logs.csv"
try:
    df = pd.read_csv(
        LOG_FILE, 
        names=["timestamp", "ip", "attack_type", "risk_score", "rule"],
        header=0
    )
    if df.empty:
        df = pd.DataFrame(columns=["timestamp", "ip", "attack_type", "risk_score", "rule"])

except FileNotFoundError:
    df = pd.DataFrame(columns=["timestamp", "ip", "attack_type", "risk_score", "rule"])

# Calculate Metrics
if not df.empty:
    total_events = len(df)
    attacks_df = df[df['attack_type'] != 'Normal Traffic']
    blocked_requests = len(attacks_df)
    
    if total_events > 0:
        anomaly_rate = (blocked_requests / total_events) * 100
    else:
        anomaly_rate = 0
else:
    total_events = 0
    blocked_requests = 0
    anomaly_rate = 0
    attacks_df = pd.DataFrame()

# ==============================
# 2. Sidebar - Modern Navigation
# ==============================
with st.sidebar:
    if lottie_shield:
        st_lottie(lottie_shield, height=150, key="shield_anim")
    
    page = option_menu(
        "WAF Control", 
        ["Live Monitor", "Analytics", "Log Inspector"], 
        icons=['activity', 'graph-up-arrow', 'search'], 
        menu_icon="shield-lock", 
        default_index=0,
        styles={
            "container": {"padding": "5!important", "background-color": "#0E1117"},
            "icon": {"color": "orange", "font-size": "20px"}, 
            "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#262730"},
            "nav-link-selected": {"background-color": "#FF4B4B"},
        }
    )
    
    st.divider()

    # ======================================================
    #  MOVED UP: WAF Configuration (Sensitivity)
    # ======================================================
    st.header("WAF Sensitivity")
    
    # 1. Fetch current threshold from Backend
    current_threshold = 0.30 # Default fallback
    try:
        resp = requests.get(f"{BACKEND_URL}/config", timeout=1, verify=False)
        if resp.status_code == 200:
            current_threshold = resp.json().get("threshold", 0.30)
    except:
        pass # Backend might be down, ignore

    # 2. Slider Control
    new_threshold = st.slider(
        "Blocking Threshold", 
        min_value=0.0, 
        max_value=1.0, 
        value=float(current_threshold),
        step=0.05,
        help="Lower = More Secure (Paranoid). Higher = More Relaxed."
    )

    # 3. Update if changed
    if new_threshold != current_threshold:
        try:
            requests.post(
                f"{BACKEND_URL}/config", 
                json={"threshold": new_threshold},
                timeout=1,
                verify=False
            )
            st.toast(f"✅ Threshold updated to {new_threshold}")
            time.sleep(0.5) # Prevent rapid-fire requests
            st.rerun() # Refresh to sync UI
        except Exception as e:
            st.error(f"Failed to update config: {e}")

    st.divider()

    # ======================================================
    #  Attack Simulator (Now Below Sensitivity)
    # ======================================================
    st.header("⚡ Attack Simulator")
    user_payload = st.text_area("Enter Payload", placeholder="<script>alert(1)</script>", height=100)

    if st.button("Fire Attack", use_container_width=True): 
        if user_payload.strip():
            try:
                res = requests.post(
                    f"{BACKEND_URL}/detect",
                    json={"msg": user_payload},
                    timeout=3,
                    verify=False
                ).json()

                if res.get("decision") == "BLOCK":
                    st.error(f"🚫 BLOCKED | Score: {res.get('risk_score', 0):.2f}")
                else:
                    st.success("✅ ALLOWED")
            except Exception as e:
                st.error(f"Backend error: {e}")

    st.divider()

    # ======================================================
    #  Feedback Loop (Now Below Simulator)
    # ======================================================
    st.header("Model Feedback Loop")
    st.caption("Reduce False Positives by teaching the AI.")
    
    false_positive_payload = st.text_area(
        "Paste Falsely Blocked Payload",
        placeholder="e.g., SELECT * FROM products WHERE id=1",
        height=100
    )
    
    if st.button("✅ Mark as Safe & Retrain", use_container_width=True):
        if false_positive_payload.strip():
            try:
                res = requests.post(
                    f"{BACKEND_URL}/feedback",
                    json={"msg": false_positive_payload},
                    timeout=5,
                    verify=False
                ).json()
                
                st.success(f"Feedback Sent! {res.get('message')}")
                time.sleep(1) # Visual pause
                st.rerun()
                
            except Exception as e:
                st.error(f"Error sending feedback: {e}")

    st.divider()
    auto_refresh = st.checkbox("Live Auto-Refresh", value=True)

# ==============================
# PAGE 1: Live Monitor
# ==============================
if page == "Live Monitor":
    col_t1, col_t2 = st.columns([0.8, 0.2])
    with col_t1:
        st.title("🛡️ ML-Powered Web Application Firewall")
    with col_t2:
        if lottie_coding:
            st_lottie(lottie_coding, height=80, key="server_anim")
    
    # --- Metrics Row ---
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Requests", total_events)
    with col2:
        st.metric("Blocked Attacks", blocked_requests)
    with col3:
        st.metric("Threat Rate", f"{anomaly_rate:.1f}%")
    with col4:
        status_text = "🔴 CRITICAL" if anomaly_rate > 20 and total_events > 10 else "🟢 STABLE"
        
        if "CRITICAL" in status_text:
            st.markdown(f'<p class="critical-status" style="font-size: 30px; margin:0;">{status_text}</p>', unsafe_allow_html=True)
            st.caption("System Status")
        else:
            st.metric("System Status", status_text)

    st.divider()

    # --- Charts & Logs ---
    c1, c2 = st.columns([2, 1])

    with c1:
        st.subheader("Recent Security Alerts")
        if not attacks_df.empty:
            display_df = attacks_df.tail(10).iloc[::-1]  
            st.dataframe(display_df, use_container_width=True)
        else:
            st.info("No active threats detected.")

    with c2:
        st.subheader("📊 Threat Distribution")
        if not attacks_df.empty:
            counts = attacks_df["attack_type"].value_counts().reset_index()
            counts.columns = ["Attack Type", "Count"]

            fig = px.pie(
                counts,
                values="Count",
                names="Attack Type",
                hole=0.4,
                color_discrete_sequence=px.colors.sequential.RdBu
            )
            fig.update_layout(height=300, margin=dict(l=20, r=20, t=20, b=20))
            st.plotly_chart(fig, use_container_width=True)
        else:
            if lottie_coding:
                st_lottie(lottie_coding, height=200, key="clean_anim")
            st.info("System Secure. No attacks to visualize.")

# ==============================
# PAGE 2: Analytics
# ==============================
elif page == "Analytics":
    st.title("📈 Attack Trends & Analytics")
    
    if not attacks_df.empty:
        try:
            attacks_df['dt'] = pd.to_datetime(attacks_df['timestamp'])
            
            st.subheader("Attack Volume Over Time")
            fig_line = px.line(attacks_df, x='dt', y='risk_score', color='attack_type', 
                               title="Risk Score Intensity per Attack", markers=True)
            st.plotly_chart(fig_line, use_container_width=True)

            c1, c2 = st.columns(2)
            with c1:
                st.subheader("Top Attacking IPs")
                st.bar_chart(attacks_df['ip'].value_counts())
            
            with c2:
                st.subheader("Risk Score Distribution")
                fig_hist = px.histogram(attacks_df, x="risk_score", nbins=20, title="Risk Score Frequency")
                st.plotly_chart(fig_hist, use_container_width=True)
                
        except Exception as e:
            st.warning(f"Could not render analytics: {e}")
    else:
        st.info("Not enough data to generate analytics yet.")

# ==============================
# PAGE 3: Log Inspector
# ==============================
elif page == "Log Inspector":
    st.title("🔍 Deep Log Inspection")
    
    if not df.empty:
        c1, c2 = st.columns(2)
        with c1:
            ip_filter = st.multiselect("Filter by IP", options=df['ip'].unique())
        with c2:
            type_filter = st.multiselect("Filter by Attack Type", options=df['attack_type'].unique())
        
        filtered_df = df.copy()
        if ip_filter:
            filtered_df = filtered_df[filtered_df['ip'].isin(ip_filter)]
        if type_filter:
            filtered_df = filtered_df[filtered_df['attack_type'].isin(type_filter)]
            
        st.dataframe(filtered_df.iloc[::-1], use_container_width=True, height=600)
        st.caption(f"Showing {len(filtered_df)} of {len(df)} total logs.")
    else:
        st.info("Log file is empty.")

# ==============================
# Auto Refresh
# ==============================
if auto_refresh:
    time.sleep(2)
    st.rerun()