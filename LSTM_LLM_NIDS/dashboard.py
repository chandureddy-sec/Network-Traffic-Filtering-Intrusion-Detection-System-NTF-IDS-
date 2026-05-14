import streamlit as st
import time
import pandas as pd
import plotly.express as px
from collections import deque

# Import modules from our project
from lstm_model import NIDSModel
from packet_capture import start_live_capture, stop_capture, packet_queue, load_pcap
from utils import init_db, store_alert, get_recent_alerts
from llm_analyzer import analyze_suspicious_packet

import packet_capture
import os
import tempfile

def highlight_risk(val):
    if val == 'Low': return "background-color: rgba(35, 197, 82, 0.3)"
    elif val == 'Medium': return "background-color: rgba(245, 212, 66, 0.3)"
    elif val == 'High': return "background-color: rgba(248, 79, 49, 0.3)"
    return ""
st.set_page_config(page_title="AI Zero-Day NIDS", layout="wide", page_icon="🛡️")

# Custom UI Aesthetics
st.markdown("""
<style>
    .main { background-color: #0b0f19; color: #f0f4f8; }
    .stMetric { background: rgba(20,25,40,0.8); border: 1px solid #1f2937; padding: 10px; border-radius: 8px;}
</style>
""", unsafe_allow_html=True)

init_db()

# Initialize session state for persistent live monitoring
if 'nids_model' not in st.session_state:
    st.session_state.nids_model = NIDSModel()
if 'seq_buffer' not in st.session_state:
    st.session_state.seq_buffer = deque(maxlen=3)
if 'metrics' not in st.session_state:
    st.session_state.metrics = {"Normal": 0, "Suspicious": 0, "Malicious": 0}
if 'capture_active' not in st.session_state:
    st.session_state.capture_active = False
if 'live_logs' not in st.session_state:
    st.session_state.live_logs = deque(maxlen=500)
if 'all_logs' not in st.session_state:
    st.session_state.all_logs = []

# Sidebar Configuration
with st.sidebar:
    st.image("https://img.icons8.com/nolan/256/lock.png", width=120)
    st.title("Admin Console")
    
    st.markdown("### 🔑 Secure Gemini AI Core")
    api_key = st.text_input("Enter Gemini API Key (Optional):", type="password")
    
    st.markdown("---")
    st.markdown("### 📡 Sensor Controls")
    source = st.selectbox("Capture Target", ["Live Interface Default", "Upload PCAP"])
    
    uploaded_file = None
    if source == "Upload PCAP":
        uploaded_file = st.file_uploader("Upload .pcap file securely", type=["pcap", "pcapng"])
    
    col1, col2 = st.columns(2)
    if not st.session_state.capture_active:
        if col1.button("▶ START", use_container_width=True):
            if source == "Upload PCAP" and uploaded_file is None:
                st.error("Please upload a .pcap file before hitting start.")
            else:
                st.session_state.capture_active = True
                st.session_state.live_logs.clear()
                st.session_state.all_logs.clear()
                st.session_state.metrics = {"Normal": 0, "Suspicious": 0, "Malicious": 0}
                
                if source == "Upload PCAP":
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                        tmp.write(uploaded_file.getbuffer())
                        tmp_path = tmp.name
                        
                    success, msg = load_pcap(tmp_path)
                    os.remove(tmp_path)
                    
                    if not success:
                        st.error(f"Failed to load PCAP: {msg}")
                        st.session_state.capture_active = False
                else:
                    start_live_capture()
            st.rerun()
    else:
        if col2.button("⏹ STOP", type="primary", use_container_width=True):
            st.session_state.capture_active = False
            stop_capture()
            st.rerun()

st.title("🛡️ AI-Driven Zero-Day Time Series Analysis")
st.markdown("Combines deep learning (LSTM) temporal detection with GenAI heuristic explanations.")
st.markdown("---")

# Metrics Top Row
m1, m2, m3, m4 = st.columns(4)
met_total = m1.empty()
met_norm = m2.empty()
met_susp = m3.empty()
met_mali = m4.empty()

col_charts, col_logs = st.columns([1, 2])
chart_placeholder = col_charts.empty()
log_placeholder = col_logs.empty()

# Real-Time Processing Loop (Tied to Streamlit App LifeCycle)
if st.session_state.capture_active:
    st.caption("🔴 Live Sensor Active... Capturing Traffic.")
    BATCH_SIZE = 15  # Process up to 15 packets per GUI cycle
    
    while st.session_state.capture_active:
        processed_count = 0
        
        # Process from the queue
        while len(packet_queue) > 0 and processed_count < BATCH_SIZE:
            packet_info, vector = packet_queue.popleft()
            processed_count += 1
            
            # 1. Build Time Series Sequence
            st.session_state.seq_buffer.append(vector)
            
            # 2. LSTM Evaluates Sequence
            score, is_threat = st.session_state.nids_model.evaluate_anomaly(st.session_state.seq_buffer, threshold=0.7)
            
            # 3. Decision Logic & 4. LLM Gemini Integration
            classification = "Normal"
            risk = "Low"
            prob = f"{int(score*100)}%"
            reason = "Packet features cluster closely with legitimate traffic baselines."
    
            if is_threat:
                # Note: st.spinner inside a fast while loop might clash, but we keep it
                llm_verdict = analyze_suspicious_packet(packet_info, api_key)
                classification = llm_verdict.get("classification", "Suspicious")
                risk = llm_verdict.get("risk_level", "High")
                prob = llm_verdict.get("threat_probability", prob)
                reason = llm_verdict.get("reason", "Anomaly confirmed by secondary heuristic scan.")
                
                # Update Metrics appropriately
                if "Malicious" in classification:
                    st.session_state.metrics["Malicious"] += 1
                else:
                    st.session_state.metrics["Suspicious"] += 1
                
                store_alert(packet_info["packet_id"], classification, risk, prob, reason)
            else:
                if score > 0.35:
                    classification = "Suspicious"
                    risk = "Medium"
                    st.session_state.metrics["Suspicious"] += 1
                    reason = "Minor deviations from standard behavior detected."
                else:
                    st.session_state.metrics["Normal"] += 1
    
            # Append to live logs
            log_entry = {
                "Timestamp": time.strftime("%H:%M:%S"),
                "Packet ID": packet_info['packet_id'],
                "Classification": classification,
                "Risk Level": risk,
                "Prob.": prob,
                "Reason": reason
            }
            st.session_state.live_logs.append(log_entry)
            st.session_state.all_logs.append(log_entry)
    
        # End of batch: Update Visuals securely via placeholders
        total_pkts = sum(st.session_state.metrics.values())
        met_total.metric("Total Scanned", f"{total_pkts}")
        met_norm.metric("✅ Legitimate", st.session_state.metrics["Normal"])
        met_susp.metric("⚠️ Suspicious", st.session_state.metrics["Suspicious"])
        met_mali.metric("🚨 Malicious", st.session_state.metrics["Malicious"])
        
        # Dynamic Pie Chart
        if total_pkts > 0:
            df_pie = pd.DataFrame(list(st.session_state.metrics.items()), columns=["Type", "Count"])
            fig = px.pie(df_pie, values="Count", names="Type", hole=0.7, 
                         color="Type", color_discrete_map={"Normal":"#23c552", "Suspicious":"#f5d442", "Malicious":"#f84f31"})
            fig.update_layout(template="plotly_dark", height=320, margin=dict(t=0,b=0,l=0,r=0))
            chart_placeholder.plotly_chart(fig, use_container_width=True)
            
        # Render purely from live_logs to stay fast (caps at 500 automatically!)
        if len(st.session_state.live_logs) > 0:
            log_list = list(st.session_state.live_logs)[::-1]
            df = pd.DataFrame(log_list)
            styled_df = df.style.map(highlight_risk, subset=["Risk Level"])
            log_placeholder.dataframe(styled_df, use_container_width=True, height=320)
        else:
            log_placeholder.info("Awaiting network packets...")
    
        # Significant delay prevents UI flickering
        time.sleep(1)
else:
    # Final Visual State Output when stopped
    st.info("System is offline. Click Start in the admin panel to initiate sensor.")
    
    total_pkts = sum(st.session_state.metrics.values())
    met_total.metric("Total Scanned", f"{total_pkts}")
    met_norm.metric("✅ Legitimate", st.session_state.metrics["Normal"])
    met_susp.metric("⚠️ Suspicious", st.session_state.metrics["Suspicious"])
    met_mali.metric("🚨 Malicious", st.session_state.metrics["Malicious"])
    
    if total_pkts > 0:
        df_pie = pd.DataFrame(list(st.session_state.metrics.items()), columns=["Type", "Count"])
        fig = px.pie(df_pie, values="Count", names="Type", hole=0.7, 
                     color="Type", color_discrete_map={"Normal":"#23c552", "Suspicious":"#f5d442", "Malicious":"#f84f31"})
        fig.update_layout(template="plotly_dark", height=350, margin=dict(t=0,b=0,l=0,r=0))
        chart_placeholder.plotly_chart(fig, use_container_width=True)
        
    if len(st.session_state.all_logs) > 0:
        st.subheader("Persistent Deep-Scan Intelligence Logs (Final Report)")
        df_all = pd.DataFrame(st.session_state.all_logs)
        st.dataframe(df_all.style.map(highlight_risk, subset=["Risk Level"]), use_container_width=True)
        
        st.markdown("### 📊 Final Category Breakdown")
        sum1, sum2, sum3 = st.columns(3)
        sum1.success(f"✅ **Normal Legitimate Traffic:** {st.session_state.metrics['Normal']}")
        sum2.warning(f"⚠️ **Suspicious Anomalies:** {st.session_state.metrics['Suspicious']}")
        sum3.error(f"🚨 **Malicious Signatures:** {st.session_state.metrics['Malicious']}")
        
        # Download final report (no truncation limit)
        csv = df_all.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download Full Threat Report", data=csv, file_name="nids_final_report.csv", mime="text/csv")
