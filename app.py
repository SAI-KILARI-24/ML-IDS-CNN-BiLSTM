import os
import sys
import time
import json
import torch
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
import streamlit as st

# Configure System Path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import config
from preprocessing.pcap_processor import PCAPProcessor
from preprocessing.payload_processor import PayloadProcessor
from preprocessing.create_samples import generate_sample_pcap
from models.cnn_bilstm import CNNBiLSTM_IDS
from explainability.shap_explainer import PyTorchIDSShapExplainer
from dashboard.styles import get_custom_css
from dashboard.components import SOCDashboardComponents

# Streamlit Page Setup
st.set_page_config(
    page_title="SOC Intrusion Detection Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Custom Enterprise Dark Theme CSS
st.markdown(get_custom_css(), unsafe_allow_html=True)


# Initialize Session State
if "system_logs" not in st.session_state:
    st.session_state.system_logs = ["[INFO] SOC Intrusion Detection Console initialized."]
if "pcap_file_info" not in st.session_state:
    st.session_state.pcap_file_info = None
if "extracted_packets" not in st.session_state:
    st.session_state.extracted_packets = []
if "detection_results" not in st.session_state:
    st.session_state.detection_results = []
if "is_analyzed" not in st.session_state:
    st.session_state.is_analyzed = False


def log_event(msg: str, level: str = "INFO"):
    timestamp = time.strftime("%H:%M:%S")
    formatted = f"[{timestamp}] [{level}] {msg}"
    st.session_state.system_logs.append(formatted)


@st.cache_resource
def load_pytorch_ids_model():
    """Loads trained PyTorch CNN-BiLSTM model checkpoint and label encoder."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    if not config.SAVED_MODEL_PATH.exists():
        return None, None, f"Model checkpoint missing at {config.SAVED_MODEL_PATH}"

    try:
        checkpoint = torch.load(config.SAVED_MODEL_PATH, map_location=device)
        classes = checkpoint.get("classes", config.CIC_IOT_CLASSES)
        num_classes = len(classes)

        model = CNNBiLSTM_IDS(
            input_size=config.PAYLOAD_SIZE,
            num_classes=num_classes,
            cnn_filters=config.CNN_FILTERS,
            cnn_kernel_size=config.CNN_KERNEL_SIZE,
            lstm_hidden_size=config.LSTM_HIDDEN_SIZE,
            lstm_num_layers=config.LSTM_NUM_LAYERS,
            dropout_rate=config.DROPOUT_RATE
        ).to(device)

        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()

        return model, classes, "Model loaded successfully."
    except Exception as e:
        return None, None, f"Error loading PyTorch model: {str(e)}"


# Load Model
model, class_labels, model_msg = load_pytorch_ids_model()
model_loaded = model is not None


# Sidebar Navigation
st.sidebar.markdown("### 🛡️ SOC NAVIGATION")
nav_option = st.sidebar.radio(
    "Select Console View:",
    [
        "OVERVIEW",
        "PCAP ANALYSIS",
        "DETECTION MONITOR (REPLAY)",
        "ATTACK ANALYSIS",
        "MODEL PERFORMANCE",
        "EXPLAINABILITY (SHAP)",
        "SYSTEM LOGS"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚙️ SYSTEM METADATA")
st.sidebar.markdown(f"**Framework:** PyTorch {torch.__version__}")
st.sidebar.markdown(f"**Model:** 1D-CNN + BiLSTM")
st.sidebar.markdown(f"**Payload Size:** {config.PAYLOAD_SIZE} Bytes")
st.sidebar.markdown(f"**Dataset:** CICIoT2023")

if st.sidebar.button("Generate Sample PCAP"):
    sample_path = generate_sample_pcap()
    log_event(f"Generated sample PCAP file at {sample_path}", "INFO")
    st.sidebar.success(f"Sample created: {Path(sample_path).name}")


# Render Header
SOCDashboardComponents.render_header(
    model_loaded=model_loaded,
    pcap_loaded=st.session_state.is_analyzed
)


# Calculate Current Overview Stats
if st.session_state.is_analyzed and st.session_state.detection_results:
    total_pkts = len(st.session_state.detection_results)
    attacks = sum(1 for d in st.session_state.detection_results if "Benign" not in d["pred_label"])
    benign = total_pkts - attacks
    avg_conf = float(np.mean([d["confidence"] for d in st.session_state.detection_results]))
    status_str = "THREAT DETECTED" if attacks > 0 else "NORMAL TRAFFIC"
    overview_stats = {
        "status": status_str,
        "total_packets": total_pkts,
        "attacks_detected": attacks,
        "benign_traffic": benign,
        "avg_confidence": avg_conf
    }
else:
    overview_stats = {
        "status": "SYSTEM READY",
        "total_packets": "N/A",
        "attacks_detected": 0,
        "benign_traffic": "N/A",
        "avg_confidence": None
    }


# ==============================================================================
# SECTION 1: OVERVIEW
# ==============================================================================
if nav_option == "OVERVIEW":
    st.markdown("### 📊 SYSTEM EXECUTIVE OVERVIEW")
    SOCDashboardComponents.render_overview_kpis(overview_stats)

    st.markdown("---")
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("<div class='soc-panel'>", unsafe_allow_html=True)
        st.markdown("<div class='soc-panel-title'>Model & Pipeline Engine Status</div>", unsafe_allow_html=True)
        st.write(f"**Model Checkpoint:** `{config.SAVED_MODEL_PATH.name}` ({'Available' if model_loaded else 'Not Found'})")
        st.write(f"**Payload Normalization:** 0 to 255 -> 0.0 to 1.0 (Fixed {config.PAYLOAD_SIZE} Bytes)")
        st.write(f"**Target Classes ({len(config.CIC_IOT_CLASSES)}):** {', '.join(config.CIC_IOT_CLASSES)}")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_right:
        st.markdown("<div class='soc-panel'>", unsafe_allow_html=True)
        st.markdown("<div class='soc-panel-title'>Recent Activity Log</div>", unsafe_allow_html=True)
        log_box = "<br>".join(st.session_state.system_logs[-5:])
        st.markdown(f"<div class='soc-log-box'>{log_box}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# SECTION 2: PCAP ANALYSIS
# ==============================================================================
elif nav_option == "PCAP ANALYSIS":
    st.markdown("### 📁 PCAP INGESTION & TRAFFIC PARSING")

    uploaded_file = st.file_uploader("Upload Network Traffic Capture (.pcap, .pcapng)", type=["pcap", "pcapng", "cap"])
    
    use_sample = st.checkbox("Or use pre-generated sample traffic PCAP")

    target_pcap_path = None
    if uploaded_file is not None:
        save_path = config.SAMPLE_PCAP_DIR / uploaded_file.name
        with open(save_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        target_pcap_path = str(save_path)
    elif use_sample:
        target_pcap_path = str(config.SAMPLE_PCAP_DIR / "sample_traffic.pcap")
        if not Path(target_pcap_path).exists():
            generate_sample_pcap(target_pcap_path)

    if target_pcap_path:
        processor = PCAPProcessor()
        valid, msg = processor.validate_pcap(target_pcap_path)

        if not valid:
            st.error(f"Validation Error: {msg}")
        else:
            st.success(f"PCAP File Validated: {Path(target_pcap_path).name}")
            
            if st.button("🚀 Analyze Traffic Packets", type="primary"):
                with st.spinner("Extracting Scapy packets & running PyTorch CNN-BiLSTM inference..."):
                    res = processor.process_pcap(target_pcap_path)
                    
                    if res["success"]:
                        st.session_state.pcap_file_info = res["file_info"]
                        st.session_state.extracted_packets = res["packets"]
                        
                        # Preprocess & Run PyTorch Inference
                        payload_proc = PayloadProcessor(target_len=config.PAYLOAD_SIZE)
                        detections = []

                        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                        for pkt in res["packets"]:
                            raw_payload = pkt["payload_bytes"]
                            norm_payload = payload_proc.preprocess_payload(raw_payload)

                            x_t = torch.tensor(norm_payload, dtype=torch.float32).unsqueeze(0).to(device)
                            with torch.no_grad():
                                logits = model(x_t)
                                probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
                                pred_idx = int(np.argmax(probs))
                                pred_label = class_labels[pred_idx] if class_labels else f"Class_{pred_idx}"

                            # Heuristic Ground Truth from payload string if available for benchmarking
                            gt = "N/A"
                            payload_str = str(raw_payload)
                            for c in config.CIC_IOT_CLASSES:
                                if c in payload_str:
                                    gt = c
                                    break
                            if gt == "N/A" and "GET /" in payload_str:
                                gt = "BenignTraffic"

                            detections.append({
                                "packet_id": pkt["packet_id"],
                                "timestamp_str": time.strftime("%H:%M:%S", time.localtime(pkt["timestamp"])),
                                "src_ip": pkt["src_ip"],
                                "dst_ip": pkt["dst_ip"],
                                "protocol": pkt["protocol"],
                                "ground_truth": gt,
                                "pred_label": pred_label,
                                "confidence": float(probs[pred_idx]),
                                "raw_payload": raw_payload,
                                "norm_payload": norm_payload
                            })

                        st.session_state.detection_results = detections
                        st.session_state.is_analyzed = True
                        log_event(f"Successfully analyzed {len(detections)} packets from {Path(target_pcap_path).name}", "SUCCESS")
                        st.rerun()

    if st.session_state.pcap_file_info:
        st.markdown("<div class='soc-panel'>", unsafe_allow_html=True)
        st.markdown("<div class='soc-panel-title'>Loaded PCAP Summary</div>", unsafe_allow_html=True)
        info = st.session_state.pcap_file_info
        st.write(f"**File Name:** `{info['file_name']}` | **Size:** {info['file_size_mb']} MB")
        st.write(f"**Total Packets:** {info['total_packets']} | **Packets with Payload:** {info['packets_with_payload']}")
        st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# SECTION 3: DETECTION MONITOR (PCAP REPLAY)
# ==============================================================================
elif nav_option == "DETECTION MONITOR (REPLAY)":
    st.markdown("### 📡 LIVE DETECTION FEED & PCAP REPLAY")

    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        run_replay = st.button("▶️ Trigger PCAP Replay Simulation")

    if run_replay and st.session_state.detection_results:
        st.info("Simulating real-time packet ingestion feed...")
        placeholder = st.empty()
        
        sim_results = []
        for i, pkt in enumerate(st.session_state.detection_results):
            sim_results.append(pkt)
            with placeholder.container():
                st.write(f"**Simulated Ingestion Stream (Packet {i+1}/{len(st.session_state.detection_results)})...**")
                SOCDashboardComponents.render_detection_table(sim_results)
            time.sleep(0.05)
        st.success("PCAP Replay completed.")
    else:
        SOCDashboardComponents.render_detection_table(st.session_state.detection_results)


# ==============================================================================
# SECTION 4: ATTACK ANALYSIS
# ==============================================================================
elif nav_option == "ATTACK ANALYSIS":
    st.markdown("### 📈 THREAT CATEGORY & ATTACK ANALYTICS")

    if not st.session_state.detection_results:
        st.info("No active detection results available. Upload and analyze a PCAP file first.")
    else:
        counts = {}
        for d in st.session_state.detection_results:
            label = d["pred_label"]
            counts[label] = counts.get(label, 0) + 1

        df_counts = pd.DataFrame(list(counts.items()), columns=["Attack Class", "Count"])

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("<div class='soc-panel'>", unsafe_allow_html=True)
            st.markdown("<div class='soc-panel-title'>Attack Distribution Chart</div>", unsafe_allow_html=True)
            st.bar_chart(df_counts.set_index("Attack Class"))
            st.markdown("</div>", unsafe_allow_html=True)

        with col2:
            st.markdown("<div class='soc-panel'>", unsafe_allow_html=True)
            st.markdown("<div class='soc-panel-title'>Threat Breakdown Table</div>", unsafe_allow_html=True)
            st.dataframe(df_counts, use_container_width=True, hide_index=True)
            st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# SECTION 5: MODEL PERFORMANCE
# ==============================================================================
elif nav_option == "MODEL PERFORMANCE":
    st.markdown("### 🏆 MODEL EVALUATION & BENCHMARK METRICS")

    if not config.METRICS_REPORT_PATH.exists():
        st.warning("Evaluation report JSON missing. Run `training/evaluate.py` to generate metrics.")
    else:
        with open(config.METRICS_REPORT_PATH, "r") as f:
            metrics = json.load(f)

        multi = metrics["multiclass"]
        binary = metrics["binary"]

        st.markdown("#### 1. Multiclass Evaluation (8 CICIoT2023 Classes)")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Multiclass Accuracy", f"{multi['accuracy'] * 100:.2f}%")
        c2.metric("Precision (Macro)", f"{multi['precision_macro']:.4f}")
        c3.metric("Recall (Macro)", f"{multi['recall_macro']:.4f}")
        c4.metric("F1-Score (Macro)", f"{multi['f1_macro']:.4f}")

        SOCDashboardComponents.render_confusion_matrix_plot(multi["confusion_matrix"], multi["classes"])

        st.markdown("---")
        st.markdown("#### 2. Binary Evaluation (Benign vs Attack)")
        b1, b2, b3, b4 = st.columns(4)
        b1.metric("Binary Accuracy", f"{binary['accuracy'] * 100:.2f}%")
        b2.metric("Precision", f"{binary['precision']:.4f}")
        b3.metric("Recall", f"{binary['recall']:.4f}")
        b4.metric("F1-Score", f"{binary['f1_score']:.4f}")


# ==============================================================================
# SECTION 6: EXPLAINABILITY (SHAP)
# ==============================================================================
elif nav_option == "EXPLAINABILITY (SHAP)":
    st.markdown("### 🧠 SHAP EXPLAINABLE AI (XAI) BYTE ENGINE")

    if not st.session_state.detection_results:
        st.info("Upload and analyze a PCAP file to compute byte-level SHAP explanations.")
    else:
        pkt_options = [f"Pkt #{d['packet_id']} - {d['pred_label']} ({d['confidence']*100:.1f}%)" for d in st.session_state.detection_results]
        selected_idx = st.selectbox("Select Analyzed Packet for SHAP Explanation:", range(len(pkt_options)), format_func=lambda i: pkt_options[i])

        target_pkt = st.session_state.detection_results[selected_idx]
        norm_payload = target_pkt["norm_payload"]

        if st.button("⚡ Compute SHAP Byte Explanation"):
            with st.spinner("Computing SHAP byte importance scores for PyTorch 1D-CNN+BiLSTM model..."):
                bg_data = np.zeros((20, config.PAYLOAD_SIZE), dtype=np.float32)
                explainer = PyTorchIDSShapExplainer(model, background_data=bg_data)
                shap_res = explainer.explain_payload(norm_payload, top_k=8)

                st.markdown("<div class='soc-panel'>", unsafe_allow_html=True)
                st.markdown(f"**Predicted Threat:** `{target_pkt['pred_label']}` | **Confidence:** `{target_pkt['confidence']*100:.2f}%`")
                st.markdown("</div>", unsafe_allow_html=True)

                SOCDashboardComponents.render_shap_heatmap(shap_res["byte_shap_scores"], shap_res["top_contributing_bytes"])


# ==============================================================================
# SECTION 7: SYSTEM LOGS
# ==============================================================================
elif nav_option == "SYSTEM LOGS":
    st.markdown("### 📜 SYSTEM OPERATIONAL LOGS")
    log_text = "<br>".join(st.session_state.system_logs)
    st.markdown(f"<div class='soc-log-box' style='max-height:500px;'>{log_text}</div>", unsafe_allow_html=True)
