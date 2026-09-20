import os
import sys
import time
import json
import torch
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
    page_title="ML-IDS Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide"
)

# Apply Custom Dark Theme CSS
st.markdown(get_custom_css(), unsafe_allow_html=True)


# Load Trained PyTorch Model
@st.cache_resource
def load_ids_model():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if not config.SAVED_MODEL_PATH.exists():
        return None, None, f"Model checkpoint missing at {config.SAVED_MODEL_PATH}"
    try:
        checkpoint = torch.load(config.SAVED_MODEL_PATH, map_location=device)
        classes = checkpoint.get("classes", config.CIC_IOT_CLASSES)
        model = CNNBiLSTM_IDS(
            input_size=config.PAYLOAD_SIZE,
            num_classes=len(classes),
            cnn_filters=config.CNN_FILTERS,
            cnn_kernel_size=config.CNN_KERNEL_SIZE,
            lstm_hidden_size=config.LSTM_HIDDEN_SIZE,
            lstm_num_layers=config.LSTM_NUM_LAYERS,
            dropout_rate=config.DROPOUT_RATE
        ).to(device)
        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()
        return model, classes, "PyTorch Model Loaded"
    except Exception as e:
        return None, None, f"Model load error: {str(e)}"


model, class_labels, model_status = load_ids_model()

# Header Banner
st.markdown(
    """
    <div style="background-color:#161b22; padding:1.2rem; border-radius:6px; border:1px solid #30363d; margin-bottom:1.5rem;">
        <h2 style="margin:0; color:#f0f6fc; font-weight:700;">🛡️ ML-IDS: Network Intrusion Detection</h2>
        <p style="margin:4px 0 0 0; color:#8b949e; font-size:0.88rem;">
            Real-Time Payload Inspection Engine | PyTorch 1D-CNN + BiLSTM & SHAP Explainable AI
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

# Session State Initialization
if "target_pcap_path" not in st.session_state:
    st.session_state.target_pcap_path = None
if "target_pcap_name" not in st.session_state:
    st.session_state.target_pcap_name = None
if "pcap_file_info" not in st.session_state:
    st.session_state.pcap_file_info = None
if "analysis_done" not in st.session_state:
    st.session_state.analysis_done = False
if "detection_results" not in st.session_state:
    st.session_state.detection_results = []
if "processing_time_ms" not in st.session_state:
    st.session_state.processing_time_ms = 0.0


# ==============================================================================
# SECTION A: PCAP UPLOAD
# ==============================================================================
st.markdown("### 1. Upload PCAP File")

col_up1, col_up2 = st.columns([3, 1])

with col_up1:
    uploaded_file = st.file_uploader(
        "Choose .pcap or .pcapng file",
        type=["pcap", "pcapng", "cap"],
        help="Upload raw network packet capture files for payload analysis"
    )

with col_up2:
    st.write(" ")
    st.write(" ")
    use_sample = st.checkbox("Use Sample PCAP File", value=False)
    if st.button("Generate Sample PCAP"):
        sample_path = generate_sample_pcap()
        st.success("Sample PCAP Created!")

# Handle file selection
if uploaded_file is not None:
    save_path = config.SAMPLE_PCAP_DIR / uploaded_file.name
    with open(save_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.session_state.target_pcap_path = str(save_path)
    st.session_state.target_pcap_name = uploaded_file.name
elif use_sample:
    sample_path = str(config.SAMPLE_PCAP_DIR / "sample_traffic.pcap")
    if not Path(sample_path).exists():
        generate_sample_pcap(sample_path)
    st.session_state.target_pcap_path = sample_path
    st.session_state.target_pcap_name = "sample_traffic.pcap"


# ==============================================================================
# SECTION B & C: FILE INFORMATION & CHECK & ANALYZE FILE BUTTON
# (Shown only after a file is uploaded/selected)
# ==============================================================================
if st.session_state.target_pcap_path and Path(st.session_state.target_pcap_path).exists():
    pcap_processor = PCAPProcessor()
    
    # Pre-validate file metadata
    if st.session_state.pcap_file_info is None or st.session_state.pcap_file_info.get("file_name") != st.session_state.target_pcap_name:
        val_res = pcap_processor.process_pcap(st.session_state.target_pcap_path, max_packets=500)
        if val_res["success"]:
            st.session_state.pcap_file_info = val_res["file_info"]
            st.session_state.pre_extracted_packets = val_res["packets"]

    file_info = st.session_state.pcap_file_info

    st.markdown("---")
    st.markdown("### 2. File Information")
    st.markdown(
        f"""
        <div class="soc-panel">
            <div style="font-size:0.95rem; color:#f0f6fc;">
                <b>Selected File:</b> <code>{st.session_state.target_pcap_name}</code> &nbsp;|&nbsp; 
                <b>File Size:</b> {file_info['file_size_mb']} MB &nbsp;|&nbsp; 
                <b>Packets Found:</b> {file_info['total_packets']} &nbsp;|&nbsp;
                <b>Payload Packets:</b> {file_info['packets_with_payload']}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("### 3. Analyze Traffic")
    btn_analyze = st.button("🔍 CHECK & ANALYZE FILE", type="primary", use_container_width=True)

    # Trigger Analysis Pass
    if btn_analyze:
        if model is None:
            st.error(f"Cannot perform detection: {model_status}")
        else:
            with st.spinner("Analyzing PCAP..."):
                start_time = time.time()
                
                packets = st.session_state.get("pre_extracted_packets", [])
                if not packets:
                    res = pcap_processor.process_pcap(st.session_state.target_pcap_path)
                    packets = res["packets"]

                payload_proc = PayloadProcessor(target_len=config.PAYLOAD_SIZE)
                detections = []
                device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

                for pkt in packets:
                    raw_payload = pkt["payload_bytes"]
                    norm_payload = payload_proc.preprocess_payload(raw_payload)

                    x_t = torch.tensor(norm_payload, dtype=torch.float32).unsqueeze(0).to(device)
                    with torch.no_grad():
                        logits = model(x_t)
                        probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
                        pred_idx = int(np.argmax(probs))
                        pred_label = class_labels[pred_idx] if class_labels else f"Class_{pred_idx}"

                    # Ground truth heuristic verification if available
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

                elapsed_ms = (time.time() - start_time) * 1000.0
                st.session_state.detection_results = detections
                st.session_state.processing_time_ms = round(elapsed_ms, 2)
                st.session_state.analysis_done = True


# ==============================================================================
# SECTIONS D - J: ANALYSIS RESULTS (Shown ONLY after "CHECK & ANALYZE FILE" button clicked)
# ==============================================================================
if st.session_state.analysis_done and st.session_state.detection_results:
    detections = st.session_state.detection_results
    total_flows = len(detections)
    attack_flows = sum(1 for d in detections if "Benign" not in d["pred_label"])
    benign_flows = total_flows - attack_flows
    avg_confidence = float(np.mean([d["confidence"] for d in detections]))

    # Determine Primary Attack Vector
    attack_counts = {}
    for d in detections:
        if "Benign" not in d["pred_label"]:
            lbl = d["pred_label"]
            attack_counts[lbl] = attack_counts.get(lbl, 0) + 1

    primary_attack = max(attack_counts, key=attack_counts.get) if attack_counts else "None"
    is_attack_detected = attack_flows > 0

    st.markdown("---")
    
    # --------------------------------------------------------------------------
    # SECTION D: ANALYSIS RESULT BANNER
    # --------------------------------------------------------------------------
    st.markdown("### 4. Analysis Result")
    
    if is_attack_detected:
        st.markdown(
            f"""
            <div style="background-color:rgba(248,81,73,0.12); border:1px solid #f85149; padding:1.2rem; border-radius:6px; margin-bottom:1rem;">
                <h3 style="color:#f85149; margin:0 0 0.5rem 0; font-weight:700;">Status: ATTACK DETECTED</h3>
                <div style="font-size:1.05rem; color:#f0f6fc;">
                    <b>Primary Attack Prediction:</b> <span class="badge-attack">{primary_attack}</span> &nbsp;|&nbsp; 
                    <b>Average Confidence:</b> <code>{avg_confidence * 100:.1f}%</code> &nbsp;|&nbsp; 
                    <b>Malicious Flows Detected:</b> <code>{attack_flows} / {total_flows}</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            """
            <div style="background-color:rgba(63,185,80,0.12); border:1px solid #3fb950; padding:1.2rem; border-radius:6px; margin-bottom:1rem;">
                <h3 style="color:#3fb950; margin:0 0 0.5rem 0; font-weight:700;">Status: BENIGN TRAFFIC</h3>
                <div style="font-size:1.05rem; color:#f0f6fc;">
                    No malicious attack vectors detected in the analyzed packet capture.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # --------------------------------------------------------------------------
    # SECTION E: DETECTION SUMMARY
    # --------------------------------------------------------------------------
    st.markdown("### 5. Detection Summary")
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Flows / Packets Analyzed", f"{total_flows:,}")
    s2.metric("Attack Flows", f"{attack_flows:,}", delta=f"{attack_flows} Malicious" if attack_flows > 0 else "0 Threat", delta_color="inverse")
    s3.metric("Benign Flows", f"{benign_flows:,}")
    s4.metric("Processing Latency", f"{st.session_state.processing_time_ms} ms")

    # --------------------------------------------------------------------------
    # SECTION F: DETECTION DETAILS TABLE
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 6. Detection Details Table")
    SOCDashboardComponents.render_detection_table(detections)

    # --------------------------------------------------------------------------
    # SECTION G: ATTACK ANALYSIS
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 7. Attack Analysis")
    cat_counts = {}
    for d in detections:
        lbl = d["pred_label"]
        cat_counts[lbl] = cat_counts.get(lbl, 0) + 1

    df_cat = pd.DataFrame(list(cat_counts.items()), columns=["Classification", "Count"])

    c_chart, c_tbl = st.columns(2)
    with c_chart:
        st.bar_chart(df_cat.set_index("Classification"))
    with c_tbl:
        st.dataframe(df_cat, use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # SECTION H: MODEL INFORMATION & EVALUATION METRICS
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 8. Model Information & Evaluation Metrics")
    m_col1, m_col2 = st.columns(2)

    with m_col1:
        st.markdown("<div class='soc-panel'>", unsafe_allow_html=True)
        st.markdown("<div class='soc-panel-title'>PyTorch Architecture Details</div>", unsafe_allow_html=True)
        st.write(f"**Framework:** PyTorch {torch.__version__}")
        st.write(f"**Model Type:** 1D-CNN + Bidirectional LSTM (BiLSTM)")
        st.write(f"**Input Format:** 1,024 Normalized Byte Sequence `(1, 1024)`")
        st.write(f"**Target Classes ({len(config.CIC_IOT_CLASSES)}):** CICIoT2023 Dataset Schema")
        st.write(f"**Saved Weights:** `{config.SAVED_MODEL_PATH.name}`")
        st.markdown("</div>", unsafe_allow_html=True)

    with m_col2:
        if config.METRICS_REPORT_PATH.exists():
            with open(config.METRICS_REPORT_PATH, "r") as f:
                metrics_rep = json.load(f)
            multi = metrics_rep["multiclass"]
            st.markdown("<div class='soc-panel'>", unsafe_allow_html=True)
            st.markdown("<div class='soc-panel-title'>Test Dataset Evaluation Metrics</div>", unsafe_allow_html=True)
            st.write(f"**Multiclass Accuracy:** `{multi['accuracy'] * 100:.2f}%`")
            st.write(f"**Precision (Macro):** `{multi['precision_macro']:.4f}`")
            st.write(f"**Recall (Macro):** `{multi['recall_macro']:.4f}`")
            st.write(f"**F1-Score (Macro):** `{multi['f1_macro']:.4f}`")
            st.markdown("</div>", unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # SECTION I: EXPLAINABILITY (SHAP)
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 9. Explainability (SHAP Byte Importance)")
    pkt_opts = [f"Flow #{d['packet_id']} - {d['pred_label']} ({d['confidence']*100:.1f}%)" for d in detections]
    sel_idx = st.selectbox("Select Flow / Packet to Explain:", range(len(pkt_opts)), format_func=lambda i: pkt_opts[i])

    sel_pkt = detections[sel_idx]

    if st.button("⚡ Compute SHAP Explanation"):
        with st.spinner("Calculating SHAP feature importance for 1024 payload bytes..."):
            bg_data = np.zeros((20, config.PAYLOAD_SIZE), dtype=np.float32)
            explainer = PyTorchIDSShapExplainer(model, background_data=bg_data)
            shap_res = explainer.explain_payload(sel_pkt["norm_payload"], top_k=8)

            st.write(f"**Flow #{sel_pkt['packet_id']}** | **Predicted Class:** `{sel_pkt['pred_label']}` | **Confidence:** `{sel_pkt['confidence']*100:.2f}%`")
            SOCDashboardComponents.render_shap_heatmap(shap_res["byte_shap_scores"], shap_res["top_contributing_bytes"])

    # --------------------------------------------------------------------------
    # SECTION J: CLEAR / NEW ANALYSIS BUTTON
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 10. Actions")
    if st.button("🔄 Clear / Start New Analysis", use_container_width=True):
        st.session_state.target_pcap_path = None
        st.session_state.target_pcap_name = None
        st.session_state.pcap_file_info = None
        st.session_state.analysis_done = False
        st.session_state.detection_results = []
        st.session_state.processing_time_ms = 0.0
        st.rerun()
