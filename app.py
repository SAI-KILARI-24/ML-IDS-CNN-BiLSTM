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

# Apply Custom Colorful Theme CSS
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

# Colorful Header Banner
st.markdown(
    """
    <div class="soc-header-banner">
        <div class="soc-title">🛡️ ML-IDS: Network Intrusion Detection Console</div>
        <div class="soc-subtitle">
            ⚡ PyTorch 1D-CNN + BiLSTM Deep Learning Model | Scapy Payload Processing | SHAP Explainable AI
        </div>
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
st.markdown("### 📥 1. Upload PCAP File")

col_up1, col_up2 = st.columns([3, 1])

with col_up1:
    uploaded_file = st.file_uploader(
        "Select or Drag & Drop PCAP File (.pcap / .pcapng)",
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
    st.markdown("### 📄 2. File Information")
    st.markdown(
        f"""
        <div class="soc-card" style="border-left: 4px solid #6366f1;">
            <div style="font-size:1rem; color:#f8fafc;">
                📂 <b>Selected File:</b> <span class="badge-info">{st.session_state.target_pcap_name}</span> &nbsp;|&nbsp; 
                💾 <b>File Size:</b> <b style="color:#60a5fa;">{file_info['file_size_mb']} MB</b> &nbsp;|&nbsp; 
                📦 <b>Packets Found:</b> <b style="color:#a78bfa;">{file_info['total_packets']}</b> &nbsp;|&nbsp;
                ⚡ <b>Payload Packets:</b> <b style="color:#f472b6;">{file_info['packets_with_payload']}</b>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("### 🔍 3. Analyze Traffic")
    btn_analyze = st.button("🚀 CHECK & ANALYZE FILE", type="primary", use_container_width=True)

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
    st.markdown("### 🚨 4. Analysis Result")
    
    if is_attack_detected:
        st.markdown(
            f"""
            <div class="banner-attack">
                <h2 style="color:#ffffff; margin:0 0 0.6rem 0; font-weight:800; display:flex; align-items:center;">
                    ⚠️ Status: ATTACK DETECTED
                </h2>
                <div style="font-size:1.1rem; color:#fecdd3; line-height:1.6;">
                    <b>Primary Attack Vector:</b> <span class="badge-attack" style="font-size:1rem;">{primary_attack}</span> &nbsp;|&nbsp; 
                    <b>Avg Model Confidence:</b> <code>{avg_confidence * 100:.1f}%</code> &nbsp;|&nbsp; 
                    <b>Malicious Flows:</b> <code>{attack_flows} / {total_flows}</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            """
            <div class="banner-benign">
                <h2 style="color:#ffffff; margin:0 0 0.6rem 0; font-weight:800;">
                    ✅ Status: BENIGN TRAFFIC
                </h2>
                <div style="font-size:1.1rem; color:#a7f3d0;">
                    No malicious attack vectors detected. All analyzed packets match normal operational network traffic.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # --------------------------------------------------------------------------
    # SECTION E: DETECTION SUMMARY (Vibrant KPI Cards)
    # --------------------------------------------------------------------------
    st.markdown("### 📊 5. Detection Summary")
    s1, s2, s3, s4 = st.columns(4)

    with s1:
        st.markdown(
            f"""
            <div class="kpi-card kpi-blue">
                <div class="kpi-title">Flows Analyzed</div>
                <div class="kpi-value">{total_flows:,}</div>
                <div class="kpi-sub">Total Packet Sequences</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with s2:
        card_class = "kpi-red" if attack_flows > 0 else "kpi-green"
        st.markdown(
            f"""
            <div class="kpi-card {card_class}">
                <div class="kpi-title">Attack Flows</div>
                <div class="kpi-value">{attack_flows:,}</div>
                <div class="kpi-sub">{attack_flows} Threats Detected</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with s3:
        st.markdown(
            f"""
            <div class="kpi-card kpi-green">
                <div class="kpi-title">Benign Flows</div>
                <div class="kpi-value">{benign_flows:,}</div>
                <div class="kpi-sub">Normal Traffic</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with s4:
        st.markdown(
            f"""
            <div class="kpi-card kpi-purple">
                <div class="kpi-title">Processing Latency</div>
                <div class="kpi-value">{st.session_state.processing_time_ms} ms</div>
                <div class="kpi-sub">PyTorch Inference Time</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # --------------------------------------------------------------------------
    # SECTION F: DETECTION DETAILS TABLE
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 📋 6. Detection Details Table")
    SOCDashboardComponents.render_detection_table(detections)

    # --------------------------------------------------------------------------
    # SECTION G: ATTACK ANALYSIS
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 📈 7. Attack Analysis")
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
    st.markdown("### ⚙️ 8. Model Information & Evaluation Metrics")
    m_col1, m_col2 = st.columns(2)

    with m_col1:
        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 4px solid #8b5cf6;">
                <h4 style="color:#c084fc; margin-top:0;">🧠 PyTorch Architecture Details</h4>
                <p style="margin:4px 0;"><b>Framework:</b> PyTorch <code>{torch.__version__}</code></p>
                <p style="margin:4px 0;"><b>Model Type:</b> 1D-CNN + Bidirectional LSTM (BiLSTM)</p>
                <p style="margin:4px 0;"><b>Input Format:</b> 1,024 Normalized Byte Sequence <code>(1, 1024)</code></p>
                <p style="margin:4px 0;"><b>Target Classes ({len(config.CIC_IOT_CLASSES)}):</b> CICIoT2023 Dataset Schema</p>
                <p style="margin:4px 0;"><b>Saved Weights:</b> <code>{config.SAVED_MODEL_PATH.name}</code></p>
            </div>
            """,
            unsafe_allow_html=True
        )

    with m_col2:
        if config.METRICS_REPORT_PATH.exists():
            with open(config.METRICS_REPORT_PATH, "r") as f:
                metrics_rep = json.load(f)
            multi = metrics_rep["multiclass"]
            st.markdown(
                f"""
                <div class="soc-card" style="border-left: 4px solid #38bdf8;">
                    <h4 style="color:#38bdf8; margin-top:0;">🏆 Test Dataset Evaluation Metrics</h4>
                    <p style="margin:4px 0;"><b>Multiclass Accuracy:</b> <b style="color:#4ade80;">{multi['accuracy'] * 100:.2f}%</b></p>
                    <p style="margin:4px 0;"><b>Precision (Macro):</b> <code>{multi['precision_macro']:.4f}</code></p>
                    <p style="margin:4px 0;"><b>Recall (Macro):</b> <code>{multi['recall_macro']:.4f}</code></p>
                    <p style="margin:4px 0;"><b>F1-Score (Macro):</b> <b style="color:#60a5fa;">{multi['f1_macro']:.4f}</b></p>
                </div>
                """,
                unsafe_allow_html=True
            )

    # --------------------------------------------------------------------------
    # SECTION I: EXPLAINABILITY (SHAP)
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 🧠 9. Explainability (SHAP Byte Importance)")
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
    st.markdown("### 🔄 10. Actions")
    if st.button("🔄 Clear / Start New Analysis", use_container_width=True):
        st.session_state.target_pcap_path = None
        st.session_state.target_pcap_name = None
        st.session_state.pcap_file_info = None
        st.session_state.analysis_done = False
        st.session_state.detection_results = []
        st.session_state.processing_time_ms = 0.0
        st.rerun()
