import os
import sys
import time
import json
import torch
import numpy as np
import pandas as pd
from pathlib import Path
import streamlit as st
import matplotlib.pyplot as plt

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

# Streamlit Page Setup
st.set_page_config(
    page_title="ML Intrusion Detection System",
    layout="wide"
)

# Apply CSS Styles
st.markdown(get_custom_css(), unsafe_allow_html=True)


# Load Trained PyTorch Model
@st.cache_resource
def load_ids_model():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if not config.SAVED_MODEL_PATH.exists():
        return None, None, f"Model file missing at {config.SAVED_MODEL_PATH}"
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
        return model, classes, "System Ready"
    except Exception as e:
        return None, None, str(e)


model, class_labels, model_status = load_ids_model()

# Top Dark Navigation Header Bar
st.markdown(
    f"""
    <div class="top-header-bar">
        <div>
            <div class="top-header-title">ML Intrusion Detection System</div>
            <div class="top-header-sub">Network Traffic Analysis</div>
            <div style="font-size:0.75rem; color:#64748b; margin-top:2px;">
                PCAP-based network intrusion detection using 1D-CNN and BiLSTM
            </div>
        </div>
        <div class="system-ready-pill">
            <span style="font-size:0.9rem;">●</span> {model_status if model else "System Offline"}
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
# PCAP FILE INPUT SECTION
# ==============================================================================
st.markdown('<div class="section-head">PCAP File</div>', unsafe_allow_html=True)
st.markdown('<div class="section-sub">Upload a network capture file for intrusion analysis.</div>', unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "Upload PCAP File",
    type=["pcap", "pcapng", "cap"],
    label_visibility="collapsed"
)

# Handle Uploaded File Selection
if uploaded_file is not None:
    save_path = config.SAMPLE_PCAP_DIR / uploaded_file.name
    with open(save_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.session_state.target_pcap_path = str(save_path)
    st.session_state.target_pcap_name = uploaded_file.name
else:
    # Auto-load default sample PCAP for convenience if no file uploaded
    sample_path = str(config.SAMPLE_PCAP_DIR / "sample_traffic.pcap")
    if not Path(sample_path).exists():
        generate_sample_pcap(sample_path)
    if st.session_state.target_pcap_path is None:
        st.session_state.target_pcap_path = sample_path
        st.session_state.target_pcap_name = "sample_traffic.pcap"


# ==============================================================================
# SELECTED FILE INFORMATION & ANALYZE PCAP BUTTON
# ==============================================================================
if st.session_state.target_pcap_path and Path(st.session_state.target_pcap_path).exists():
    pcap_processor = PCAPProcessor()
    
    if st.session_state.pcap_file_info is None or st.session_state.pcap_file_info.get("file_name") != st.session_state.target_pcap_name:
        val_res = pcap_processor.process_pcap(st.session_state.target_pcap_path, max_packets=500)
        if val_res["success"]:
            st.session_state.pcap_file_info = val_res["file_info"]
            st.session_state.pre_extracted_packets = val_res["packets"]

    file_info = st.session_state.pcap_file_info

    # File info + Analyze Button Bar matching mockup screenshot
    col_f1, col_f2, col_f3, col_btn = st.columns([2.5, 2, 2, 2.5])
    
    with col_f1:
        st.write(f"📄 **Selected file:**  \n`{st.session_state.target_pcap_name}`")
    with col_f2:
        st.write(f"**File size:**  \n`{file_info['file_size_mb']} MB`")
    with col_f3:
        st.write(f"**Packets:**  \n`{file_info['total_packets']}`")
    with col_btn:
        st.write(" ")
        btn_analyze = st.button("▶ Analyze PCAP", type="primary", use_container_width=True)

    # Execute PyTorch Inference Pass upon clicking button
    if btn_analyze:
        if model is None:
            st.error(f"Cannot perform detection: {model_status}")
        else:
            with st.spinner("Analyzing network traffic..."):
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

                    detections.append({
                        "packet_id": pkt["packet_id"],
                        "timestamp_str": time.strftime("%H:%M:%S", time.localtime(pkt["timestamp"])),
                        "src_ip": pkt["src_ip"],
                        "dst_ip": pkt["dst_ip"],
                        "protocol": pkt["protocol"],
                        "pred_label": pred_label,
                        "confidence": float(probs[pred_idx]),
                        "raw_payload": raw_payload,
                        "norm_payload": norm_payload
                    })

                elapsed_ms = (time.time() - start_time) * 1000.0
                st.session_state.detection_results = detections
                st.session_state.processing_time_ms = round(elapsed_ms, 1)
                st.session_state.analysis_done = True


# ==============================================================================
# RESULTS DASHBOARD GRID (2 COLUMNS MATCHING MOCKUP SCREENSHOT)
# ==============================================================================
if st.session_state.analysis_done and st.session_state.detection_results:
    detections = st.session_state.detection_results
    total_packets = len(detections)
    attack_packets = sum(1 for d in detections if "Benign" not in d["pred_label"])
    benign_packets = total_packets - attack_packets
    avg_confidence = float(np.mean([d["confidence"] for d in detections]))

    # Determine primary predicted attack class
    attack_counts = {}
    for d in detections:
        if "Benign" not in d["pred_label"]:
            lbl = d["pred_label"]
            attack_counts[lbl] = attack_counts.get(lbl, 0) + 1

    primary_attack = max(attack_counts, key=attack_counts.get) if attack_counts else "None"
    is_attack = attack_packets > 0

    st.markdown("---")
    
    col_left, col_right = st.columns([1, 1.15], gap="medium")

    # ==========================================================================
    # LEFT COLUMN: ANALYSIS RESULT, TRAFFIC SUMMARY, MODEL INFORMATION
    # ==========================================================================
    with col_left:
        # 1. ANALYSIS RESULT BOX
        st.markdown('<div class="section-head">Analysis Result</div>', unsafe_allow_html=True)
        
        if is_attack:
            st.markdown(
                f"""
                <div class="result-box-attack">
                    <div class="result-title-attack">
                        <span style="font-size:1.4rem;">⚠️</span> ATTACK DETECTED
                    </div>
                    <div style="display:flex; justify-content:space-between; margin-top:1rem;">
                        <div>
                            <div class="metric-label">Predicted Class</div>
                            <div class="metric-val-red">{primary_attack}</div>
                        </div>
                        <div>
                            <div class="metric-label">Confidence</div>
                            <div class="metric-val-red">{avg_confidence * 100:.1f}%</div>
                        </div>
                        <div>
                            <div class="metric-label">Packets Analyzed</div>
                            <div class="metric-val-dark">{total_packets}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div class="result-box-benign">
                    <div class="result-title-benign">
                        BENIGN TRAFFIC
                    </div>
                    <div style="display:flex; justify-content:space-between; margin-top:1rem;">
                        <div>
                            <div class="metric-label">Predicted Class</div>
                            <div style="font-size:1.4rem; font-weight:800; color:#16a34a;">BenignTraffic</div>
                        </div>
                        <div>
                            <div class="metric-label">Confidence</div>
                            <div style="font-size:1.4rem; font-weight:800; color:#16a34a;">{avg_confidence * 100:.1f}%</div>
                        </div>
                        <div>
                            <div class="metric-label">Packets Analyzed</div>
                            <div class="metric-val-dark">{total_packets}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # 2. TRAFFIC SUMMARY TABLE
        st.markdown('<div class="section-head" style="margin-top:1rem;">Traffic Summary</div>', unsafe_allow_html=True)
        summary_df = pd.DataFrame([
            {"Metric": "Total packets", "Value": str(file_info["total_packets"])},
            {"Metric": "Packets analyzed", "Value": str(total_packets)},
            {"Metric": "Attack packets", "Value": str(attack_packets)},
            {"Metric": "Benign packets", "Value": str(benign_packets)},
            {"Metric": "Processing time", "Value": f"{st.session_state.processing_time_ms} ms"}
        ])
        st.table(summary_df)

        # 3. MODEL INFORMATION
        st.markdown('<div class="section-head" style="margin-top:1.5rem;">Model Information</div>', unsafe_allow_html=True)
        m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
        with m_col1:
            st.write("**Model**  \n1D-CNN + BiLSTM")
        with m_col2:
            st.write(f"**Framework**  \nPyTorch")
        with m_col3:
            st.write("**Input**  \nNetwork packet payload")
        with m_col4:
            st.write("**Input size**  \n1,024 bytes")
        with m_col5:
            st.write("**Dataset**  \nCICIoT2023")

    # ==========================================================================
    # RIGHT COLUMN: DETECTION RESULTS, ATTACK ANALYSIS, SHAP & ACTIONS
    # ==========================================================================
    with col_right:
        # 1. DETECTION RESULTS TABLE
        st.markdown('<div class="section-head">Detection Results</div>', unsafe_allow_html=True)
        details_data = []
        for d in detections:
            is_pkt_attack = "Benign" not in d["pred_label"]
            status_tag = "Attack" if is_pkt_attack else "Benign"
            details_data.append({
                "Flow / Packet": str(d["packet_id"]),
                "Predicted Class": d["pred_label"],
                "Confidence": f"{d['confidence'] * 100:.1f}%",
                "Status": status_tag
            })

        df_details = pd.DataFrame(details_data)
        st.dataframe(df_details, use_container_width=True, hide_index=True)

        # 2. ATTACK ANALYSIS
        if is_attack:
            st.markdown('<div class="section-head" style="margin-top:1.2rem;">Attack Analysis</div>', unsafe_allow_html=True)
            st.markdown('<div class="section-sub">Detected Attack Classes</div>', unsafe_allow_html=True)
            atk_df = pd.DataFrame(list(attack_counts.items()), columns=["Attack Class", "Count"])
            st.dataframe(atk_df, use_container_width=True, hide_index=True)

        # 3. EXPLAINABILITY (SHAP)
        st.markdown('<div class="section-head" style="margin-top:1.2rem;">Explainability</div>', unsafe_allow_html=True)
        
        pkt_opts = [f"Packet #{d['packet_id']} - {d['pred_label']} ({d['confidence']*100:.1f}%)" for d in detections]
        sel_idx = st.selectbox("Select packet for SHAP byte contribution analysis:", range(len(pkt_opts)), format_func=lambda i: pkt_opts[i])
        sel_pkt = detections[sel_idx]

        if st.button("Compute SHAP Explanation"):
            with st.spinner("Calculating SHAP feature importance for 1024 payload bytes..."):
                bg_data = np.zeros((20, config.PAYLOAD_SIZE), dtype=np.float32)
                explainer = PyTorchIDSShapExplainer(model, background_data=bg_data)
                shap_res = explainer.explain_payload(sel_pkt["norm_payload"], top_k=8)

                st.write(f"**Packet #{sel_pkt['packet_id']}** | **Predicted:** `{sel_pkt['pred_label']}` | **Confidence:** `{sel_pkt['confidence']*100:.2f}%`")
                
                # Matplotlib SHAP Grid Plot
                scores_arr = np.array(shap_res["byte_shap_scores"]).reshape((32, 32))
                fig, ax = plt.subplots(figsize=(6.5, 3))
                fig.patch.set_facecolor("#ffffff")
                ax.set_facecolor("#ffffff")
                im = ax.imshow(scores_arr, cmap="coolwarm", aspect="auto")
                cbar = fig.colorbar(im, ax=ax)
                cbar.ax.yaxis.set_tick_params(color="#0f172a")
                plt.setp(plt.getp(cbar.ax, 'yticklabels'), color="#0f172a")
                ax.set_title("1024-Byte Payload SHAP Grid (32x32 Offsets)", color="#0f172a", fontsize=9)
                ax.tick_params(colors="#0f172a", labelsize=8)
                plt.tight_layout()
                st.pyplot(fig)
                plt.close(fig)

                # Top Bytes Table
                top_df = pd.DataFrame(shap_res["top_contributing_bytes"])
                if not top_df.empty:
                    st.dataframe(
                        top_df[["byte_offset", "hex_byte", "raw_byte", "norm_value", "shap_score", "impact"]],
                        use_container_width=True,
                        hide_index=True
                    )

        # 4. NEW ANALYSIS BUTTON (Bottom Right)
        st.markdown("<br>", unsafe_allow_html=True)
        col_dummy, col_new = st.columns([2, 1])
        with col_new:
            if st.button("🔄 New Analysis", use_container_width=True):
                st.session_state.target_pcap_path = None
                st.session_state.target_pcap_name = None
                st.session_state.pcap_file_info = None
                st.session_state.analysis_done = False
                st.session_state.detection_results = []
                st.session_state.processing_time_ms = 0.0
                st.rerun()
