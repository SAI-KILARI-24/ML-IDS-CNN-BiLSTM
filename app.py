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
from models.cnn_bilstm import CNNBiLSTM_IDS
from explainability.shap_explainer import PyTorchIDSShapExplainer
from dashboard.styles import get_custom_css

# Streamlit Page Setup
st.set_page_config(
    page_title="ML Intrusion Detection System",
    layout="wide"
)

# Apply Minimal Academic Theme CSS
st.markdown(get_custom_css(), unsafe_allow_html=True)


# Load Trained PyTorch Model
@st.cache_resource
def load_ids_model():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if not config.SAVED_MODEL_PATH.exists():
        return None, None, f"Model file not found at {config.SAVED_MODEL_PATH}"
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
        return model, classes, "Loaded"
    except Exception as e:
        return None, None, str(e)


model, class_labels, model_status = load_ids_model()

# Header
st.markdown(
    """
    <div class="app-header">
        <div class="app-title">ML Intrusion Detection System</div>
        <div style="font-size:1.1rem; color:#e2e8f0; font-weight:600; margin-top:2px;">Network Traffic Analysis</div>
        <div class="app-subtitle">PCAP-based network intrusion detection using 1D-CNN and BiLSTM</div>
    </div>
    """,
    unsafe_allow_html=True
)

# Initialize Session State
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
# MAIN INPUT AREA: PCAP FILE UPLOAD
# ==============================================================================
st.markdown("#### PCAP File")
st.caption("Upload a network capture file for intrusion analysis.")

uploaded_file = st.file_uploader(
    "Choose PCAP File",
    type=["pcap", "pcapng", "cap"],
    label_visibility="collapsed"
)

# Handle Uploaded File
if uploaded_file is not None:
    save_path = config.SAMPLE_PCAP_DIR / uploaded_file.name
    with open(save_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.session_state.target_pcap_path = str(save_path)
    st.session_state.target_pcap_name = uploaded_file.name


# ==============================================================================
# FILE INFORMATION & ANALYZE BUTTON (Shown ONLY after file is uploaded)
# ==============================================================================
if st.session_state.target_pcap_path and Path(st.session_state.target_pcap_path).exists():
    pcap_processor = PCAPProcessor()
    
    # Extract metadata without running prediction
    if st.session_state.pcap_file_info is None or st.session_state.pcap_file_info.get("file_name") != st.session_state.target_pcap_name:
        val_res = pcap_processor.process_pcap(st.session_state.target_pcap_path, max_packets=500)
        if val_res["success"]:
            st.session_state.pcap_file_info = val_res["file_info"]
            st.session_state.pre_extracted_packets = val_res["packets"]

    file_info = st.session_state.pcap_file_info

    # Display Selected File Information
    st.markdown("<br>", unsafe_allow_html=True)
    col_info1, col_info2, col_info3 = st.columns(3)
    col_info1.write(f"**Selected file:** `{st.session_state.target_pcap_name}`")
    col_info2.write(f"**File size:** `{file_info['file_size_mb']} MB`")
    col_info3.write(f"**Packets:** `{file_info['total_packets']}`")

    # Analyze PCAP Button
    st.markdown("<br>", unsafe_allow_html=True)
    btn_analyze = st.button("Analyze PCAP", type="primary")

    # Execute Inference upon button click
    if btn_analyze:
        if model is None:
            st.error(f"Cannot execute analysis: {model_status}")
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
                st.session_state.processing_time_ms = round(elapsed_ms, 2)
                st.session_state.analysis_done = True


# ==============================================================================
# OUTPUT RESULTS SECTION (Rendered ONLY after "Analyze PCAP" is clicked)
# ==============================================================================
if st.session_state.analysis_done and st.session_state.detection_results:
    detections = st.session_state.detection_results
    total_packets = len(detections)
    attack_packets = sum(1 for d in detections if "Benign" not in d["pred_label"])
    benign_packets = total_packets - attack_packets
    avg_confidence = float(np.mean([d["confidence"] for d in detections]))

    # Identify primary predicted attack class
    attack_counts = {}
    for d in detections:
        if "Benign" not in d["pred_label"]:
            lbl = d["pred_label"]
            attack_counts[lbl] = attack_counts.get(lbl, 0) + 1

    primary_attack = max(attack_counts, key=attack_counts.get) if attack_counts else "None"
    is_attack = attack_packets > 0

    st.markdown("---")
    
    # --------------------------------------------------------------------------
    # 1. ANALYSIS RESULT
    # --------------------------------------------------------------------------
    st.markdown("#### ANALYSIS RESULT")
    
    if is_attack:
        st.markdown(
            f"""
            <div class="status-box-attack">
                <div class="status-title">Status: ATTACK DETECTED</div>
                <div><b>Predicted Class:</b> <span class="badge-attack">{primary_attack}</span></div>
                <div><b>Confidence:</b> <code>{avg_confidence * 100:.1f}%</code></div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f"""
            <div class="status-box-benign">
                <div class="status-title">Status: BENIGN TRAFFIC</div>
                <div><b>Predicted Class:</b> <span class="badge-benign">BenignTraffic</span></div>
                <div><b>Confidence:</b> <code>{avg_confidence * 100:.1f}%</code></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # --------------------------------------------------------------------------
    # 2. TRAFFIC SUMMARY
    # --------------------------------------------------------------------------
    st.markdown("#### Traffic Summary")
    summary_df = pd.DataFrame([
        {"Metric": "Total packets", "Value": str(file_info["total_packets"])},
        {"Metric": "Packets analyzed", "Value": str(total_packets)},
        {"Metric": "Attack packets", "Value": str(attack_packets)},
        {"Metric": "Benign packets", "Value": str(benign_packets)},
        {"Metric": "Processing time", "Value": f"{st.session_state.processing_time_ms} ms"}
    ])
    st.table(summary_df)

    # --------------------------------------------------------------------------
    # 3. DETECTION RESULTS
    # --------------------------------------------------------------------------
    st.markdown("#### Detection Results")
    details_data = []
    for d in detections:
        is_pkt_attack = "Benign" not in d["pred_label"]
        details_data.append({
            "Flow / Packet": str(d["packet_id"]),
            "Predicted Class": d["pred_label"],
            "Confidence": f"{d['confidence'] * 100:.1f}%",
            "Status": "Attack" if is_pkt_attack else "Benign"
        })
    st.dataframe(pd.DataFrame(details_data), use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # 4. ATTACK ANALYSIS
    # --------------------------------------------------------------------------
    if is_attack:
        st.markdown("#### Detected Attack Classes")
        atk_df = pd.DataFrame(list(attack_counts.items()), columns=["Attack Class", "Count"])
        st.dataframe(atk_df, use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # 5. MODEL INFORMATION
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("#### Model Information")
    model_info_df = pd.DataFrame([
        {"Property": "Model", "Details": "1D-CNN + BiLSTM"},
        {"Property": "Framework", "Details": f"PyTorch {torch.__version__}"},
        {"Property": "Input", "Details": "Network packet payload"},
        {"Property": "Input size", "Details": "1,024 bytes"},
        {"Property": "Dataset", "Details": "CICIoT2023"}
    ])
    st.table(model_info_df)

    # --------------------------------------------------------------------------
    # 6. EXPLAINABILITY (SHAP)
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("#### Explainability (SHAP)")
    pkt_opts = [f"Packet #{d['packet_id']} - {d['pred_label']} ({d['confidence']*100:.1f}%)" for d in detections]
    sel_idx = st.selectbox("Select packet for SHAP explanation:", range(len(pkt_opts)), format_func=lambda i: pkt_opts[i])
    sel_pkt = detections[sel_idx]

    if st.button("Compute SHAP Explanation"):
        with st.spinner("Computing SHAP feature importance for 1024 payload bytes..."):
            bg_data = np.zeros((20, config.PAYLOAD_SIZE), dtype=np.float32)
            explainer = PyTorchIDSShapExplainer(model, background_data=bg_data)
            shap_res = explainer.explain_payload(sel_pkt["norm_payload"], top_k=8)

            st.write(f"**Packet #{sel_pkt['packet_id']}** | **Predicted Class:** `{sel_pkt['pred_label']}` | **Confidence:** `{sel_pkt['confidence']*100:.2f}%`")
            
            # Matplotlib Grid Plot
            scores_arr = np.array(shap_res["byte_shap_scores"]).reshape((32, 32))
            fig, ax = plt.subplots(figsize=(7, 3.5))
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

            # Top Contributing Bytes Table
            top_df = pd.DataFrame(shap_res["top_contributing_bytes"])
            if not top_df.empty:
                st.dataframe(
                    top_df[["byte_offset", "hex_byte", "raw_byte", "norm_value", "shap_score", "impact"]],
                    use_container_width=True,
                    hide_index=True
                )

    # --------------------------------------------------------------------------
    # 7. NEW ANALYSIS BUTTON
    # --------------------------------------------------------------------------
    st.markdown("---")
    st.markdown("#### Actions")
    if st.button("New Analysis"):
        st.session_state.target_pcap_path = None
        st.session_state.target_pcap_name = None
        st.session_state.pcap_file_info = None
        st.session_state.analysis_done = False
        st.session_state.detection_results = []
        st.session_state.processing_time_ms = 0.0
        st.rerun()
