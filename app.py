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
    page_title="ML Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)

# Apply Custom Dark Theme CSS
st.markdown(get_custom_css(), unsafe_allow_html=True)


# Load PyTorch Model
@st.cache_resource
def load_ids_model():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if not config.SAVED_MODEL_PATH.exists():
        return None, None, "Model checkpoint missing."
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
        return model, classes, "Model Online"
    except Exception as e:
        return None, None, str(e)


model, class_labels, model_status = load_ids_model()

# Header Title Banner
st.markdown(
    """
    <div style="background-color:#161b22; padding:1.2rem; border-radius:6px; border:1px solid #30363d; margin-bottom:1.5rem;">
        <h2 style="margin:0; color:#f0f6fc; font-weight:700;">🛡️ ML-Powered Intrusion Detection System (IDS)</h2>
        <p style="margin:4px 0 0 0; color:#8b949e; font-size:0.9rem;">
            PyTorch 1D-CNN + BiLSTM Deep Learning Model & SHAP Explainable AI for Network Traffic Analysis
        </p>
    </div>
    """,
    unsafe_allow_html=True
)


# ==============================================================================
# STEP 1: INPUT FIELD & FILE UPLOAD
# ==============================================================================
st.markdown("### 📥 STEP 1: Upload Network Traffic File (.pcap / .pcapng)")

col_input1, col_input2 = st.columns([3, 1])

with col_input1:
    uploaded_file = st.file_uploader(
        "Select or Drag & Drop PCAP File",
        type=["pcap", "pcapng", "cap"],
        help="Upload raw network packet capture files for payload analysis"
    )

with col_input2:
    st.write(" ")
    st.write(" ")
    use_sample = st.checkbox("Use Sample PCAP File", value=False)
    if st.button("Generate Sample PCAP"):
        sample_path = generate_sample_pcap()
        st.success("Sample PCAP Generated!")

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


# ==============================================================================
# STEP 2: CHECK FILE BUTTON
# ==============================================================================
st.markdown("---")
st.markdown("### 🔍 STEP 2: Run Traffic Analysis")

btn_analyze = st.button("🚀 CHECK FILE & DETECT ATTACKS", type="primary", use_container_width=True)


# ==============================================================================
# STEP 3: OUTPUT RESULTS
# ==============================================================================
if btn_analyze:
    if not target_pcap_path or not Path(target_pcap_path).exists():
        st.error("Please upload a valid PCAP file or select 'Use Sample PCAP File' before checking.")
    elif model is None:
        st.error(f"Cannot run detection: PyTorch model unavailable. ({model_status})")
    else:
        with st.spinner("Extracting Scapy packet payloads & running PyTorch 1D-CNN + BiLSTM inference..."):
            processor = PCAPProcessor()
            res = processor.process_pcap(target_pcap_path)

            if not res["success"]:
                st.error(f"PCAP Processing Failed: {res['message']}")
            else:
                st.session_state["last_analysis"] = res
                st.session_state["analyzed_file_name"] = Path(target_pcap_path).name

                # Process Payloads & Predict
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

                    # Ground truth heuristic tag matching
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

                st.session_state["detections"] = detections


# Display Output Results if analysis exists
if "detections" in st.session_state and st.session_state["detections"]:
    detections = st.session_state["detections"]
    file_info = st.session_state["last_analysis"]["file_info"]

    st.markdown("---")
    st.markdown("## 📊 ANALYSIS OUTPUT & DETECTION RESULTS")

    # 1. File Metadata Summary
    st.success(f"Successfully Analyzed File: `{file_info['file_name']}` ({file_info['file_size_mb']} MB)")

    total_pkts = len(detections)
    attacks = sum(1 for d in detections if "Benign" not in d["pred_label"])
    benign = total_pkts - attacks
    avg_conf = float(np.mean([d["confidence"] for d in detections]))

    # 2. Executive KPI Panels
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Packets Analyzed", total_pkts)
    c2.metric("Attacks Detected", attacks, delta=f"{attacks} Malicious" if attacks > 0 else "0 Threat", delta_color="inverse")
    c3.metric("Benign Traffic", benign)
    c4.metric("Avg Confidence", f"{avg_conf * 100:.1f}%")

    # 3. Packet Detection Table
    st.markdown("### 📋 Packet-by-Packet Detection Feed")
    SOCDashboardComponents.render_detection_table(detections)

    # 4. Attack Analytics & Class Distribution
    st.markdown("---")
    st.markdown("### 📈 Attack Distribution Analysis")
    col_chart, col_tbl = st.columns(2)

    counts = {}
    for d in detections:
        lbl = d["pred_label"]
        counts[lbl] = counts.get(lbl, 0) + 1

    df_counts = pd.DataFrame(list(counts.items()), columns=["Threat Category", "Packet Count"])

    with col_chart:
        st.bar_chart(df_counts.set_index("Threat Category"))

    with col_tbl:
        st.dataframe(df_counts, use_container_width=True, hide_index=True)

    # 5. Model Evaluation Metrics
    st.markdown("---")
    st.markdown("### 🏆 Actual PyTorch Model Evaluation Metrics")
    if config.METRICS_REPORT_PATH.exists():
        with open(config.METRICS_REPORT_PATH, "r") as f:
            metrics_report = json.load(f)

        multi = metrics_report["multiclass"]
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Multiclass Accuracy", f"{multi['accuracy'] * 100:.2f}%")
        m2.metric("Precision (Macro)", f"{multi['precision_macro']:.4f}")
        m3.metric("Recall (Macro)", f"{multi['recall_macro']:.4f}")
        m4.metric("F1-Score (Macro)", f"{multi['f1_macro']:.4f}")

        SOCDashboardComponents.render_confusion_matrix_plot(multi["confusion_matrix"], multi["classes"])

    # 6. SHAP Byte Explainability
    st.markdown("---")
    st.markdown("### 🧠 SHAP Explainable AI (XAI) Byte Inspection")
    pkt_options = [f"Pkt #{d['packet_id']} - {d['pred_label']} ({d['confidence']*100:.1f}%)" for d in detections]
    selected_pkt_idx = st.selectbox("Select Analyzed Packet to Explain:", range(len(pkt_options)), format_func=lambda i: pkt_options[i])

    target_pkt = detections[selected_pkt_idx]

    if st.button("⚡ Compute SHAP Explanation for Selected Packet"):
        with st.spinner("Computing SHAP byte importance scores..."):
            bg_data = np.zeros((20, config.PAYLOAD_SIZE), dtype=np.float32)
            explainer = PyTorchIDSShapExplainer(model, background_data=bg_data)
            shap_res = explainer.explain_payload(target_pkt["norm_payload"], top_k=8)

            st.write(f"**Selected Packet:** `{target_pkt['packet_id']}` | **Predicted Threat:** `{target_pkt['pred_label']}` | **Confidence:** `{target_pkt['confidence']*100:.2f}%`")
            SOCDashboardComponents.render_shap_heatmap(shap_res["byte_shap_scores"], shap_res["top_contributing_bytes"])

else:
    st.info("💡 Instructions: Upload a PCAP file above (or check 'Use Sample PCAP File') and click '🚀 CHECK FILE & DETECT ATTACKS' to view analysis output.")
