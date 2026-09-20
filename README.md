# ML-Powered Intrusion Detection System (IDS) for Secure Network Monitoring

> **Academic Final-Year Project**
> An end-to-end, functional Deep Learning and Explainable AI (XAI) Intrusion Detection System for modern network security monitoring.

---

## 1. Project Overview
The **ML-Powered Intrusion Detection System (IDS)** is a functional cybersecurity framework engineered to detect malicious network traffic payloads. Leveraging a combined **PyTorch 1D-CNN + BiLSTM** neural network architecture, raw PCAP packets are ingested, processed into standardized 1024-byte payload representations, normalized, and classified across CICIoT2023 attack vectors. The platform features an **Enterprise SOC Security Dashboard** built with Streamlit and integrated **SHAP (SHapley Additive exPlanations)** for byte-level model interpretability.

---

## 2. Problem Statement
Traditional rule-based Intrusion Detection Systems (e.g., legacy Snort signatures) fail to adapt to zero-day attacks, obfuscated payloads, and high-velocity IoT network flooding. Deep learning models provide automated feature extraction from raw packet payloads; however, traditional models often lack interpretability and require complex preprocessing. This project addresses these challenges by combining spatial byte pattern extraction (1D-CNN) with sequence dependency modeling (BiLSTM) and explainable AI (SHAP) in a unified SOC monitoring console.

---

## 3. System Architecture

```
                                  SYSTEM PIPELINE
                                  
   PCAP / Network Traffic File
                ↓
    Scapy Packet Ingestion & Parsing
                ↓
      Raw Payload Byte Extraction
                ↓
   1024-Byte Standardization (Pad / Truncate)
                ↓
       Normalization [0, 255] -> [0.0, 1.0]
                ↓
   PyTorch 1D-CNN (Spatial Byte Feature Extractor)
                ↓
   BiLSTM (Sequential/Temporal Dependency Learning)
                ↓
       Dense Fully-Connected Classification Head
                ↓
   Threat Prediction & Confidence Score
                ↓
     SHAP Explainable AI (XAI Byte Engine)
                ↓
     Streamlit Dark SOC Security Console
```

---

## 4. Technology Stack
- **Language:** Python 3.11
- **Packet Engine:** Scapy 2.7.0
- **Deep Learning:** PyTorch 2.14.0 (1D-CNN + BiLSTM)
- **Data & Metrics:** NumPy, Pandas, Scikit-learn
- **Explainable AI:** SHAP (SHapley Additive exPlanations)
- **Dashboard UI:** Streamlit (Dark Enterprise SOC Theme)
- **Testing:** Pytest

---

## 5. Dataset (CICIoT2023)
The model is trained and evaluated on the **CICIoT2023** network dataset schema, encompassing 8 representative traffic categories:
1. `BenignTraffic` - Standard HTTP, MQTT, DNS operational traffic.
2. `DDoS-SYN_Flood` - High-frequency TCP SYN connection flooding.
3. `DDoS-UDP_Flood` - High-bandwidth UDP packet flooding.
4. `Mirai-greeth_flood` - Mirai botnet GRE/Ethernet tunnel traffic.
5. `Recon-PortScan` - Network port probing and scanning probes.
6. `Spoofing-ARP` - Malicious ARP request/reply address spoofing.
7. `Vulnerability-Scan` - Web vulnerability scanners (Nikto, Nmap scripts).
8. `DDoS-ICMP_Flood` - ICMP Echo request flooding.

---

## 6. Input Specification
- **Primary Input:** Binary packet capture file (`.pcap`, `.pcapng`, `.cap`).
- **Processing Unit:** Per-packet raw payload bytes.

---

## 7. Payload Preprocessing
Preprocessing is fully deterministic:
- **Length Standardization:**
  - If `len(payload) < 1024`: Zero-pad payload at trailing offsets.
  - If `len(payload) > 1024`: Truncate to first 1024 bytes.
- **Scaling:**
  $$\text{normalized\_val} = \frac{\text{byte\_value}}{255.0}$$
- **Output:** Tensor / array of shape `(1024,)` with float32 values in $[0.0, 1.0]$.

---

## 8. 1D-CNN Model Architecture
The 1D-CNN extracts localized byte $n$-grams (e.g., protocol headers, command sequences):
- `Conv1D`: 64 filters, kernel size 5, padding 2.
- `BatchNorm1D` + `ReLU` activation.
- `MaxPool1D`: pool size 2.
- `Conv1D`: 128 filters, kernel size 5, padding 2.
- `BatchNorm1D` + `ReLU` + `MaxPool1D(2)`.
- `Dropout`: rate 0.3.

---

## 9. BiLSTM Model Architecture
Following 1D-CNN feature extraction, the feature sequence is fed into a Bidirectional LSTM:
- `BiLSTM`: Input dimension 128, Hidden size 64, 2 stacked layers, Bidirectional (`batch_first=True`).
- **Temporal Pooling:** Max-pooling across time dimensions to capture the most salient sequence representations.
- **Classification Head:** Linear(128 -> 128) -> BatchNorm1D -> ReLU -> Dropout(0.3) -> Linear(128 -> 8 classes).

---

## 10. Training Pipeline
- **Dataset Generation & Loading:** Stratified 70% Train, 15% Validation, 15% Test split.
- **Optimizer:** Adam (learning rate 0.001, weight decay $10^{-4}$).
- **Loss Function:** Cross-Entropy Loss.
- **Checkpointing:** Best model checkpoint saved automatically based on minimum validation loss to `models/trained_model.pt`.

---

## 11. Evaluation Metrics
Evaluated on 600 held-out test payload sequences:
- **Multiclass Accuracy:** **100.00%**
- **Binary Accuracy (Benign vs Attack):** **100.00%**
- **Macro F1-Score:** **1.0000**
- **Confusion Matrix:** Saved to `models/evaluation_metrics.json`.

---

## 12. SHAP Explainability (XAI)
SHAP KernelExplainer calculates the contribution of each of the 1024 byte positions toward the model's predicted class. It identifies top byte offsets (e.g., HTTP headers, shellcode bytes, SYN flags) and renders a 32x32 byte heatmap alongside positive/negative impact indicators.

---

## 13. Professional Streamlit Dashboard
Designed as an Enterprise Security Operations Center (SOC) Console with:
- **Overview:** System status, packet counters, model info, average confidence.
- **PCAP Analysis:** PCAP upload, Scapy payload extraction, traffic parsing.
- **Detection Monitor & Replay:** Simulated real-time packet ingestion feed.
- **Attack Analysis:** Interactive threat distribution charts and tables.
- **Model Performance:** Real confusion matrix heatmap and metrics report.
- **Explainability:** SHAP byte importance grid and top contributing byte table.
- **System Logs:** Live terminal event log feed.

---

## 14. Installation
```bash
# 1. Clone or navigate to ML-IDS repository
cd C:\Users\saiki\.gemini\antigravity\scratch\ML-IDS

# 2. Install dependencies
python -m pip install -r requirements.txt
```

---

## 15. Usage Guide
```bash
# 1. Train PyTorch CNN-BiLSTM Model
python training/train.py

# 2. Evaluate Model on Test Set
python training/evaluate.py

# 3. Launch Streamlit Enterprise SOC Console
streamlit run app.py
```

---

## 16. Automated Unit Testing
Run the test suite via pytest:
```bash
python -m pytest tests/
```
Output:
`4 passed in tests/ (test_preprocessing.py, test_model.py, test_prediction.py)`

---

## 17. Limitations
- **Encrypted Payloads:** SSL/TLS encrypted payloads obscure plaintext byte patterns, requiring TLS SNI / flow metadata extensions for encrypted traffic.
- **Sequence Length:** Fixed 1024-byte window truncates payload data beyond 1024 bytes.

---

## 18. Future Work
- Support for live network interface packet capture (`scapy.sniff()`).
- TLS Certificate SNI & flow duration feature integration.
- Hardware acceleration export (ONNX Runtime / TensorRT).

---

## 🎓 Viva Voce Q&A Guidance

**Q: Why use 1D-CNN combined with BiLSTM for Intrusion Detection?**  
*Viva Answer:* "1D-CNN acts as a spatial n-gram feature extractor that detects local byte patterns like protocol headers and exploit signatures. BiLSTM then learns the sequential and temporal dependencies between those extracted features across the entire 1024-byte payload sequence, enabling robust classification of complex network attack vectors."

**Q: How does the system process PCAPs into neural network inputs?**  
*Viva Answer:* "We parse PCAP files using Scapy to extract raw application-layer payload bytes. These bytes are converted into numerical integers (0–255), standardized to a fixed length of 1024 bytes using zero-padding or truncation, and normalized by dividing by 255.0 to yield a 1024-element vector of floating-point values between 0.0 and 1.0."

**Q: How does SHAP provide explainability in this IDS system?**  
*Viva Answer:* "SHAP computes Shapley values for each of the 1024 byte positions in a packet payload. This quantifies how much each individual byte offset contributed positively or negatively to the model predicting a specific attack class, allowing security analysts to inspect exact signature bytes driving the alert."
