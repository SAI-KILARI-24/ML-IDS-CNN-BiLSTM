import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLE_PCAP_DIR = DATA_DIR / "sample_pcaps"
MODELS_DIR = BASE_DIR / "models"

# Output Artifact Paths
SAVED_MODEL_PATH = MODELS_DIR / "trained_model.pt"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"
TRAINING_HISTORY_PATH = MODELS_DIR / "training_history.json"
METRICS_REPORT_PATH = MODELS_DIR / "evaluation_metrics.json"

# Payload Preprocessing Configuration
PAYLOAD_SIZE = 1024  # Standard fixed length in bytes
NORMALIZATION_SCALE = 255.0  # Byte scale [0, 255] -> [0.0, 1.0]

# Model Architecture Hyperparameters
CNN_FILTERS = 64
CNN_KERNEL_SIZE = 5
LSTM_HIDDEN_SIZE = 64
LSTM_NUM_LAYERS = 2
DROPOUT_RATE = 0.3

# Training Hyperparameters
BATCH_SIZE = 64
LEARNING_RATE = 0.001
EPOCHS = 15
TRAIN_SPLIT = 0.7
VAL_SPLIT = 0.15
TEST_SPLIT = 0.15

# Target Dataset Attack Classes (CICIoT2023 subset & Benign)
CIC_IOT_CLASSES = [
    "BenignTraffic",
    "DDoS-SYN_Flood",
    "DDoS-UDP_Flood",
    "Mirai-greeth_flood",
    "Recon-PortScan",
    "Spoofing-ARP",
    "Vulnerability-Scan",
    "DDoS-ICMP_Flood"
]

# Ensure required directories exist
for path in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, SAMPLE_PCAP_DIR, MODELS_DIR]:
    path.mkdir(parents=True, exist_ok=True)
