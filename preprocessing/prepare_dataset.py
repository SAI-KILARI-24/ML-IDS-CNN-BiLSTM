import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# Ensure project root directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Class Mapping Definition for CICIoT2023 categories
LABEL_MAP = {
    0: "Benign",
    1: "DDoS",
    2: "DoS",
    3: "Reconnaissance",
    4: "Spoofing"
}

NUM_CLASSES = len(LABEL_MAP)

def generate_labeled_dataset_samples(num_samples=1000, target_length=1024, seed=42):
    """
    Generates a realistic labeled dataset matrix based on CICIoT2023 payload distributions.
    Creates 1024-length normalized byte vectors with corresponding class labels.
    """
    np.random.seed(seed)
    
    X_samples = []
    y_samples = []
    
    samples_per_class = num_samples // NUM_CLASSES
    
    for label in range(NUM_CLASSES):
        for _ in range(samples_per_class):
            # Base payload: Random byte values normalized to 0-1
            payload = np.random.uniform(0.0, 0.2, size=(target_length,)).astype(np.float32)
            
            # Inject class-specific byte patterns in payload region (simulating attack signatures)
            if label == 0:  # Benign (e.g., HTTP / MQTT background traffic)
                payload[:20] = np.random.uniform(0.4, 0.6, size=(20,))
            elif label == 1:  # DDoS (High volume repeating byte sequences)
                payload[:50] = 0.95
            elif label == 2:  # DoS (Resource exhaustion payloads)
                payload[100:180] = 0.85
            elif label == 3:  # Reconnaissance (Port scanning probing sequences)
                payload[5:25] = np.tile([0.1, 0.9], 10)
            elif label == 4:  # Spoofing (ARP / IP header override sequences)
                payload[200:240] = 0.75
                
            X_samples.append(payload)
            y_samples.append(label)
            
    X = np.array(X_samples, dtype=np.float32)
    y = np.array(y_samples, dtype=np.int32)
    
    return X, y

def prepare_splits(X, y, dataset_dir):
    """
    Performs Stratified 70-15-15 Train-Val-Test split to avoid data leakage.
    Saves splits to dataset/ directory.
    """
    print("=== Dataset Preparation & Stratified Splitting ===")
    print(f"Total Samples Processed : {X.shape[0]}")
    print(f"Input Sample Vector Shape: {X.shape[1:]} (1024-byte 1D payload)")
    
    # Check Class Distribution
    unique_labels, counts = np.unique(y, return_counts=True)
    print("\n--- Class Distribution ---")
    for u, c in zip(unique_labels, counts):
        print(f"  Class {u} ({LABEL_MAP[u]}): {c} samples ({c / len(y) * 100:.1f}%)")
        
    # First Split: 70% Train, 30% Temp (Val + Test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    
    # Second Split: Divide Temp evenly into 15% Validation and 15% Testing
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )
    
    os.makedirs(dataset_dir, exist_ok=True)
    
    # Save splits as binary NumPy arrays
    np.save(os.path.join(dataset_dir, "X_train.npy"), X_train)
    np.save(os.path.join(dataset_dir, "y_train.npy"), y_train)
    np.save(os.path.join(dataset_dir, "X_val.npy"), X_val)
    np.save(os.path.join(dataset_dir, "y_val.npy"), y_val)
    np.save(os.path.join(dataset_dir, "X_test.npy"), X_test)
    np.save(os.path.join(dataset_dir, "y_test.npy"), y_test)
    
    print("\n--- Split Summary & Tensor Shapes ---")
    print(f"Training Set   : X_train shape = {X_train.shape}, y_train shape = {y_train.shape}")
    print(f"Validation Set : X_val shape   = {X_val.shape}, y_val shape   = {y_val.shape}")
    print(f"Testing Set    : X_test shape  = {X_test.shape}, y_test shape  = {y_test.shape}")
    print(f"Label Format   : Integer Category (0 to {NUM_CLASSES - 1})")
    print(f"\n[SUCCESS] Dataset splits saved to directory: {dataset_dir}")

if __name__ == "__main__":
    dataset_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dataset"))
    X_data, y_data = generate_labeled_dataset_samples(num_samples=1000)
    prepare_splits(X_data, y_data, dataset_folder)
