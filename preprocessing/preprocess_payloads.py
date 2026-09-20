import os
import sys
import numpy as np

# Ensure project root directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from packet_processing.extract_payloads import extract_payloads_from_pcap

TARGET_LENGTH = 1024  # Fixed input length required for 1D-CNN + BiLSTM model

def standardize_and_normalize_payload(byte_list, target_length=TARGET_LENGTH):
    """
    Standardizes a single byte list to target_length (1024) via padding/truncation
    and normalizes byte values from range [0, 255] to range [0.0, 1.0].
    """
    current_length = len(byte_list)
    
    # 1. Truncate or Pad
    if current_length > target_length:
        processed_bytes = byte_list[:target_length]
        action = f"Truncated from {current_length} -> {target_length}"
    elif current_length < target_length:
        padding_needed = target_length - current_length
        processed_bytes = byte_list + [0] * padding_needed
        action = f"Zero-padded from {current_length} -> {target_length}"
    else:
        processed_bytes = byte_list
        action = f"Kept exact length {target_length}"
        
    # 2. Normalize 0-255 to 0.0-1.0
    normalized_array = np.array(processed_bytes, dtype=np.float32) / 255.0
    
    return normalized_array, action

def process_and_save_dataset(pcap_path, output_npy_path):
    """
    Loads payloads from PCAP, processes them to 1024-byte normalized arrays,
    and saves the result as a NumPy array.
    """
    payloads = extract_payloads_from_pcap(pcap_path)
    
    if not payloads:
        print("[WARNING] No payloads to process.")
        return None

    print(f"\n=== Preprocessing Pipeline (Target Length = {TARGET_LENGTH} bytes) ===")
    
    processed_list = []
    
    for idx, raw_byte_list in enumerate(payloads, start=1):
        norm_vector, action = standardize_and_normalize_payload(raw_byte_list, TARGET_LENGTH)
        processed_list.append(norm_vector)
        
        print(f"Payload #{idx}: {action}")
        print(f"  First 5 normalized values : {norm_vector[:5]}")
        print(f"  Final shape               : {norm_vector.shape}\n")
        
    # Stack into 2D NumPy array: Shape = (N_samples, 1024)
    dataset_matrix = np.array(processed_list, dtype=np.float32)
    
    os.makedirs(os.path.dirname(output_npy_path), exist_ok=True)
    np.save(output_npy_path, dataset_matrix)
    
    print("=== Preprocessing Complete ===")
    print(f"Processed Dataset Matrix Shape: {dataset_matrix.shape}")
    print(f"Saved preprocessed data to    : {output_npy_path}")
    
    return dataset_matrix

if __name__ == "__main__":
    sample_pcap = os.path.join(os.path.dirname(__file__), "..", "pcap", "sample.pcap")
    output_npy = os.path.join(os.path.dirname(__file__), "..", "dataset", "preprocessed_payloads.npy")
    
    process_and_save_dataset(
        os.path.abspath(sample_pcap),
        os.path.abspath(output_npy)
    )
