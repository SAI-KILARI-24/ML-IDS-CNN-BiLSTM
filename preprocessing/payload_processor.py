import numpy as np
from typing import Union, List


class PayloadProcessor:
    """
    Deterministic Payload Preprocessing Module.
    Converts raw payload byte sequences into 1024 standardized, 0-1 normalized floating-point arrays.
    """

    def __init__(self, target_len: int = 1024, scale: float = 255.0):
        self.target_len = target_len
        self.scale = scale

    def preprocess_payload(self, raw_payload: Union[bytes, bytearray, List[int], np.ndarray]) -> np.ndarray:
        """
        Preprocesses a single raw packet payload.

        Args:
            raw_payload: Raw payload bytes, list of byte ints, or array.

        Returns:
            np.ndarray of shape (1024,) with float32 values in [0.0, 1.0].
        """
        # Handle None or empty inputs
        if raw_payload is None:
            return np.zeros(self.target_len, dtype=np.float32)

        try:
            if isinstance(raw_payload, (bytes, bytearray)):
                byte_array = np.frombuffer(raw_payload, dtype=np.uint8)
            elif isinstance(raw_payload, np.ndarray):
                byte_array = raw_payload.astype(np.uint8).flatten()
            elif isinstance(raw_payload, (list, tuple)):
                byte_array = np.array(raw_payload, dtype=np.uint8)
            else:
                byte_array = np.zeros(0, dtype=np.uint8)
        except Exception:
            # Safe fallback for malformed data
            return np.zeros(self.target_len, dtype=np.float32)

        current_len = len(byte_array)

        # Pad or Truncate
        if current_len < self.target_len:
            # Zero-padding
            padded = np.zeros(self.target_len, dtype=np.uint8)
            padded[:current_len] = byte_array
            processed_bytes = padded
        else:
            # Truncation
            processed_bytes = byte_array[:self.target_len]

        # Normalization from [0, 255] to [0.0, 1.0]
        normalized = processed_bytes.astype(np.float32) / self.scale
        return normalized

    def preprocess_batch(self, raw_payloads: List[Union[bytes, bytearray, List[int], np.ndarray]]) -> np.ndarray:
        """
        Preprocesses a batch of raw payloads.

        Returns:
            np.ndarray of shape (N, 1024) with float32 values in [0.0, 1.0].
        """
        if not raw_payloads:
            return np.zeros((0, self.target_len), dtype=np.float32)

        batch = [self.preprocess_payload(p) for p in raw_payloads]
        return np.vstack(batch)
