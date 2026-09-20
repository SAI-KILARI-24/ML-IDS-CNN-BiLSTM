import pytest
import numpy as np
from pathlib import Path

import config
from preprocessing.payload_processor import PayloadProcessor
from preprocessing.pcap_processor import PCAPProcessor


def test_payload_processor_length_and_normalization():
    processor = PayloadProcessor(target_len=1024, scale=255.0)

    # 1. Test payload shorter than 1024 (Zero-padding)
    short_payload = b"\x41\x42\x43\x44"  # 4 bytes
    res_short = processor.preprocess_payload(short_payload)
    assert res_short.shape == (1024,)
    assert res_short.dtype == np.float32
    assert np.allclose(res_short[:4], np.array([65, 66, 67, 68]) / 255.0)
    assert np.all(res_short[4:] == 0.0)

    # 2. Test payload longer than 1024 (Truncation)
    long_payload = bytes([i % 256 for i in range(2000)])
    res_long = processor.preprocess_payload(long_payload)
    assert res_long.shape == (1024,)
    assert np.allclose(res_long[:5], np.array([0, 1, 2, 3, 4]) / 255.0)

    # 3. Test empty payload
    empty_payload = b""
    res_empty = processor.preprocess_payload(empty_payload)
    assert res_empty.shape == (1024,)
    assert np.all(res_empty == 0.0)

    # 4. Test None payload
    res_none = processor.preprocess_payload(None)
    assert res_none.shape == (1024,)
    assert np.all(res_none == 0.0)


def test_pcap_processor_validation():
    pcap_proc = PCAPProcessor()

    # Non-existent file
    valid, msg = pcap_proc.validate_pcap("non_existent_file.pcap")
    assert not valid
    assert "File not found" in msg

    # Invalid extension
    fake_txt = config.BASE_DIR / "test_fake.txt"
    fake_txt.write_text("dummy text")
    valid, msg = pcap_proc.validate_pcap(str(fake_txt))
    assert not valid
    assert "Invalid file extension" in msg
    if fake_txt.exists():
        fake_txt.unlink()
