import pytest
import numpy as np
import torch

import config
from models.cnn_bilstm import CNNBiLSTM_IDS
from preprocessing.payload_processor import PayloadProcessor
from explainability.shap_explainer import PyTorchIDSShapExplainer


def test_end_to_end_inference_and_shap():
    # 1. Prepare raw payload
    raw_payload = b"GET /index.php?id=1' UNION SELECT NULL, password FROM users -- HTTP/1.1\r\nHost: target.local\r\n"
    
    # 2. Preprocess payload to 1024 floats
    processor = PayloadProcessor(target_len=1024)
    norm_payload = processor.preprocess_payload(raw_payload)
    assert norm_payload.shape == (1024,)

    # 3. Model Inference
    model = CNNBiLSTM_IDS(input_size=1024, num_classes=len(config.CIC_IOT_CLASSES))
    model.eval()

    x_tensor = torch.tensor(norm_payload, dtype=torch.float32).unsqueeze(0)
    with torch.no_grad():
        logits = model(x_tensor)
        probs = torch.softmax(logits, dim=1).numpy()[0]
        pred_class = int(np.argmax(probs))

    assert len(probs) == len(config.CIC_IOT_CLASSES)
    assert 0 <= pred_class < len(config.CIC_IOT_CLASSES)

    # 4. SHAP Explainer
    bg_data = np.zeros((10, 1024), dtype=np.float32)
    explainer = PyTorchIDSShapExplainer(model, background_data=bg_data)
    shap_res = explainer.explain_payload(norm_payload, top_k=5)

    assert "byte_shap_scores" in shap_res
    assert len(shap_res["byte_shap_scores"]) == 1024
    assert len(shap_res["top_contributing_bytes"]) == 5
