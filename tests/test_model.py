import pytest
import torch
import numpy as np

import config
from models.cnn_bilstm import CNNBiLSTM_IDS


def test_cnn_bilstm_architecture_and_forward():
    batch_size = 8
    seq_len = 1024
    num_classes = 8

    model = CNNBiLSTM_IDS(
        input_size=seq_len,
        num_classes=num_classes,
        cnn_filters=32,
        lstm_hidden_size=32
    )
    model.eval()

    # 1. 2D Tensor Input (N, 1024)
    x_2d = torch.rand((batch_size, seq_len), dtype=torch.float32)
    logits_2d = model(x_2d)
    assert logits_2d.shape == (batch_size, num_classes)

    # 2. 3D Tensor Input (N, 1, 1024)
    x_3d = torch.rand((batch_size, 1, seq_len), dtype=torch.float32)
    logits_3d = model(x_3d)
    assert logits_3d.shape == (batch_size, num_classes)

    # 3. Softmax Probabilities
    probas = model.predict_proba(x_2d)
    assert probas.shape == (batch_size, num_classes)
    prob_sums = torch.sum(probas, dim=1).detach().numpy()
    assert np.allclose(prob_sums, 1.0, atol=1e-5)

    # 4. Argmax Class Predictions
    preds = model.predict(x_2d)
    assert preds.shape == (batch_size,)
    assert torch.all(preds >= 0) and torch.all(preds < num_classes)
