import os
import sys
import json
import torch
import numpy as np
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from preprocessing.dataset_loader import CICIoT2023DatasetLoader
from models.cnn_bilstm import CNNBiLSTM_IDS
from training.metrics import IDSMetricsCalculator


def evaluate_model(
    model_path: Path = config.SAVED_MODEL_PATH,
    output_path: Path = config.METRICS_REPORT_PATH
) -> Dict[str, Any]:
    """
    Evaluates the saved PyTorch model on the held-out test dataset.
    Generates actual performance metrics and saves report JSON.
    """
    print("=" * 60)
    print("      EVALUATING TRAINED IDS MODEL ON TEST DATASET      ")
    print("=" * 60)

    if not Path(model_path).exists():
        raise FileNotFoundError(f"Model checkpoint not found at: {model_path}. Train the model first.")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Load test dataset
    loader = CICIoT2023DatasetLoader()
    data = loader.load_dataset()
    X_test, y_test = data["X_test"], data["y_test"]
    classes = data["classes"]

    # Load model checkpoint
    checkpoint = torch.load(model_path, map_location=device)
    num_classes = checkpoint.get("num_classes", len(classes))

    model = CNNBiLSTM_IDS(
        input_size=config.PAYLOAD_SIZE,
        num_classes=num_classes,
        cnn_filters=config.CNN_FILTERS,
        cnn_kernel_size=config.CNN_KERNEL_SIZE,
        lstm_hidden_size=config.LSTM_HIDDEN_SIZE,
        lstm_num_layers=config.LSTM_NUM_LAYERS,
        dropout_rate=config.DROPOUT_RATE
    ).to(device)

    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    # Predict on test set
    X_tensor = torch.tensor(X_test, dtype=torch.float32).to(device)
    with torch.no_grad():
        logits = model(X_tensor)
        preds = torch.argmax(logits, dim=1).cpu().numpy()

    # Compute actual metrics
    metrics = IDSMetricsCalculator.compute_all_metrics(
        y_true=y_test,
        y_pred=preds,
        classes=classes
    )

    print(f"[+] Test Multiclass Accuracy: {metrics['multiclass']['accuracy'] * 100:.2f}%")
    print(f"[+] Test Binary Accuracy:     {metrics['binary']['accuracy'] * 100:.2f}%")
    print(f"[+] Test Multiclass F1-Score: {metrics['multiclass']['f1_macro']:.4f}")

    # Save metrics report JSON
    with open(output_path, "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"[+] Evaluation metrics saved to: {output_path}")
    return metrics


if __name__ == "__main__":
    evaluate_model()
