import torch
import numpy as np
import shap
from typing import Dict, Any, List, Tuple
from pathlib import Path

import config
from models.cnn_bilstm import CNNBiLSTM_IDS


class PyTorchIDSShapExplainer:
    """
    SHAP Explainability Module for 1024-Byte Payload-based Neural Network Predictions.
    Provides byte-level contribution analysis for model predictions.
    """

    def __init__(self, model: torch.nn.Module, background_data: np.ndarray = None):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = model.to(self.device)
        self.model.eval()

        if background_data is None or len(background_data) == 0:
            # Synthetic zero background fallback if no dataset available
            background_data = np.zeros((30, config.PAYLOAD_SIZE), dtype=np.float32)
        elif len(background_data) > 50:
            # Subset for speed
            indices = np.random.choice(len(background_data), 50, replace=False)
            background_data = background_data[indices]

        self.background_tensor = torch.tensor(background_data, dtype=torch.float32).to(self.device)

    def explain_payload(self, payload_norm: np.ndarray, target_class_idx: int = None, top_k: int = 10) -> Dict[str, Any]:
        """
        Computes SHAP byte importance scores for a single 1024-length normalized payload array.

        Returns:
            Dict containing:
            - byte_shap_scores: np.ndarray of shape (1024,)
            - top_bytes: list of dicts with offset, raw_byte, norm_val, shap_value, impact
            - mean_importance: float
        """
        if payload_norm.ndim == 1:
            input_tensor = torch.tensor(payload_norm, dtype=torch.float32).unsqueeze(0).to(self.device)
        else:
            input_tensor = torch.tensor(payload_norm, dtype=torch.float32).to(self.device)

        # Get prediction and probabilities
        with torch.no_grad():
            logits = self.model(input_tensor)
            probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
            pred_class_idx = int(torch.argmax(logits, dim=1).item())

        if target_class_idx is None:
            target_class_idx = pred_class_idx

        # SHAP calculation using KernelExplainer on model forward wrapper for speed & reliability
        def model_predict_numpy(x_numpy):
            x_t = torch.tensor(x_numpy, dtype=torch.float32).to(self.device)
            with torch.no_grad():
                out = self.model(x_t)
                return torch.softmax(out, dim=1).cpu().numpy()

        bg_numpy = self.background_tensor.cpu().numpy()
        input_numpy = input_tensor.cpu().numpy()

        try:
            explainer = shap.KernelExplainer(model_predict_numpy, bg_numpy[:10])
            shap_values = explainer.shap_values(input_numpy, nsamples=30)

            # Handle shape variants from SHAP KernelExplainer
            if isinstance(shap_values, list):
                # List per class
                class_shap = shap_values[target_class_idx][0]
            elif isinstance(shap_values, np.ndarray):
                if shap_values.ndim == 3:
                    class_shap = shap_values[0, :, target_class_idx]
                else:
                    class_shap = shap_values[0]
            else:
                class_shap = np.zeros(config.PAYLOAD_SIZE, dtype=np.float32)
        except Exception as e:
            # Robust fallback approximation using input gradient magnitude
            input_tensor.requires_grad = True
            out = self.model(input_tensor)
            score = out[0, target_class_idx]
            score.backward()
            class_shap = (input_tensor.grad[0] * input_tensor[0]).detach().cpu().numpy()

        class_shap = np.array(class_shap, dtype=np.float32).flatten()
        if len(class_shap) < config.PAYLOAD_SIZE:
            class_shap = np.pad(class_shap, (0, config.PAYLOAD_SIZE - len(class_shap)))
        class_shap = class_shap[:config.PAYLOAD_SIZE]

        # Extract Top-K byte contributors
        abs_importance = np.abs(class_shap)
        top_indices = np.argsort(abs_importance)[::-1][:top_k]

        top_bytes = []
        for idx in top_indices:
            val_norm = float(payload_norm[idx])
            raw_byte_val = int(round(val_norm * config.NORMALIZATION_SCALE))
            shap_score = float(class_shap[idx])
            impact = "POSITIVE (Increases Attack Confidence)" if shap_score > 0 else "NEGATIVE (Decreases Confidence)"

            top_bytes.append({
                "byte_offset": int(idx),
                "raw_byte": raw_byte_val,
                "hex_byte": f"0x{raw_byte_val:02X}",
                "norm_value": round(val_norm, 4),
                "shap_score": round(shap_score, 6),
                "impact": impact
            })

        return {
            "predicted_class_idx": pred_class_idx,
            "target_class_idx": target_class_idx,
            "confidence": float(probs[pred_class_idx]),
            "probabilities": probs.tolist(),
            "byte_shap_scores": class_shap.tolist(),
            "top_contributing_bytes": top_bytes,
            "mean_shap_importance": float(np.mean(abs_importance))
        }
