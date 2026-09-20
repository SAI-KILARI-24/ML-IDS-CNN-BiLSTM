import numpy as np
import pandas as pd
from typing import Dict, Any, List
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)


class IDSMetricsCalculator:
    """
    Computes rigorous Multiclass and Binary evaluation metrics for PyTorch IDS evaluation.
    """

    @staticmethod
    def compute_all_metrics(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        classes: List[str]
    ) -> Dict[str, Any]:
        """
        Calculates accuracy, per-class precision/recall/F1/support, macro/weighted averages,
        confusion matrix, and binary (Benign vs Attack) metrics.
        """
        # Overall Accuracy
        acc = float(accuracy_score(y_true, y_pred))

        # Multiclass Per-class and Aggregate Metrics
        p_class, r_class, f1_class, supp_class = precision_recall_fscore_support(
            y_true, y_pred, labels=list(range(len(classes))), zero_division=0
        )
        p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
            y_true, y_pred, average="macro", zero_division=0
        )
        p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(
            y_true, y_pred, average="weighted", zero_division=0
        )

        cm = confusion_matrix(y_true, y_pred, labels=list(range(len(classes))))

        # Class-wise Metrics Dictionary
        per_class_metrics = {}
        for i, class_name in enumerate(classes):
            per_class_metrics[class_name] = {
                "precision": round(float(p_class[i]), 4),
                "recall": round(float(r_class[i]), 4),
                "f1_score": round(float(f1_class[i]), 4),
                "support": int(supp_class[i])
            }

        # Binary Metrics (Benign vs Attack)
        # Identify index of 'BenignTraffic' or class containing 'benign'
        benign_indices = [i for i, c in enumerate(classes) if 'benign' in c.lower()]
        benign_idx = benign_indices[0] if benign_indices else 0

        y_true_binary = np.where(y_true == benign_idx, 0, 1)  # 0 = Benign, 1 = Attack
        y_pred_binary = np.where(y_pred == benign_idx, 0, 1)

        bin_acc = float(accuracy_score(y_true_binary, y_pred_binary))
        bin_p, bin_r, bin_f1, _ = precision_recall_fscore_support(
            y_true_binary, y_pred_binary, average="binary", zero_division=0
        )
        bin_cm = confusion_matrix(y_true_binary, y_pred_binary, labels=[0, 1])

        return {
            "multiclass": {
                "accuracy": round(acc, 4),
                "precision_macro": round(float(p_macro), 4),
                "recall_macro": round(float(r_macro), 4),
                "f1_macro": round(float(f1_macro), 4),
                "precision_weighted": round(float(p_weighted), 4),
                "recall_weighted": round(float(r_weighted), 4),
                "f1_weighted": round(float(f1_weighted), 4),
                "confusion_matrix": cm.tolist(),
                "classes": classes,
                "per_class": per_class_metrics
            },
            "binary": {
                "accuracy": round(bin_acc, 4),
                "precision": round(float(bin_p), 4),
                "recall": round(float(bin_r), 4),
                "f1_score": round(float(bin_f1), 4),
                "confusion_matrix": bin_cm.tolist(),
                "tn": int(bin_cm[0, 0]),
                "fp": int(bin_cm[0, 1]),
                "fn": int(bin_cm[1, 0]),
                "tp": int(bin_cm[1, 1])
            }
        }
