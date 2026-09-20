import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import tensorflow as tf

# Ensure project root directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

LABEL_NAMES = ["Benign", "DDoS", "DoS", "Reconnaissance", "Spoofing"]

def evaluate_ids_model():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dataset_dir = os.path.join(base_dir, "dataset")
    model_path = os.path.join(base_dir, "saved_models", "cnn_bilstm_ids.keras")
    eval_dir = os.path.join(base_dir, "evaluation")
    
    os.makedirs(eval_dir, exist_ok=True)
    
    # 1. Load Test Split Data
    print("=== Loading Unseen Testing Dataset ===")
    X_test = np.load(os.path.join(dataset_dir, "X_test.npy"))
    y_test = np.load(os.path.join(dataset_dir, "y_test.npy"))
    
    # Reshape for 1D-CNN: (N, 1024, 1)
    X_test = np.expand_dims(X_test, axis=-1)
    print(f"X_test Shape: {X_test.shape} | y_test Shape: {y_test.shape}\n")
    
    # 2. Load Trained Model Weights
    if not os.path.exists(model_path):
        print(f"[ERROR] Trained model file not found at: {model_path}")
        return
        
    print(f"=== Loading Model from: {model_path} ===")
    model = tf.keras.models.load_model(model_path)
    
    # 3. Predict Class Probabilities on Test Data
    y_probs = model.predict(X_test, verbose=0)
    y_pred = np.argmax(y_probs, axis=1)
    
    # 4. Compute Evaluation Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted")
    rec = recall_score(y_test, y_pred, average="weighted")
    f1 = f1_score(y_test, y_pred, average="weighted")
    
    print("\n==================================================")
    print("           MODEL EVALUATION RESULTS               ")
    print("==================================================")
    print(f"  Overall Accuracy : {acc * 100:.2f}%")
    print(f"  Weighted Precision: {prec * 100:.2f}%")
    print(f"  Weighted Recall   : {rec * 100:.2f}%")
    print(f"  Weighted F1-Score : {f1 * 100:.2f}%")
    print("==================================================\n")
    
    print("--- Detailed Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES, digits=4))
    
    # 5. Compute and Save Confusion Matrix Plot
    cm = confusion_matrix(y_test, y_pred)
    print("--- Confusion Matrix Array ---")
    print(cm)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=LABEL_NAMES, yticklabels=LABEL_NAMES)
    plt.title("1D-CNN + BiLSTM IDS Confusion Matrix")
    plt.xlabel("Predicted Traffic Class")
    plt.ylabel("Actual True Traffic Class")
    plt.tight_layout()
    
    cm_plot_path = os.path.join(eval_dir, "confusion_matrix.png")
    plt.savefig(cm_plot_path, dpi=300)
    plt.close()
    
    print(f"\n[SUCCESS] Confusion Matrix saved to: {cm_plot_path}")

if __name__ == "__main__":
    evaluate_ids_model()
