import os
import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from typing import Dict, Any

import config
from preprocessing.dataset_loader import CICIoT2023DatasetLoader
from models.cnn_bilstm import CNNBiLSTM_IDS


def train_model(
    epochs: int = config.EPOCHS,
    batch_size: int = config.BATCH_SIZE,
    lr: float = config.LEARNING_RATE
) -> Dict[str, Any]:
    """
    Executes the PyTorch 1D-CNN + BiLSTM training pipeline.
    
    Returns:
        Dict containing training history and model performance summary.
    """
    print("=" * 60)
    print("      STARTING IDS MODEL TRAINING (PyTorch 1D-CNN + BiLSTM)      ")
    print("=" * 60)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training Device: {device}")

    # 1. Load Dataset
    loader = CICIoT2023DatasetLoader()
    data = loader.load_dataset()

    X_train, y_train = data["X_train"], data["y_train"]
    X_val, y_val = data["X_val"], data["y_val"]
    classes = data["classes"]
    num_classes = len(classes)

    print(f"[*] Training Samples: {X_train.shape[0]} | Validation Samples: {X_val.shape[0]} | Classes: {num_classes}")

    # Convert to PyTorch Tensors & DataLoaders
    train_dataset = TensorDataset(torch.tensor(X_train, dtype=torch.float32), torch.tensor(y_train, dtype=torch.long))
    val_dataset = TensorDataset(torch.tensor(X_val, dtype=torch.float32), torch.tensor(y_val, dtype=torch.long))

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    # 2. Instantiate Model, Loss & Optimizer
    model = CNNBiLSTM_IDS(
        input_size=config.PAYLOAD_SIZE,
        num_classes=num_classes,
        cnn_filters=config.CNN_FILTERS,
        cnn_kernel_size=config.CNN_KERNEL_SIZE,
        lstm_hidden_size=config.LSTM_HIDDEN_SIZE,
        lstm_num_layers=config.LSTM_NUM_LAYERS,
        dropout_rate=config.DROPOUT_RATE
    ).to(device)

    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)

    best_val_loss = float("inf")
    history = {
        "train_loss": [], "train_acc": [],
        "val_loss": [], "val_acc": [],
        "epochs": epochs
    }

    start_time = time.time()

    # 3. Epoch Loop
    for epoch in range(1, epochs + 1):
        # Training Phase
        model.train()
        running_loss = 0.0
        correct = 0
        total = 0

        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)

            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

            running_loss += loss.item() * batch_x.size(0)
            preds = torch.argmax(outputs, dim=1)
            correct += (preds == batch_y).sum().item()
            total += batch_y.size(0)

        epoch_train_loss = running_loss / total
        epoch_train_acc = correct / total

        # Validation Phase
        model.eval()
        val_running_loss = 0.0
        val_correct = 0
        val_total = 0

        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)

                outputs = model(batch_x)
                loss = criterion(outputs, batch_y)

                val_running_loss += loss.item() * batch_x.size(0)
                preds = torch.argmax(outputs, dim=1)
                val_correct += (preds == batch_y).sum().item()
                val_total += batch_y.size(0)

        epoch_val_loss = val_running_loss / val_total
        epoch_val_acc = val_correct / val_total

        history["train_loss"].append(round(epoch_train_loss, 4))
        history["train_acc"].append(round(epoch_train_acc, 4))
        history["val_loss"].append(round(epoch_val_loss, 4))
        history["val_acc"].append(round(epoch_val_acc, 4))

        print(
            f"Epoch [{epoch:02d}/{epochs:02d}] "
            f"Train Loss: {epoch_train_loss:.4f} | Train Acc: {epoch_train_acc * 100:.2f}% | "
            f"Val Loss: {epoch_val_loss:.4f} | Val Acc: {epoch_val_acc * 100:.2f}%"
        )

        # Checkpoint Best Model
        if epoch_val_loss < best_val_loss:
            best_val_loss = epoch_val_loss
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_loss": epoch_val_loss,
                "val_acc": epoch_val_acc,
                "num_classes": num_classes,
                "classes": classes
            }, config.SAVED_MODEL_PATH)
            print(f"  [+] Saved best model checkpoint to {config.SAVED_MODEL_PATH}")

    total_time = round(time.time() - start_time, 2)
    history["training_time_seconds"] = total_time

    # Save History JSON
    with open(config.TRAINING_HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=4)

    print(f"\n[+] Training completed in {total_time}s. Best Val Loss: {best_val_loss:.4f}")
    return history


if __name__ == "__main__":
    train_model()
