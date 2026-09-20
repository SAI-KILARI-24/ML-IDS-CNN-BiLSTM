import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Dict, Any

import config


class CNNBiLSTM_IDS(nn.Module):
    """
    PyTorch 1D-CNN + BiLSTM Neural Network Architecture for Payload-based Network Intrusion Detection.
    
    Pipeline:
    1024-byte input tensor (N, 1, 1024)
        ↓
    1D-CNN (Spatial feature & n-gram byte extraction)
        ↓
    BiLSTM (Temporal/Sequential byte pattern dependencies)
        ↓
    Dense Fully Connected Layers
        ↓
    Logits / Class Probabilities (N, num_classes)
    """

    def __init__(
        self,
        input_size: int = config.PAYLOAD_SIZE,
        num_classes: int = len(config.CIC_IOT_CLASSES),
        cnn_filters: int = config.CNN_FILTERS,
        cnn_kernel_size: int = config.CNN_KERNEL_SIZE,
        lstm_hidden_size: int = config.LSTM_HIDDEN_SIZE,
        lstm_num_layers: int = config.LSTM_NUM_LAYERS,
        dropout_rate: float = config.DROPOUT_RATE
    ):
        super(CNNBiLSTM_IDS, self).__init__()

        self.input_size = input_size
        self.num_classes = num_classes

        # 1D Conv Layer 1
        self.conv1 = nn.Conv1d(
            in_channels=1,
            out_channels=cnn_filters,
            kernel_size=cnn_kernel_size,
            padding=cnn_kernel_size // 2
        )
        self.bn1 = nn.BatchNorm1d(cnn_filters)
        self.pool1 = nn.MaxPool1d(kernel_size=2)

        # 1D Conv Layer 2
        self.conv2 = nn.Conv1d(
            in_channels=cnn_filters,
            out_channels=cnn_filters * 2,
            kernel_size=cnn_kernel_size,
            padding=cnn_kernel_size // 2
        )
        self.bn2 = nn.BatchNorm1d(cnn_filters * 2)
        self.pool2 = nn.MaxPool1d(kernel_size=2)

        self.dropout = nn.Dropout(p=dropout_rate)

        # BiLSTM Layer
        bilstm_input_dim = cnn_filters * 2
        self.bilstm = nn.LSTM(
            input_size=bilstm_input_dim,
            hidden_size=lstm_hidden_size,
            num_layers=lstm_num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout_rate if lstm_num_layers > 1 else 0.0
        )

        # Classification Dense Head
        fc_input_dim = lstm_hidden_size * 2  # Bidirectional (2 * hidden_size)
        self.fc1 = nn.Linear(fc_input_dim, 128)
        self.bn3 = nn.BatchNorm1d(128)
        self.fc2 = nn.Linear(128, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        Args:
            x: Input tensor of shape (batch_size, 1024) or (batch_size, 1, 1024)
        Returns:
            Logits of shape (batch_size, num_classes)
        """
        if x.dim() == 2:
            x = x.unsqueeze(1)  # Reshape to (N, 1, 1024)

        # Conv Block 1
        x = self.conv1(x)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.pool1(x)

        # Conv Block 2
        x = self.conv2(x)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.pool2(x)
        x = self.dropout(x)

        # Permute for LSTM: (N, C, L) -> (N, L, C)
        x = x.permute(0, 2, 1)

        # BiLSTM Pass
        lstm_out, (h_n, c_n) = self.bilstm(x)

        # Max pooling over time dimension
        out = torch.max(lstm_out, dim=1)[0]  # (N, 2 * hidden_size)

        # Fully Connected Layers
        out = self.fc1(out)
        out = self.bn3(out)
        out = F.relu(out)
        out = self.dropout(out)
        logits = self.fc2(out)

        return logits

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Computes Softmax class probabilities."""
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            return F.softmax(logits, dim=1)

    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """Returns predicted class index (argmax)."""
        probas = self.predict_proba(x)
        return torch.argmax(probas, dim=1)
