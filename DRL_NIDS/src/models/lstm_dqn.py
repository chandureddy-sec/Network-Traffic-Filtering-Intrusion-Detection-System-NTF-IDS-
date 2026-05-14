import torch
import torch.nn as nn
from config import LSTM_UNITS, DROPOUT_RATE

class LSTMDQN(nn.Module):
    """
    LSTM-DQN model architecture in PyTorch.
    Reflects the 3 stacked LSTM layers and Dense output layers.
    """
    def __init__(self, input_dim, output_dim):
        super(LSTMDQN, self).__init__()
        
        # Initial Dense layer to create features for LSTM
        self.fc1 = nn.Linear(input_dim, 64)
        self.dropout = nn.Dropout(DROPOUT_RATE)
        
        # 3 Stacked LSTM layers 
        # input shape: (batch, seq_len, input_size)
        self.lstm = nn.LSTM(input_size=64, hidden_size=LSTM_UNITS, num_layers=3, batch_first=True, dropout=DROPOUT_RATE)
        
        # Final Dense layers
        self.fc2 = nn.Linear(LSTM_UNITS, 128)
        self.fc3 = nn.Linear(128, output_dim)
        
        self.relu = nn.ReLU()
        # Softmax is often handled by the Loss function (CrossEntropy) or added manually for action probabilities
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x):
        # x shape: (batch, input_dim)
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        
        # Reshape for LSTM: (batch, 1, 64)
        x = x.unsqueeze(1)
        
        # LSTM layers
        lstm_out, _ = self.lstm(x)
        
        # Take the output of the last time step
        x = lstm_out[:, -1, :]
        
        x = self.relu(self.fc2(x))
        x = self.softmax(self.fc3(x))
        
        return x

def build_lstm_dqn(input_dim, output_dim):
    """
    Factory function for consistency with previously planned structure.
    """
    return LSTMDQN(input_dim, output_dim)
