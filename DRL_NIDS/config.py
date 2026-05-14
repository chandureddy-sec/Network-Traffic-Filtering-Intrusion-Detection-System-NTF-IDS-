import os

try:
    import torch
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    TORCH_INITIALIZED = True
except Exception:
    DEVICE = "cpu"
    TORCH_INITIALIZED = False

# Dataset paths
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'NF-BoT-IoT.csv')
ZERO_DAY_ATTACKS = ["DoS", "Backdoor"]

# RL Hyperparameters
GAMMA = 0.95
EPS_START = 1.0
EPS_END = 0.05
EPS_DECAY = 0.999
LEARNING_RATE = 0.0005
MEMORY_SIZE = 50000
BATCH_SIZE = 128
TARGET_UPDATE = 20

# LSTM Hyperparameters
LSTM_UNITS = 64
DROPOUT_RATE = 0.2
SEQUENCE_LENGTH = 1

# Environment settings
REWARD_CORRECT = 1.0
REWARD_INCORRECT = -1.0

# PyTorch Settings
MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), 'models', 'lstm_dqn.pth')
