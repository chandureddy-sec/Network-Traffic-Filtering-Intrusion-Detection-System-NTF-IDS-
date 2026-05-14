import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from src.data.dataset import split_zero_day
from src.models.lstm_dqn import build_lstm_dqn
from config import MODEL_SAVE_PATH, DEVICE, ZERO_DAY_ATTACKS

def evaluate():
    """
    Load trained PyTorch model and evaluate on test set.
    """
    # 1. Load Data
    _, _, test_f, test_l, test_a = split_zero_day()
    
    # 2. Build and Load Model
    input_dim = test_f.shape[1]
    model = build_lstm_dqn(input_dim, 2).to(DEVICE)
    model.load_state_dict(torch.load(MODEL_SAVE_PATH, map_location=DEVICE))
    model.eval()
    
    # 3. Predict
    test_tensor = torch.FloatTensor(test_f).to(DEVICE)
    with torch.no_grad():
        predictions = model(test_tensor)
        predicted_labels = torch.argmax(predictions, dim=1).cpu().numpy()
    
    # 4. Filter for Zero-Day attacks
    zero_day_mask = test_a.isin(ZERO_DAY_ATTACKS)
    
    # Calculate Overall Metrics
    accuracy = accuracy_score(test_l, predicted_labels)
    precision = precision_score(test_l, predicted_labels)
    recall = recall_score(test_l, predicted_labels)
    f1 = f1_score(test_l, predicted_labels)
    
    # Calculate Zero-Day Specific Metrics
    zero_day_accuracy = accuracy_score(test_l[zero_day_mask], predicted_labels[zero_day_mask])
    
    print("\nOverall Performance (PyTorch Model):")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-score: {f1:.4f}")
    
    print("\nZero-Day Attack Performance:")
    print(f"Accuracy on Zero-Day Samples: {zero_day_accuracy:.4f}")
    
    # 5. Visualization: Confusion Matrix
    cm = confusion_matrix(test_l, predicted_labels)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
    plt.title('Confusion Matrix - Adaptive NIDS')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig('d:/zero day attacks/DRL_NIDS/confusion_matrix.png')
    print("\nConfusion matrix saved as confusion_matrix.png")

if __name__ == "__main__":
    evaluate()
