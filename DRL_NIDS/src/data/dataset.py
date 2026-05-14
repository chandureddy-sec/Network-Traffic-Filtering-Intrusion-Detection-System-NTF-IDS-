import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from config import ZERO_DAY_ATTACKS, DATA_PATH

def preprocess_data(df):
    """
    Remove irrelevant columns, handle missing values, and normalize features.
    """
    # Define common columns to drop (IP addresses, Ports, etc. if needed)
    drop_cols = ["ipv4_src_addr", "ipv4_dst_addr", "l4_src_port", "l4_dst_port"]
    drop_cols = [col for col in drop_cols if col in df.columns]
    df.drop(columns=drop_cols, inplace=True)
    
    # Handle missing values
    df.fillna(0, inplace=True)
    
    # Extract features and labels
    # Assumed labels: 'Label' (0: Benign, 1: Attack), 'Attack' (specific category)
    if 'Attack' not in df.columns and 'Label' not in df.columns:
        df['Attack'] = "Unknown"
        df['Label'] = 0
    elif 'Label' not in df.columns:
        # Fallback if the dataset has 'Attack' instead
        df['Label'] = df['Attack'].apply(lambda x: 0 if x == 'Benign' else 1)
        
    features = df.drop(columns=['Label', 'Attack']) if 'Attack' in df.columns else df.drop(columns=['Label'])
    labels = df['Label']
    
    # Ensure all remaining features are purely numeric to prevent Scaler string-to-float crashes
    features = features.apply(pd.to_numeric, errors='coerce')
    features.fillna(0, inplace=True)
    
    # Normalize features
    scaler = StandardScaler()
    features_normalized = scaler.fit_transform(features)
    
    return features_normalized, labels, df['Attack'] if 'Attack' in df.columns else None

def split_zero_day(data_path=DATA_PATH):
    """
    Load dataset and split into train (standard) and test (including zero-day).
    """
    df = pd.read_csv(data_path)
    
    # Separate Zero-Day attacks
    zero_day_mask = df['Attack'].isin(ZERO_DAY_ATTACKS)
    zero_day_data = df[zero_day_mask]
    remaining_data = df[~zero_day_mask]
    
    # Preprocess both
    train_features, train_labels, _ = preprocess_data(remaining_data)
    test_features, test_labels, test_attacks = preprocess_data(pd.concat([remaining_data.sample(frac=0.2), zero_day_data]))
    
    return train_features, train_labels, test_features, test_labels, test_attacks
