from imblearn.over_sampling import KMeansSMOTE
import pandas as pd
import numpy as np

def balance_training_data(features, labels):
    """
    Apply KMeans-SMOTE to balance training data.
    """
    # Balance features and labels
    sm = KMeansSMOTE(random_state=42)
    features_resampled, labels_resampled = sm.fit_resample(features, labels)
    
    return features_resampled, labels_resampled
