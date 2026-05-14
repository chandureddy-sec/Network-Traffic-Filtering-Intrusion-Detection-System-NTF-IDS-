import pandas as pd
import joblib
import time
import sys

def simulate_network_scanning():
    print("="*70)
    print("   ZERO-DAY NETWORK INTRUSION DETECTION SYSTEM (PRE-TRAINED DEMO)")
    print("="*70)
    
    # 1. Load the pre-trained model
    print("\n[INIT] Loading pre-trained NIDS anomaly model weights (pretrained_model.pkl)...")
    try:
        model = joblib.load('pretrained_model.pkl')
        print("[SUCCESS] Model loaded instantly. Ready for inference.\n")
    except Exception as e:
        print(f"[ERROR] Could not load model: {e}")
        return

    # 2. Load the network traffic dataset
    print("[INIT] Loading incoming network traffic buffer (test_traffic.csv)...")
    try:
        df = pd.read_csv('test_traffic.csv')
        print(f"[SUCCESS] Intercepted {len(df)} incoming network connection packets.\n")
    except Exception as e:
        print(f"[ERROR] Could not load traffic: {e}")
        return

    print("="*70)
    print("                 LIVE NETWORK DEEP-PACKET INSPECTION ")
    print("="*70)
    
    # 3. Simulate real-time scanning
    # If the CSV has a 'label' column, we use it just to show what the packet actually is.
    # The model NEVER sees the label during inference.
    features = df.drop('label', axis=1, errors='ignore').values
    actual_labels = df['label'].values if 'label' in df else ['Unknown']*len(df)
    
    attacks_detected = 0
    
    for i in range(len(features)):
        print(f"Scanning Packet #{i+1:03d} [Type: {actual_labels[i]:>10}] ... ", end="")
        sys.stdout.flush()
        time.sleep(0.05) # Simulate processing time for presentation effect
        
        # Inference using pre-trained model
        prediction = model.predict([features[i]])[0] 
        
        if prediction == 1:
            attacks_detected += 1
            print("[X] ALARM: MALICIOUS ANOMALY DETECTED!")
        else:
            print("[+] SAFE: NORMAL TRAFFIC")

    print("\n" + "="*70)
    print(f" SCAN COMPLETE. Total Packets: {len(df)} | Attacks Blocked: {attacks_detected}")
    print("="*70)

if __name__ == "__main__":
    simulate_network_scanning()
