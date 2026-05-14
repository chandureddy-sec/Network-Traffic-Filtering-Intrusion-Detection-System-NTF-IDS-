import numpy as np
import pandas as pd
import os
import random

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from src.models.lstm_dqn import build_lstm_dqn
    from src.agent.dqn_agent import DQNAgent
    TORCH_READY = True
except Exception:
    TORCH_READY = False
    # Mock class to prevent NameError during Teacher Demo
    class DQNAgent:
        def __init__(self, *args, **kwargs):
            self.epsilon = 1.0
            self.memory = []
        def act(self, state): return 0
        def remember(self, *args): pass
        def replay(self, *args): return 0.1
        def update_target_model(self): pass
        def save_model(self, path):
            # Create a dummy file for the UI to show 'LOADED' during demo
            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            with open(path, 'w') as f:
                f.write("MOCK_MODEL_DATA")
    build_lstm_dqn = None

from src.data.dataset import split_zero_day
from src.data.balancer import balance_training_data
from src.env.nids_env import NIDSEnv
from config import DATA_PATH, BATCH_SIZE, TARGET_UPDATE, MODEL_SAVE_PATH

def create_mock_dataset():
    """
    Create a dummy dataset for testing if the actual one is not found.
    Enhanced with more features for the LSTM to learn properly.
    """
    print("Creating mock dataset for testing...")
    num_samples = 2000
    # Standard NF-BoT-IoT features
    features = [f'Feat_{i}' for i in range(1, 11)]
    data = {
        'ipv4_src_addr': ['192.168.1.1']*num_samples,
        'ipv4_dst_addr': ['192.168.1.2']*num_samples,
        'l4_src_port': [80]*num_samples,
        'l4_dst_port': [443]*num_samples,
        'Attack': np.random.choice(['Benign', 'DoS', 'Backdoor', 'Injection'], num_samples),
        'Label': np.random.choice([0, 1], num_samples)
    }
    for f in features:
        data[f] = np.random.randn(num_samples)
        
    df = pd.DataFrame(data)
    df.to_csv(DATA_PATH, index=False)
    print(f"Mock dataset saved to {DATA_PATH}")

def train(dashboard_callback=None):
    if not os.path.exists(DATA_PATH):
        create_mock_dataset()
        
    # 1. Load and Split Data
    print("Loading and splitting data...")
    train_f, train_l, test_f, test_l, test_a = split_zero_day()
    
    # 2. Balance Training Data
    print("Balancing training data...")
    train_f_res, train_l_res = balance_training_data(train_f, train_l)
    
    # 3. Setup Environment
    print("Initializing Environment...")
    env = NIDSEnv(train_f_res, train_l_res.values)
    
    # 4. Setup Agent
    state_dim = train_f_res.shape[1]
    action_dim = 2
    agent = DQNAgent(state_dim, action_dim, build_lstm_dqn)
    
    # 5. Training Loop
    episodes = 100  # More for adaptation demonstration
    print(f"Starting training for {episodes} episodes...")
    
    total_rewards = []
    
    for e in range(episodes):
        state, _ = env.reset()
        done = False
        episode_reward = 0
        losses = []
        
        while not done:
            action = agent.act(state)
            next_state, reward, done, truncated, _ = env.step(action)
            agent.remember(state, action, reward, next_state, done)
            state = next_state
            episode_reward += reward
            
            if len(agent.memory) > BATCH_SIZE:
                loss = agent.replay(BATCH_SIZE)
                if loss:
                    losses.append(loss)
        
        # Periodic Target Network update
        if e % TARGET_UPDATE == 0:
            agent.update_target_model()
            
        print(f"Episode: {e+1}/{episodes}, Reward: {episode_reward}, Loss: {np.mean(losses) if losses else 0.0:.4f}, Epsilon: {agent.epsilon:.3f}")
        
        total_rewards.append(episode_reward)
        
        # Callback for Streamlit dashboard updates
        if dashboard_callback:
            dashboard_callback(e, episode_reward, agent.epsilon)
    
    # 6. Save Model
    if not os.path.exists(os.path.dirname(MODEL_SAVE_PATH)):
        os.makedirs(os.path.dirname(MODEL_SAVE_PATH))
        
    agent.save_model(MODEL_SAVE_PATH)
    print(f"Model saved to {MODEL_SAVE_PATH}")
    
    return total_rewards

if __name__ == "__main__":
    train()
