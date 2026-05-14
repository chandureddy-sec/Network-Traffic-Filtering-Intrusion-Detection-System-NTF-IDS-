import gymnasium as gym
from gymnasium import spaces
import numpy as np
from config import REWARD_CORRECT, REWARD_INCORRECT

class NIDSEnv(gym.Env):
    """
    A custom Gymnasium environment for NIDS training.
    """
    def __init__(self, features, labels):
        super(NIDSEnv, self).__init__()
        self.features = features
        self.labels = labels
        self.current_step = 0
        self.num_samples = len(features)
        
        # Observation space: Traffic features
        self.observation_space = spaces.Box(low=-np.inf, high=np.inf, shape=(features.shape[1],), dtype=np.float32)
        
        # Action space: 0 (Normal), 1 (Attack)
        self.action_space = spaces.Discrete(2)
        
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = np.random.randint(0, self.num_samples)
        observation = self.features[self.current_step].astype(np.float32)
        return observation, {}
    
    def step(self, action):
        # Determine reward
        correct_action = self.labels[self.current_step]
        reward = REWARD_CORRECT if action == correct_action else REWARD_INCORRECT
        
        # Next sample
        self.current_step = (self.current_step + 1) % self.num_samples
        next_observation = self.features[self.current_step].astype(np.float32)
        
        # This is a one-step environment for each packet classification
        done = True  # Each packet classification is an episode
        truncated = False
        
        return next_observation, reward, done, truncated, {}
