import torch
import torch.nn as nn
import torch.optim as optim
import random
import numpy as np
from collections import deque
from config import GAMMA, EPS_START, EPS_END, EPS_DECAY, LEARNING_RATE, MEMORY_SIZE, BATCH_SIZE, DEVICE

class DQNAgent:
    """
    DQN Agent with LSTM-DQN model in PyTorch.
    """
    def __init__(self, state_size, action_size, model_builder):
        self.state_size = state_size
        self.action_size = action_size
        self.memory = deque(maxlen=MEMORY_SIZE)
        self.gamma = GAMMA
        self.epsilon = EPS_START
        self.epsilon_min = EPS_END
        self.epsilon_decay = EPS_DECAY
        
        # Build models and move to device
        self.model = model_builder(state_size, action_size).to(DEVICE)
        self.target_model = model_builder(state_size, action_size).to(DEVICE)
        self.optimizer = optim.Adam(self.model.parameters(), lr=LEARNING_RATE)
        self.criterion = nn.MSELoss()
        
        self.update_target_model()
        
    def update_target_model(self):
        """
        Copy model weights to target network.
        """
        self.target_model.load_state_dict(self.model.state_dict())
        
    def act(self, state):
        """
        Choose action using epsilon-greedy policy.
        """
        if np.random.rand() <= self.epsilon:
            return random.randrange(self.action_size)
        
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(DEVICE)
        self.model.eval()
        with torch.no_grad():
            act_values = self.model(state_tensor)
        self.model.train()
        
        return torch.argmax(act_values).item()
    
    def remember(self, state, action, reward, next_state, done):
        """
        Store transition in memory.
        """
        self.memory.append((state, action, reward, next_state, float(done)))
        
    def replay(self, batch_size):
        """
        Train the model using experience replay.
        """
        if len(self.memory) < batch_size:
            return
            
        minibatch = random.sample(self.memory, batch_size)
        
        states, actions, rewards, next_states, dones = zip(*minibatch)
        
        states = torch.FloatTensor(np.array(states)).to(DEVICE)
        actions = torch.LongTensor(actions).unsqueeze(1).to(DEVICE)
        rewards = torch.FloatTensor(rewards).unsqueeze(1).to(DEVICE)
        next_states = torch.FloatTensor(np.array(next_states)).to(DEVICE)
        dones = torch.FloatTensor(dones).unsqueeze(1).to(DEVICE)
        
        # Get Q values for current states
        q_values = self.model(states).gather(1, actions)
        
        # Get target Q values for next states from target model
        with torch.no_grad():
            next_q_values = self.target_model(next_states).max(1)[0].unsqueeze(1)
            target_q_values = rewards + (self.gamma * next_q_values * (1 - dones))
            
        # Optimize the model
        loss = self.criterion(q_values, target_q_values)
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # Epsilon decay
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        return loss.item()

    def save_model(self, path):
        """
        Save the model state dictionary.
        """
        torch.save(self.model.state_dict(), path)

    def load_model(self, path):
        """
        Load the model state dictionary.
        """
        self.model.load_state_dict(torch.load(path, map_location=DEVICE, weights_only=False))
        self.update_target_model()
