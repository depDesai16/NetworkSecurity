"""
Traffic Generator Module
Generates synthetic network traffic with both benign and malicious patterns
"""

import numpy as np
import pandas as pd
import time
from typing import List, Tuple


class TrafficGenerator:
    """Main class for generating synthetic network traffic"""
    
    def __init__(self, seed=42):
        """
        Initialize the traffic generator
        
        Args:
            seed: Random seed for reproducibility
        """
        np.random.seed(seed)
        self.packet_id_counter = 0
    
    def generate_dataset(self, num_samples: int, attack_ratio: float = 0.3) -> pd.DataFrame:
        """
        Generate a complete dataset with both benign and malicious traffic
        
        Args:
            num_samples: Total number of samples to generate
            attack_ratio: Ratio of attack traffic (0.0 to 1.0)
        
        Returns:
            DataFrame containing the generated traffic dataset
        """
        if not 0 <= attack_ratio <= 1:
            raise ValueError("attack_ratio must be between 0 and 1")
        
        num_attacks = int(num_samples * attack_ratio)
        num_benign = num_samples - num_attacks
        
        print(f"Generating {num_samples} samples ({num_benign} benign, {num_attacks} malicious)...")
        
        # Generate benign traffic
        benign_df = self.generate_benign_traffic(num_benign)
        
        # Generate attack traffic
        attack_types = ['dos', 'port_scan', 'unauthorized_access']
        attack_df = self.generate_attack_traffic(num_attacks, attack_types)
        
        # Combine and shuffle
        dataset = pd.concat([benign_df, attack_df], ignore_index=True)
        dataset = dataset.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"Dataset generation complete: {len(dataset)} samples")
        return dataset
    
    def generate_benign_traffic(self, num_samples: int) -> pd.DataFrame:
        """
        Generate benign (normal) network traffic patterns
        
        Args:
            num_samples: Number of benign samples to generate
        
        Returns:
            DataFrame containing benign traffic samples
        """
        samples = []
        base_timestamp = time.time()
        
        for i in range(num_samples):
            sample = self._create_benign_packet(base_timestamp + i * np.random.uniform(0.01, 0.5))
            samples.append(sample)
        
        return pd.DataFrame(samples)
    
    def generate_attack_traffic(self, num_samples: int, attack_types: List[str]) -> pd.DataFrame:
        """
        Generate malicious attack traffic patterns
        
        Args:
            num_samples: Number of attack samples to generate
            attack_types: List of attack types to simulate
        
        Returns:
            DataFrame containing attack traffic samples
        """
        samples = []
        base_timestamp = time.time()
        
        # Distribute samples across attack types
        samples_per_type = num_samples // len(attack_types)
        
        for attack_type in attack_types:
            for i in range(samples_per_type):
                timestamp = base_timestamp + len(samples) * np.random.uniform(0.001, 0.1)
                
                if attack_type == 'dos':
                    sample = self._create_dos_packet(timestamp)
                elif attack_type == 'port_scan':
                    sample = self._create_port_scan_packet(timestamp)
                elif attack_type == 'unauthorized_access':
                    sample = self._create_unauthorized_access_packet(timestamp)
                else:
                    raise ValueError(f"Unknown attack type: {attack_type}")
                
                samples.append(sample)
        
        # Handle remaining samples
        remaining = num_samples - len(samples)
        for i in range(remaining):
            attack_type = np.random.choice(attack_types)
            timestamp = base_timestamp + len(samples) * np.random.uniform(0.001, 0.1)
            
            if attack_type == 'dos':
                sample = self._create_dos_packet(timestamp)
            elif attack_type == 'port_scan':
                sample = self._create_port_scan_packet(timestamp)
            else:
                sample = self._create_unauthorized_access_packet(timestamp)
            
            samples.append(sample)
        
        return pd.DataFrame(samples)
    
    def _create_benign_packet(self, timestamp: float) -> dict:
        """Create a single benign network packet"""
        self.packet_id_counter += 1
        
        return {
            'packet_id': self.packet_id_counter,
            'timestamp': timestamp,
            'src_ip': np.random.randint(1, 255),
            'dst_ip': np.random.randint(1, 255),
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.choice([80, 443, 22, 21, 25, 53]),  # Common ports
            'protocol': np.random.choice([0, 1]),  # TCP or UDP
            'packet_size': np.random.randint(64, 1500),
            'duration': np.random.uniform(0.1, 5.0),
            'syn_flag': np.random.randint(0, 2),
            'ack_flag': np.random.randint(0, 3),
            'fin_flag': np.random.randint(0, 2),
            'failed_logins': 0,
            'packet_rate': np.random.uniform(1, 50),
            'label': 'benign'
        }
    
    def _create_dos_packet(self, timestamp: float) -> dict:
        """Create a DoS attack packet with high packet rate and repeated connections"""
        self.packet_id_counter += 1
        
        return {
            'packet_id': self.packet_id_counter,
            'timestamp': timestamp,
            'src_ip': np.random.randint(1, 50),  # Limited source IPs (botnet)
            'dst_ip': np.random.randint(200, 210),  # Targeting specific servers
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.choice([80, 443]),  # Target web servers
            'protocol': 0,  # TCP
            'packet_size': np.random.randint(40, 100),  # Small packets
            'duration': np.random.uniform(0.001, 0.1),  # Very short duration
            'syn_flag': np.random.randint(5, 20),  # Many SYN flags
            'ack_flag': np.random.randint(0, 2),  # Few ACKs
            'fin_flag': 0,
            'failed_logins': 0,
            'packet_rate': np.random.uniform(500, 2000),  # Very high packet rate
            'label': 'malicious'
        }
    
    def _create_port_scan_packet(self, timestamp: float) -> dict:
        """Create a port scan attack packet with sequential port access"""
        self.packet_id_counter += 1
        
        # Sequential port scanning pattern
        base_port = np.random.randint(1, 60000)
        
        return {
            'packet_id': self.packet_id_counter,
            'timestamp': timestamp,
            'src_ip': np.random.randint(1, 255),
            'dst_ip': np.random.randint(200, 210),  # Scanning specific targets
            'src_port': np.random.randint(1024, 65535),
            'dst_port': base_port + np.random.randint(0, 100),  # Sequential ports
            'protocol': 0,  # TCP
            'packet_size': np.random.randint(40, 80),  # Small probe packets
            'duration': np.random.uniform(0.01, 0.05),  # Quick probes
            'syn_flag': 1,  # SYN scan
            'ack_flag': 0,
            'fin_flag': 0,
            'failed_logins': 0,
            'packet_rate': np.random.uniform(100, 500),  # High rate
            'label': 'malicious'
        }
    
    def _create_unauthorized_access_packet(self, timestamp: float) -> dict:
        """Create an unauthorized access attempt packet with failed logins"""
        self.packet_id_counter += 1
        
        return {
            'packet_id': self.packet_id_counter,
            'timestamp': timestamp,
            'src_ip': np.random.randint(1, 255),
            'dst_ip': np.random.randint(200, 210),
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.choice([22, 21, 23, 3389]),  # SSH, FTP, Telnet, RDP
            'protocol': 0,  # TCP
            'packet_size': np.random.randint(100, 500),
            'duration': np.random.uniform(0.5, 2.0),
            'syn_flag': np.random.randint(1, 3),
            'ack_flag': np.random.randint(1, 3),
            'fin_flag': np.random.randint(0, 2),
            'failed_logins': np.random.randint(3, 20),  # Multiple failed attempts
            'packet_rate': np.random.uniform(10, 100),
            'label': 'malicious'
        }
    
    def save_dataset(self, dataset: pd.DataFrame, filepath: str) -> None:
        """
        Save the generated dataset to a CSV file
        
        Args:
            dataset: DataFrame to save
            filepath: Output file path
        """
        dataset.to_csv(filepath, index=False)
        print(f"Dataset saved to {filepath}")
