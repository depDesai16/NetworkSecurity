"""
Configuration Manager Module
Handles saving and loading of simulation configurations
"""

import os
import yaml
import json
import logging
from datetime import datetime
from typing import Dict, Any, List
from src.utils import ConfigurationError

logger = logging.getLogger('ids_simulation')


class ConfigManager:
    """Manages simulation configurations"""
    
    def __init__(self, config_dir: str = 'configs'):
        """
        Initialize the configuration manager
        
        Args:
            config_dir: Directory to store configuration files
        """
        self.config_dir = config_dir
        os.makedirs(config_dir, exist_ok=True)
        
        self.history_file = os.path.join(config_dir, 'simulation_history.json')
    
    def save_config(self, config: Dict[str, Any], filepath: str) -> None:
        """
        Save configuration to a YAML file
        
        Args:
            config: Configuration dictionary
            filepath: Output file path
        """
        # Add timestamp if not present
        if 'simulation' not in config:
            config['simulation'] = {}
        
        if 'timestamp' not in config['simulation']:
            config['simulation']['timestamp'] = datetime.now().isoformat()
        
        # Ensure filepath is in config directory
        if not filepath.startswith(self.config_dir):
            filepath = os.path.join(self.config_dir, os.path.basename(filepath))
        
        with open(filepath, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        
        print(f"Configuration saved to {filepath}")
    
    def load_config(self, filepath: str) -> Dict[str, Any]:
        """
        Load configuration from a YAML file
        
        Args:
            filepath: Input file path
        
        Returns:
            Configuration dictionary
        """
        try:
            if not os.path.exists(filepath):
                logger.error(f"Configuration file not found: {filepath}")
                raise ConfigurationError(f"Configuration file not found: {filepath}")
            
            with open(filepath, 'r') as f:
                config = yaml.safe_load(f)
            
            logger.info(f"Configuration loaded from {filepath}")
            print(f"Configuration loaded from {filepath}")
            return config
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML in configuration file: {e}")
            raise ConfigurationError(f"Invalid YAML syntax: {e}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def validate_config(self, config: Dict[str, Any]) -> tuple[bool, List[str]]:
        """
        Validate configuration parameters
        
        Args:
            config: Configuration dictionary to validate
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Validate traffic generation settings
        if 'traffic_generation' in config:
            tg = config['traffic_generation']
            
            if 'num_samples' in tg:
                if not isinstance(tg['num_samples'], int) or tg['num_samples'] <= 0:
                    errors.append("num_samples must be a positive integer")
            
            if 'attack_ratio' in tg:
                if not isinstance(tg['attack_ratio'], (int, float)) or not 0 <= tg['attack_ratio'] <= 1:
                    errors.append("attack_ratio must be between 0 and 1")
            
            if 'attack_types' in tg:
                valid_types = ['dos', 'port_scan', 'unauthorized_access']
                for attack_type in tg['attack_types']:
                    if attack_type not in valid_types:
                        errors.append(f"Invalid attack type: {attack_type}. Must be one of {valid_types}")
        
        # Validate Decision Tree hyperparameters
        if 'models' in config and 'decision_tree' in config['models']:
            dt = config['models']['decision_tree']
            
            if 'max_depth' in dt:
                if not isinstance(dt['max_depth'], int) or dt['max_depth'] <= 0:
                    errors.append("Decision Tree max_depth must be a positive integer")
            
            if 'min_samples_split' in dt:
                if not isinstance(dt['min_samples_split'], int) or dt['min_samples_split'] < 2:
                    errors.append("Decision Tree min_samples_split must be >= 2")
            
            if 'criterion' in dt:
                if dt['criterion'] not in ['gini', 'entropy']:
                    errors.append("Decision Tree criterion must be 'gini' or 'entropy'")
        
        # Validate KNN hyperparameters
        if 'models' in config and 'knn' in config['models']:
            knn = config['models']['knn']
            
            if 'n_neighbors' in knn:
                if not isinstance(knn['n_neighbors'], int) or knn['n_neighbors'] <= 0:
                    errors.append("KNN n_neighbors must be a positive integer")
            
            if 'weights' in knn:
                if knn['weights'] not in ['uniform', 'distance']:
                    errors.append("KNN weights must be 'uniform' or 'distance'")
            
            if 'metric' in knn:
                valid_metrics = ['euclidean', 'manhattan', 'minkowski']
                if knn['metric'] not in valid_metrics:
                    errors.append(f"KNN metric must be one of {valid_metrics}")
        
        # Validate output settings
        if 'output' in config:
            output = config['output']
            
            if 'save_models' in output:
                if not isinstance(output['save_models'], bool):
                    errors.append("save_models must be a boolean")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def save_simulation_run(self, run_data: Dict[str, Any]) -> None:
        """
        Save simulation run metadata to history
        
        Args:
            run_data: Dictionary containing run information
        """
        # Load existing history
        history = self._load_history()
        
        # Add timestamp if not present
        if 'timestamp' not in run_data:
            run_data['timestamp'] = datetime.now().isoformat()
        
        # Add to history
        history.append(run_data)
        
        # Save updated history
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)
        
        print(f"Simulation run saved to history")
    
    def get_simulation_history(self) -> List[Dict[str, Any]]:
        """
        Retrieve simulation history
        
        Returns:
            List of simulation run dictionaries
        """
        return self._load_history()
    
    def _load_history(self) -> List[Dict[str, Any]]:
        """Load simulation history from file"""
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                return json.load(f)
        return []
    
    def create_default_config(self) -> Dict[str, Any]:
        """
        Create a default configuration
        
        Returns:
            Default configuration dictionary
        """
        return {
            'simulation': {
                'name': 'Default IDS Simulation',
                'timestamp': datetime.now().isoformat()
            },
            'traffic_generation': {
                'num_samples': 10000,
                'attack_ratio': 0.3,
                'attack_types': ['dos', 'port_scan', 'unauthorized_access']
            },
            'models': {
                'decision_tree': {
                    'max_depth': 10,
                    'min_samples_split': 5,
                    'criterion': 'gini'
                },
                'knn': {
                    'n_neighbors': 5,
                    'weights': 'uniform',
                    'metric': 'euclidean'
                }
            },
            'output': {
                'results_dir': 'results/',
                'visualizations_dir': 'visualizations/',
                'save_models': True
            }
        }



