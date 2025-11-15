"""
Model Trainer Module
Trains and persists ML models for intrusion detection
"""

import pickle
import time
import logging
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from typing import Tuple, Dict, Any
from src.utils import ModelError, DataValidationError

logger = logging.getLogger('ids_simulation')


class ModelTrainer:
    """Base class for training ML models"""
    
    def __init__(self):
        """Initialize the model trainer"""
        self.model = None
        self.label_encoder = LabelEncoder()
        self.feature_columns = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'packet_size', 'duration', 'syn_flag', 'ack_flag', 'fin_flag',
            'failed_logins', 'packet_rate'
        ]
    
    def preprocess_data(self, data: pd.DataFrame, test_size: float = 0.2) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Preprocess data and split into train/test sets
        
        Args:
            data: DataFrame containing the traffic data
            test_size: Proportion of data to use for testing
        
        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        # Extract features and labels
        X = data[self.feature_columns].values
        y = self.label_encoder.fit_transform(data['label'].values)
        
        # Split into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        return X_train, X_test, y_train, y_test
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, hyperparameters: Dict[str, Any]) -> object:
        """
        Train the model (to be implemented by subclasses)
        
        Args:
            X_train: Training features
            y_train: Training labels
            hyperparameters: Model hyperparameters
        
        Returns:
            Trained model object
        """
        raise NotImplementedError("Subclasses must implement train()")
    
    def save_model(self, model: object, filepath: str) -> None:
        """
        Save the trained model to a file
        
        Args:
            model: Trained model object
            filepath: Output file path
        """
        try:
            model_data = {
                'model': model,
                'label_encoder': self.label_encoder,
                'feature_columns': self.feature_columns
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            logger.info(f"Model saved to {filepath}")
            print(f"Model saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save model to {filepath}: {e}")
            raise ModelError(f"Failed to save model: {e}")
    
    def load_model(self, filepath: str) -> object:
        """
        Load a trained model from a file
        
        Args:
            filepath: Input file path
        
        Returns:
            Loaded model object
        """
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.label_encoder = model_data['label_encoder']
            self.feature_columns = model_data['feature_columns']
            
            logger.info(f"Model loaded from {filepath}")
            print(f"Model loaded from {filepath}")
            return self.model
        except FileNotFoundError:
            logger.error(f"Model file not found: {filepath}")
            raise ModelError(f"Model file not found: {filepath}")
        except Exception as e:
            logger.error(f"Failed to load model from {filepath}: {e}")
            raise ModelError(f"Failed to load model: {e}")
    
    def get_feature_importance(self, model: object) -> Dict[str, float]:
        """
        Get feature importance (if supported by the model)
        
        Args:
            model: Trained model object
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            return dict(zip(self.feature_columns, importances))
        else:
            return {}


class DecisionTreeTrainer(ModelTrainer):
    """Trainer for Decision Tree models"""
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, hyperparameters: Dict[str, Any] = None) -> DecisionTreeClassifier:
        """
        Train a Decision Tree classifier
        
        Args:
            X_train: Training features
            y_train: Training labels
            hyperparameters: Model hyperparameters (max_depth, min_samples_split, criterion)
        
        Returns:
            Trained Decision Tree model
        """
        if hyperparameters is None:
            hyperparameters = {}
        
        # Set default hyperparameters
        max_depth = hyperparameters.get('max_depth', 10)
        min_samples_split = hyperparameters.get('min_samples_split', 5)
        criterion = hyperparameters.get('criterion', 'gini')
        
        print(f"Training Decision Tree (max_depth={max_depth}, min_samples_split={min_samples_split}, criterion={criterion})...")
        start_time = time.time()
        
        # Create and train the model
        self.model = DecisionTreeClassifier(
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            criterion=criterion,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds")
        
        return self.model


class KNNTrainer(ModelTrainer):
    """Trainer for K-Nearest Neighbors models"""
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, hyperparameters: Dict[str, Any] = None) -> KNeighborsClassifier:
        """
        Train a K-Nearest Neighbors classifier
        
        Args:
            X_train: Training features
            y_train: Training labels
            hyperparameters: Model hyperparameters (n_neighbors, weights, metric)
        
        Returns:
            Trained KNN model
        """
        if hyperparameters is None:
            hyperparameters = {}
        
        # Set default hyperparameters
        n_neighbors = hyperparameters.get('n_neighbors', 5)
        weights = hyperparameters.get('weights', 'uniform')
        metric = hyperparameters.get('metric', 'euclidean')
        
        print(f"Training KNN (n_neighbors={n_neighbors}, weights={weights}, metric={metric})...")
        start_time = time.time()
        
        # Create and train the model
        self.model = KNeighborsClassifier(
            n_neighbors=n_neighbors,
            weights=weights,
            metric=metric
        )
        
        self.model.fit(X_train, y_train)
        
        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds")
        
        return self.model
