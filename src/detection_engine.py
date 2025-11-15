"""
Detection Engine Module
Applies trained models to detect intrusions in network traffic
"""

import pickle
import time
import logging
import numpy as np
import pandas as pd
from dataclasses import dataclass
from typing import List, Dict, Any
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc
)
from src.utils import ModelError, DataValidationError

logger = logging.getLogger('ids_simulation')


@dataclass
class DetectionEvent:
    """Represents a detected intrusion event"""
    timestamp: float
    packet_id: int
    predicted_class: str  # 'benign' or 'malicious'
    confidence: float
    features: dict


class DetectionEngine:
    """Main detection orchestrator for applying trained models"""
    
    def __init__(self):
        """Initialize the detection engine"""
        self.model = None
        self.label_encoder = None
        self.feature_columns = None
    
    def load_model(self, model_path: str) -> None:
        """
        Load a trained model from file
        
        Args:
            model_path: Path to the saved model file
        """
        try:
            print(f"Loading model from {model_path}...")
            logger.info(f"Loading model from {model_path}")
            
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.label_encoder = model_data['label_encoder']
            self.feature_columns = model_data['feature_columns']
            
            logger.info("Model loaded successfully")
            print("Model loaded successfully")
        except FileNotFoundError:
            logger.error(f"Model file not found: {model_path}")
            raise ModelError(f"Model file not found: {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise ModelError(f"Failed to load model: {e}")
    
    def detect(self, traffic_data: pd.DataFrame) -> List[DetectionEvent]:
        """
        Detect intrusions in network traffic using the loaded model
        
        Args:
            traffic_data: DataFrame containing network traffic to analyze
        
        Returns:
            List of DetectionEvent objects for detected intrusions
        """
        if self.model is None:
            raise ValueError("No model loaded. Call load_model() first.")
        
        print(f"Running detection on {len(traffic_data)} packets...")
        start_time = time.time()
        
        # Extract features
        X = traffic_data[self.feature_columns].values
        
        # Make predictions
        predictions = self.model.predict(X)
        
        # Get confidence scores if available
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X)
            confidences = np.max(probabilities, axis=1)
        else:
            # For models without probability estimates, use 1.0
            confidences = np.ones(len(predictions))
        
        # Create detection events
        events = []
        for idx, (pred, conf) in enumerate(zip(predictions, confidences)):
            predicted_label = self.label_encoder.inverse_transform([pred])[0]
            
            event = DetectionEvent(
                timestamp=traffic_data.iloc[idx]['timestamp'],
                packet_id=traffic_data.iloc[idx]['packet_id'],
                predicted_class=predicted_label,
                confidence=float(conf),
                features=traffic_data.iloc[idx][self.feature_columns].to_dict()
            )
            events.append(event)
        
        detection_time = time.time() - start_time
        packets_per_second = len(traffic_data) / detection_time if detection_time > 0 else 0
        
        print(f"Detection completed in {detection_time:.2f} seconds")
        print(f"Throughput: {packets_per_second:.2f} packets/second")
        
        return events
    
    def evaluate_performance(self, predictions: np.ndarray, ground_truth: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate model performance using various metrics
        
        Args:
            predictions: Predicted labels
            ground_truth: True labels
        
        Returns:
            Dictionary containing performance metrics
        """
        # Calculate metrics
        accuracy = accuracy_score(ground_truth, predictions)
        precision = precision_score(ground_truth, predictions, average='binary', pos_label=1)
        recall = recall_score(ground_truth, predictions, average='binary', pos_label=1)
        f1 = f1_score(ground_truth, predictions, average='binary', pos_label=1)
        
        # Confusion matrix
        cm = confusion_matrix(ground_truth, predictions)
        
        # Calculate FPR and TPR
        tn, fp, fn, tp = cm.ravel()
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        true_positive_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'false_positive_rate': float(false_positive_rate),
            'true_positive_rate': float(true_positive_rate),
            'confusion_matrix': cm,
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp)
        }
        
        return metrics


class ModelEvaluator:
    """Calculates and manages performance metrics"""
    
    @staticmethod
    def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray, processing_time: float = 0) -> Dict[str, Any]:
        """
        Calculate comprehensive performance metrics
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            processing_time: Time taken for processing (optional)
        
        Returns:
            Dictionary containing all performance metrics
        """
        # Basic metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='binary', pos_label=1, zero_division=0)
        recall = recall_score(y_true, y_pred, average='binary', pos_label=1, zero_division=0)
        f1 = f1_score(y_true, y_pred, average='binary', pos_label=1, zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        # Rates
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # Throughput
        packets_per_second = len(y_true) / processing_time if processing_time > 0 else 0
        
        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'false_positive_rate': float(fpr),
            'true_positive_rate': float(tpr),
            'confusion_matrix': cm,
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp),
            'processing_time': float(processing_time),
            'packets_per_second': float(packets_per_second)
        }
    
    @staticmethod
    def print_metrics(metrics: Dict[str, Any]) -> None:
        """
        Print metrics in a readable format
        
        Args:
            metrics: Dictionary containing performance metrics
        """
        print("\n" + "="*50)
        print("PERFORMANCE METRICS")
        print("="*50)
        print(f"Accuracy:              {metrics['accuracy']:.4f}")
        print(f"Precision:             {metrics['precision']:.4f}")
        print(f"Recall:                {metrics['recall']:.4f}")
        print(f"F1-Score:              {metrics['f1_score']:.4f}")
        print(f"False Positive Rate:   {metrics['false_positive_rate']:.4f}")
        print(f"True Positive Rate:    {metrics['true_positive_rate']:.4f}")
        print("\nConfusion Matrix:")
        print(f"  TN: {metrics['true_negatives']:6d}  |  FP: {metrics['false_positives']:6d}")
        print(f"  FN: {metrics['false_negatives']:6d}  |  TP: {metrics['true_positives']:6d}")
        
        if 'processing_time' in metrics and metrics['processing_time'] > 0:
            print(f"\nProcessing Time:       {metrics['processing_time']:.2f} seconds")
            print(f"Throughput:            {metrics['packets_per_second']:.2f} packets/second")
        print("="*50 + "\n")
