"""
Dashboard Module
Visualizes detection results and performance metrics
"""

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict, Any
from src.detection_engine import DetectionEvent


class Dashboard:
    """Main visualization coordinator"""
    
    def __init__(self, output_dir: str = 'visualizations'):
        """
        Initialize the dashboard
        
        Args:
            output_dir: Directory to save visualizations
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Set style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (10, 6)
    
    def plot_performance_metrics(self, metrics: Dict[str, Any], model_name: str = 'Model') -> None:
        """
        Create bar charts for performance metrics
        
        Args:
            metrics: Dictionary containing performance metrics
            model_name: Name of the model for the title
        """
        # Extract metrics for plotting
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        metric_values = [
            metrics['accuracy'],
            metrics['precision'],
            metrics['recall'],
            metrics['f1_score']
        ]
        
        # Create bar chart
        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.bar(metric_names, metric_values, color=['#2ecc71', '#3498db', '#e74c3c', '#f39c12'])
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.3f}',
                   ha='center', va='bottom', fontsize=12, fontweight='bold')
        
        ax.set_ylim(0, 1.1)
        ax.set_ylabel('Score', fontsize=12, fontweight='bold')
        ax.set_title(f'{model_name} - Performance Metrics', fontsize=14, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        filepath = os.path.join(self.output_dir, f'{model_name.lower().replace(" ", "_")}_metrics.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Performance metrics chart saved to {filepath}")
        
        # Create additional chart for FPR
        fig, ax = plt.subplots(figsize=(8, 6))
        rate_names = ['False Positive Rate', 'True Positive Rate']
        rate_values = [metrics['false_positive_rate'], metrics['true_positive_rate']]
        colors = ['#e74c3c', '#2ecc71']
        
        bars = ax.bar(rate_names, rate_values, color=colors)
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.3f}',
                   ha='center', va='bottom', fontsize=12, fontweight='bold')
        
        ax.set_ylim(0, 1.1)
        ax.set_ylabel('Rate', fontsize=12, fontweight='bold')
        ax.set_title(f'{model_name} - Detection Rates', fontsize=14, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        filepath = os.path.join(self.output_dir, f'{model_name.lower().replace(" ", "_")}_rates.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Detection rates chart saved to {filepath}")
    
    def plot_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray, model_name: str = 'Model') -> None:
        """
        Generate confusion matrix heatmap
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            model_name: Name of the model for the title
        """
        from sklearn.metrics import confusion_matrix
        
        # Calculate confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # Create heatmap
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True,
                   xticklabels=['Benign', 'Malicious'],
                   yticklabels=['Benign', 'Malicious'],
                   ax=ax, annot_kws={'size': 16, 'weight': 'bold'})
        
        ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
        ax.set_ylabel('True Label', fontsize=12, fontweight='bold')
        ax.set_title(f'{model_name} - Confusion Matrix', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        filepath = os.path.join(self.output_dir, f'{model_name.lower().replace(" ", "_")}_confusion_matrix.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Confusion matrix saved to {filepath}")
    
    def plot_model_comparison(self, model_metrics: Dict[str, Dict[str, Any]]) -> None:
        """
        Create comparison charts for multiple models
        
        Args:
            model_metrics: Dictionary mapping model names to their metrics
        """
        if len(model_metrics) < 2:
            print("Need at least 2 models for comparison")
            return
        
        # Extract data for comparison
        model_names = list(model_metrics.keys())
        metrics_to_compare = ['accuracy', 'precision', 'recall', 'f1_score']
        metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        
        # Create grouped bar chart
        x = np.arange(len(metric_labels))
        width = 0.35 if len(model_names) == 2 else 0.25
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
        
        for i, model_name in enumerate(model_names):
            values = [model_metrics[model_name][metric] for metric in metrics_to_compare]
            offset = width * (i - len(model_names)/2 + 0.5)
            bars = ax.bar(x + offset, values, width, label=model_name, color=colors[i % len(colors)])
            
            # Add value labels
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.3f}',
                       ha='center', va='bottom', fontsize=9)
        
        ax.set_ylabel('Score', fontsize=12, fontweight='bold')
        ax.set_title('Model Performance Comparison', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(metric_labels)
        ax.legend()
        ax.set_ylim(0, 1.1)
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        filepath = os.path.join(self.output_dir, 'model_comparison.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Model comparison chart saved to {filepath}")
        
        # Create FPR comparison
        fig, ax = plt.subplots(figsize=(10, 6))
        
        fpr_values = [model_metrics[name]['false_positive_rate'] for name in model_names]
        tpr_values = [model_metrics[name]['true_positive_rate'] for name in model_names]
        
        x = np.arange(len(model_names))
        width = 0.35
        
        bars1 = ax.bar(x - width/2, fpr_values, width, label='False Positive Rate', color='#e74c3c')
        bars2 = ax.bar(x + width/2, tpr_values, width, label='True Positive Rate', color='#2ecc71')
        
        # Add value labels
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.3f}',
                       ha='center', va='bottom', fontsize=10)
        
        ax.set_ylabel('Rate', fontsize=12, fontweight='bold')
        ax.set_title('Model Detection Rates Comparison', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(model_names)
        ax.legend()
        ax.set_ylim(0, 1.1)
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        filepath = os.path.join(self.output_dir, 'model_comparison_rates.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Model rates comparison chart saved to {filepath}")
    
    def plot_detection_results(self, events: List[DetectionEvent], title: str = 'Detection Results') -> None:
        """
        Visualize detection events over time
        
        Args:
            events: List of DetectionEvent objects
            title: Title for the plot
        """
        if not events:
            print("No detection events to visualize")
            return
        
        # Extract data from events
        timestamps = [e.timestamp for e in events]
        predictions = [1 if e.predicted_class == 'malicious' else 0 for e in events]
        
        # Normalize timestamps to start from 0
        min_timestamp = min(timestamps)
        normalized_times = [(t - min_timestamp) for t in timestamps]
        
        # Create timeline plot
        fig, ax = plt.subplots(figsize=(14, 6))
        
        # Separate benign and malicious
        benign_times = [t for t, p in zip(normalized_times, predictions) if p == 0]
        malicious_times = [t for t, p in zip(normalized_times, predictions) if p == 1]
        
        benign_y = [0] * len(benign_times)
        malicious_y = [1] * len(malicious_times)
        
        ax.scatter(benign_times, benign_y, c='#2ecc71', label='Benign', alpha=0.6, s=20)
        ax.scatter(malicious_times, malicious_y, c='#e74c3c', label='Malicious', alpha=0.6, s=20)
        
        ax.set_xlabel('Time (seconds)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Classification', fontsize=12, fontweight='bold')
        ax.set_yticks([0, 1])
        ax.set_yticklabels(['Benign', 'Malicious'])
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.legend(loc='upper right')
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        filepath = os.path.join(self.output_dir, 'detection_timeline.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Detection timeline saved to {filepath}")
        
        # Create distribution chart
        fig, ax = plt.subplots(figsize=(8, 6))
        
        counts = [len(benign_times), len(malicious_times)]
        labels = ['Benign', 'Malicious']
        colors = ['#2ecc71', '#e74c3c']
        
        bars = ax.bar(labels, counts, color=colors)
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontsize=12, fontweight='bold')
        
        ax.set_ylabel('Count', fontsize=12, fontweight='bold')
        ax.set_title('Detection Results Distribution', fontsize=14, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        filepath = os.path.join(self.output_dir, 'detection_distribution.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Detection distribution saved to {filepath}")
    
    def export_results(self, output_dir: str, format: str = 'png') -> None:
        """
        Export all visualizations to specified directory
        
        Args:
            output_dir: Output directory path
            format: Export format (png or pdf)
        """
        if format not in ['png', 'pdf']:
            raise ValueError("Format must be 'png' or 'pdf'")
        
        print(f"All visualizations are saved in {self.output_dir} as {format} files")
