# Design Document: AI-IDS Simulation Tool

## Overview

The AI-IDS Simulation Tool is a Python-based application that simulates network intrusion detection using machine learning algorithms. The tool consists of four main components: a traffic generator, ML model trainer, detection engine, and visualization dashboard. The architecture follows a modular design pattern to allow independent development and testing of each component.

The tool will use scikit-learn for ML implementations, NumPy/Pandas for data handling, and Matplotlib/Plotly for visualizations. A simple CLI interface will allow users to run simulations, while results are displayed both in terminal output and saved as visualization files.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Interface                         │
│              (User Commands & Configuration)             │
└────────────┬────────────────────────────────────────────┘
             │
             ├──────────────┬──────────────┬──────────────┐
             ▼              ▼              ▼              ▼
    ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
    │  Traffic   │  │   Model    │  │ Detection  │  │Visualization│
    │ Generator  │  │  Trainer   │  │   Engine   │  │  Dashboard │
    └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
          │               │               │               │
          └───────────────┴───────────────┴───────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Data Storage    │
                    │ (Datasets, Models,│
                    │  Configurations)  │
                    └───────────────────┘
```

### Component Interaction Flow

1. User initiates simulation via CLI
2. Traffic Generator creates synthetic dataset
3. Model Trainer trains Decision Tree and KNN models on dataset
4. Detection Engine applies trained models to test traffic
5. Visualization Dashboard displays results and metrics
6. Results and configurations saved to storage

## Components and Interfaces

### 1. Traffic Generator

**Purpose**: Generate synthetic network traffic with both benign and malicious patterns

**Key Classes**:
- `TrafficGenerator`: Main class for traffic generation
- `PacketFeatureExtractor`: Extracts features from network packets
- `AttackSimulator`: Generates specific attack patterns

**Interface**:
```python
class TrafficGenerator:
    def generate_dataset(self, num_samples: int, attack_ratio: float) -> pd.DataFrame
    def generate_benign_traffic(self, num_samples: int) -> pd.DataFrame
    def generate_attack_traffic(self, num_samples: int, attack_types: List[str]) -> pd.DataFrame
```

**Features Generated** (per packet):
- Source/Destination IP (encoded)
- Source/Destination Port
- Protocol type (TCP/UDP/ICMP)
- Packet size
- Time interval between packets
- Connection duration
- Number of failed login attempts (for relevant attacks)
- Flag counts (SYN, ACK, FIN, etc.)

**Attack Types**:
- DoS (Denial of Service): High packet rate, repeated connections
- Port Scan: Sequential port access patterns
- Unauthorized Access: Multiple failed authentication attempts

### 2. Model Trainer

**Purpose**: Train and persist ML models using generated traffic data

**Key Classes**:
- `ModelTrainer`: Base trainer class
- `DecisionTreeTrainer`: Specialized for Decision Tree models
- `KNNTrainer`: Specialized for K-Nearest Neighbors models

**Interface**:
```python
class ModelTrainer:
    def train(self, X_train: np.ndarray, y_train: np.ndarray, hyperparameters: dict) -> object
    def save_model(self, model: object, filepath: str) -> None
    def load_model(self, filepath: str) -> object
    def get_feature_importance(self, model: object) -> dict
```

**Hyperparameters**:
- Decision Tree: max_depth, min_samples_split, criterion
- KNN: n_neighbors, weights, metric

### 3. Detection Engine

**Purpose**: Apply trained models to detect intrusions in network traffic

**Key Classes**:
- `DetectionEngine`: Main detection orchestrator
- `ModelEvaluator`: Calculates performance metrics
- `DetectionEvent`: Represents a detected intrusion

**Interface**:
```python
class DetectionEngine:
    def load_model(self, model_path: str) -> None
    def detect(self, traffic_data: pd.DataFrame) -> List[DetectionEvent]
    def evaluate_performance(self, predictions: np.ndarray, ground_truth: np.ndarray) -> dict
```

**Detection Event Structure**:
```python
@dataclass
class DetectionEvent:
    timestamp: float
    packet_id: int
    predicted_class: str  # 'benign' or 'malicious'
    confidence: float
    features: dict
```

### 4. Visualization Dashboard

**Purpose**: Display simulation results and performance metrics

**Key Classes**:
- `Dashboard`: Main visualization coordinator
- `MetricsVisualizer`: Creates performance metric charts
- `ConfusionMatrixPlotter`: Generates confusion matrices
- `ComparisonPlotter`: Compares model performances

**Interface**:
```python
class Dashboard:
    def plot_detection_results(self, events: List[DetectionEvent]) -> None
    def plot_performance_metrics(self, metrics: dict) -> None
    def plot_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray) -> None
    def plot_model_comparison(self, model_metrics: dict) -> None
    def export_results(self, output_dir: str, format: str) -> None
```

**Visualizations**:
- Real-time detection timeline
- Performance metrics bar charts (accuracy, precision, recall, F1-score)
- Confusion matrix heatmap
- ROC curves for model comparison
- Feature importance plots (for Decision Tree)

### 5. CLI Interface

**Purpose**: Provide command-line interface for user interactions

**Commands**:
```bash
# Generate traffic dataset
python ids_sim.py generate --samples 10000 --attack-ratio 0.3 --output data/traffic.csv

# Train models
python ids_sim.py train --data data/traffic.csv --model dt --output models/dt_model.pkl
python ids_sim.py train --data data/traffic.csv --model knn --k 5 --output models/knn_model.pkl

# Run detection
python ids_sim.py detect --model models/dt_model.pkl --data data/test_traffic.csv --output results/

# Visualize results
python ids_sim.py visualize --results results/ --output visualizations/

# Run full simulation
python ids_sim.py simulate --config configs/simulation.yaml
```

### 6. Configuration Manager

**Purpose**: Handle saving and loading of simulation configurations

**Configuration Format** (YAML):
```yaml
simulation:
  name: "IDS Simulation Run 1"
  timestamp: "2025-11-15T10:30:00"

traffic_generation:
  num_samples: 10000
  attack_ratio: 0.3
  attack_types:
    - dos
    - port_scan
    - unauthorized_access

models:
  decision_tree:
    max_depth: 10
    min_samples_split: 5
    criterion: "gini"
  
  knn:
    n_neighbors: 5
    weights: "uniform"
    metric: "euclidean"

output:
  results_dir: "results/"
  visualizations_dir: "visualizations/"
  save_models: true
```

## Data Models

### Traffic Dataset Schema

```python
# DataFrame columns for generated traffic
columns = [
    'packet_id',           # int: Unique identifier
    'timestamp',           # float: Unix timestamp
    'src_ip',             # int: Encoded source IP
    'dst_ip',             # int: Encoded destination IP
    'src_port',           # int: Source port number
    'dst_port',           # int: Destination port number
    'protocol',           # int: Protocol type (0=TCP, 1=UDP, 2=ICMP)
    'packet_size',        # int: Size in bytes
    'duration',           # float: Connection duration
    'syn_flag',           # int: SYN flag count
    'ack_flag',           # int: ACK flag count
    'fin_flag',           # int: FIN flag count
    'failed_logins',      # int: Number of failed login attempts
    'packet_rate',        # float: Packets per second
    'label'               # str: 'benign' or 'malicious'
]
```

### Performance Metrics Structure

```python
metrics = {
    'accuracy': float,        # Overall accuracy
    'precision': float,       # Precision score
    'recall': float,          # Recall score
    'f1_score': float,        # F1 score
    'false_positive_rate': float,  # FPR
    'true_positive_rate': float,   # TPR (sensitivity)
    'confusion_matrix': np.ndarray,  # 2x2 matrix
    'processing_time': float,  # Time in seconds
    'packets_per_second': float  # Throughput
}
```

## Error Handling

### Error Categories

1. **Data Errors**
   - Invalid dataset format
   - Missing required columns
   - Corrupted data files
   - **Handling**: Validate data schema, provide clear error messages, suggest fixes

2. **Model Errors**
   - Model file not found
   - Incompatible model version
   - Training failure due to insufficient data
   - **Handling**: Check file existence, validate model compatibility, ensure minimum data requirements

3. **Configuration Errors**
   - Invalid YAML syntax
   - Missing required parameters
   - Out-of-range hyperparameters
   - **Handling**: Validate configuration schema, provide default values, show validation errors

4. **Runtime Errors**
   - Insufficient memory for large datasets
   - Disk space issues
   - Permission errors
   - **Handling**: Check system resources, provide graceful degradation, clear error messages

### Error Handling Strategy

```python
class IDSSimulationError(Exception):
    """Base exception for IDS simulation errors"""
    pass

class DataValidationError(IDSSimulationError):
    """Raised when data validation fails"""
    pass

class ModelError(IDSSimulationError):
    """Raised when model operations fail"""
    pass

class ConfigurationError(IDSSimulationError):
    """Raised when configuration is invalid"""
    pass
```

All errors will be logged with appropriate severity levels and user-friendly messages.

## Testing Strategy

### Unit Testing

**Scope**: Test individual components in isolation

**Test Cases**:
1. **Traffic Generator**
   - Verify correct number of samples generated
   - Validate feature ranges and distributions
   - Ensure attack patterns have expected characteristics
   - Test label accuracy

2. **Model Trainer**
   - Verify models train successfully with valid data
   - Test hyperparameter application
   - Validate model persistence and loading
   - Test with edge cases (minimal data, imbalanced classes)

3. **Detection Engine**
   - Test prediction accuracy with known data
   - Verify metrics calculation correctness
   - Test detection event generation
   - Validate performance with different model types

4. **Visualization Dashboard**
   - Test plot generation without errors
   - Verify export functionality
   - Test with various data sizes
   - Validate file output formats

### Integration Testing

**Scope**: Test component interactions

**Test Scenarios**:
1. End-to-end simulation flow (generate → train → detect → visualize)
2. Configuration save and load with full simulation
3. Model comparison workflow
4. Error propagation between components

### Performance Testing

**Metrics to Measure**:
- Traffic generation speed (samples per second)
- Model training time with varying dataset sizes
- Detection throughput (packets per second)
- Memory usage during operations
- Visualization rendering time

**Targets**:
- Generate 10,000 samples in under 5 seconds
- Detect at least 1,000 packets per second
- Support datasets up to 100,000 samples
- Complete full simulation in under 2 minutes

### Validation Testing

**Scope**: Verify ML model correctness

**Validation Approach**:
1. Use known benchmark datasets (if available)
2. Cross-validation during training
3. Compare results against expected ML behavior
4. Verify confusion matrix calculations
5. Test with deliberately mislabeled data to ensure detection

## Technology Stack

- **Language**: Python 3.8+
- **ML Libraries**: scikit-learn, NumPy, Pandas
- **Visualization**: Matplotlib, Seaborn, Plotly
- **CLI**: argparse or Click
- **Configuration**: PyYAML
- **Testing**: pytest
- **Data Storage**: CSV files, pickle for models
- **Logging**: Python logging module

## Project Structure

```
ai-ids-simulation/
├── src/
│   ├── __init__.py
│   ├── traffic_generator.py
│   ├── model_trainer.py
│   ├── detection_engine.py
│   ├── dashboard.py
│   ├── config_manager.py
│   └── utils.py
├── tests/
│   ├── test_traffic_generator.py
│   ├── test_model_trainer.py
│   ├── test_detection_engine.py
│   └── test_dashboard.py
├── data/
│   └── .gitkeep
├── models/
│   └── .gitkeep
├── results/
│   └── .gitkeep
├── visualizations/
│   └── .gitkeep
├── configs/
│   └── default_simulation.yaml
├── ids_sim.py (main CLI entry point)
├── requirements.txt
└── README.md
```
