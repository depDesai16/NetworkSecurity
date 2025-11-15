# AI-Driven Intrusion Detection System Simulation Tool

A Python-based simulation tool that demonstrates how AI techniques (Decision Trees and K-Nearest Neighbors) can enhance intrusion detection capabilities compared to traditional signature-based approaches.

## Overview

This tool simulates network traffic, applies machine learning algorithms to detect intrusions, and visualizes the results. It's designed to support academic research by providing a controlled environment for testing and comparing AI-based intrusion detection methods.

## Features

- **Synthetic Traffic Generation**: Create realistic network traffic with configurable benign and malicious patterns
- **ML Model Training**: Train Decision Tree and K-Nearest Neighbors models on generated traffic
- **Intrusion Detection**: Apply trained models to detect potential threats in network traffic
- **Performance Visualization**: Generate comprehensive visualizations of detection results and model performance
- **Configuration Management**: Save and load simulation configurations for reproducible experiments

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd NetworkSecurity
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Generate Synthetic Traffic

```bash
python ids_sim.py generate --samples 10000 --attack-ratio 0.3 --output data/traffic.csv
```

### Train Models

Train a Decision Tree model:
```bash
python ids_sim.py train --data data/traffic.csv --model dt --max-depth 10 --output models/dt_model.pkl
```

Train a K-Nearest Neighbors model:
```bash
python ids_sim.py train --data data/traffic.csv --model knn --k 5 --output models/knn_model.pkl
```

### Run Detection

```bash
python ids_sim.py detect --model models/dt_model.pkl --data data/test_traffic.csv --output results/
```

### Create Visualizations

```bash
python ids_sim.py visualize --results results/ --output visualizations/
```

### Run Full Simulation

```bash
python ids_sim.py simulate --config configs/simulation.yaml
```

## Project Structure

```
NetworkSecurity/
├── src/                    # Source code modules
│   ├── traffic_generator.py
│   ├── model_trainer.py
│   ├── detection_engine.py
│   ├── dashboard.py
│   ├── config_manager.py
│   └── utils.py
├── tests/                  # Unit tests
├── data/                   # Generated datasets
├── models/                 # Trained ML models
├── results/                # Detection results
├── visualizations/         # Generated plots and charts
├── configs/                # Configuration files
├── writeups/               # Requirements, design, and tasks documentation
├── ids_sim.py             # Main CLI entry point
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Attack Types Simulated

1. **Denial of Service (DoS)**: High packet rate, repeated connections
2. **Port Scanning**: Sequential port access patterns
3. **Unauthorized Access**: Multiple failed authentication attempts

## Performance Metrics

The tool calculates and visualizes the following metrics:

- Accuracy
- Precision
- Recall
- F1-Score
- False Positive Rate (FPR)
- True Positive Rate (TPR)
- Confusion Matrix

## Requirements

- Python 3.8+
- scikit-learn
- NumPy
- Pandas
- Matplotlib
- Seaborn
- Plotly
- PyYAML
- pytest

## License

This project is for academic research purposes.

## Contributing

This is an academic research project. For questions or suggestions, please open an issue.
