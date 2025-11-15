#!/usr/bin/env python3
"""
AI-IDS Simulation Tool - Main CLI Entry Point
"""

import argparse
import sys
import os
import pandas as pd
from src.traffic_generator import TrafficGenerator
from src.model_trainer import DecisionTreeTrainer, KNNTrainer
from src.detection_engine import DetectionEngine, ModelEvaluator
from src.dashboard import Dashboard
from src.config_manager import ConfigManager
from src.utils import setup_logging, IDSSimulationError

# Initialize logging
logger = setup_logging()


def cmd_generate(args):
    """Handle generate command"""
    print("\n" + "="*60)
    print("GENERATING SYNTHETIC NETWORK TRAFFIC")
    print("="*60)
    
    generator = TrafficGenerator()
    dataset = generator.generate_dataset(args.samples, args.attack_ratio)
    generator.save_dataset(dataset, args.output)
    
    print(f"\n✓ Successfully generated {len(dataset)} samples")
    print(f"✓ Saved to {args.output}")


def cmd_train(args):
    """Handle train command"""
    print("\n" + "="*60)
    print("TRAINING ML MODEL")
    print("="*60)
    
    # Load data
    print(f"Loading training data from {args.data}...")
    data = pd.read_csv(args.data)
    print(f"Loaded {len(data)} samples")
    
    # Select trainer
    if args.model == 'dt':
        trainer = DecisionTreeTrainer()
        hyperparameters = {
            'max_depth': args.max_depth,
            'min_samples_split': 5,
            'criterion': 'gini'
        }
        model_name = 'Decision Tree'
    else:  # knn
        trainer = KNNTrainer()
        hyperparameters = {
            'n_neighbors': args.k,
            'weights': 'uniform',
            'metric': 'euclidean'
        }
        model_name = 'KNN'
    
    # Preprocess and train
    X_train, X_test, y_train, y_test = trainer.preprocess_data(data)
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    model = trainer.train(X_train, y_train, hyperparameters)
    
    # Evaluate on test set
    y_pred = model.predict(X_test)
    metrics = ModelEvaluator.calculate_metrics(y_test, y_pred)
    ModelEvaluator.print_metrics(metrics)
    
    # Save model
    trainer.save_model(model, args.output)
    
    print(f"\n✓ {model_name} model trained successfully")
    print(f"✓ Model saved to {args.output}")


def cmd_detect(args):
    """Handle detect command"""
    print("\n" + "="*60)
    print("RUNNING INTRUSION DETECTION")
    print("="*60)
    
    # Load model
    engine = DetectionEngine()
    engine.load_model(args.model)
    
    # Load test data
    print(f"Loading test data from {args.data}...")
    data = pd.read_csv(args.data)
    print(f"Loaded {len(data)} samples")
    
    # Run detection
    events = engine.detect(data)
    
    # Evaluate if ground truth is available
    if 'label' in data.columns:
        X = data[engine.feature_columns].values
        y_true = engine.label_encoder.transform(data['label'].values)
        y_pred = engine.model.predict(X)
        
        metrics = engine.evaluate_performance(y_pred, y_true)
        ModelEvaluator.print_metrics(metrics)
        
        # Save results
        os.makedirs(args.output, exist_ok=True)
        results_file = os.path.join(args.output, 'detection_results.csv')
        
        results_df = pd.DataFrame([{
            'packet_id': e.packet_id,
            'timestamp': e.timestamp,
            'predicted_class': e.predicted_class,
            'confidence': e.confidence
        } for e in events])
        results_df.to_csv(results_file, index=False)
        
        # Save metrics
        import json
        metrics_file = os.path.join(args.output, 'metrics.json')
        metrics_to_save = {k: v for k, v in metrics.items() if k != 'confusion_matrix'}
        metrics_to_save['confusion_matrix'] = metrics['confusion_matrix'].tolist()
        
        with open(metrics_file, 'w') as f:
            json.dump(metrics_to_save, f, indent=2)
        
        print(f"\n✓ Detection completed")
        print(f"✓ Results saved to {results_file}")
        print(f"✓ Metrics saved to {metrics_file}")
    else:
        print("Warning: No ground truth labels found in data")


def cmd_visualize(args):
    """Handle visualize command"""
    print("\n" + "="*60)
    print("CREATING VISUALIZATIONS")
    print("="*60)
    
    import json
    
    # Load metrics
    metrics_file = os.path.join(args.results, 'metrics.json')
    if not os.path.exists(metrics_file):
        print(f"Error: Metrics file not found at {metrics_file}")
        sys.exit(1)
    
    with open(metrics_file, 'r') as f:
        metrics = json.load(f)
    
    # Load results
    results_file = os.path.join(args.results, 'detection_results.csv')
    if os.path.exists(results_file):
        results_df = pd.read_csv(results_file)
    
    # Create dashboard
    dashboard = Dashboard(args.output)
    
    # Generate visualizations
    dashboard.plot_performance_metrics(metrics, 'Model')
    
    if 'confusion_matrix' in metrics:
        import numpy as np
        cm = np.array(metrics['confusion_matrix'])
        # We need y_true and y_pred for confusion matrix
        # For now, we'll skip this if we don't have the raw data
        print("Note: Confusion matrix visualization requires raw prediction data")
    
    print(f"\n✓ Visualizations created")
    print(f"✓ Saved to {args.output}")


def cmd_simulate(args):
    """Handle simulate command - full pipeline"""
    print("\n" + "="*60)
    print("RUNNING FULL SIMULATION PIPELINE")
    print("="*60)
    
    # Load configuration
    config_manager = ConfigManager()
    config = config_manager.load_config(args.config)
    
    # Validate configuration
    is_valid, errors = config_manager.validate_config(config)
    if not is_valid:
        print("Configuration validation failed:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)
    
    print("Configuration validated successfully\n")
    
    # Extract settings
    tg_config = config['traffic_generation']
    models_config = config['models']
    output_config = config['output']
    
    # Step 1: Generate traffic
    print("\n--- Step 1: Generating Traffic ---")
    generator = TrafficGenerator()
    dataset = generator.generate_dataset(
        tg_config['num_samples'],
        tg_config['attack_ratio']
    )
    
    traffic_file = 'data/simulation_traffic.csv'
    generator.save_dataset(dataset, traffic_file)
    
    # Step 2: Train models
    print("\n--- Step 2: Training Models ---")
    models = {}
    
    # Train Decision Tree
    if 'decision_tree' in models_config:
        print("\nTraining Decision Tree...")
        dt_trainer = DecisionTreeTrainer()
        X_train, X_test, y_train, y_test = dt_trainer.preprocess_data(dataset)
        dt_model = dt_trainer.train(X_train, y_train, models_config['decision_tree'])
        
        if output_config.get('save_models', True):
            dt_trainer.save_model(dt_model, 'models/dt_model.pkl')
        
        # Evaluate
        y_pred = dt_model.predict(X_test)
        dt_metrics = ModelEvaluator.calculate_metrics(y_test, y_pred)
        models['Decision Tree'] = dt_metrics
        print("\nDecision Tree Performance:")
        ModelEvaluator.print_metrics(dt_metrics)
    
    # Train KNN
    if 'knn' in models_config:
        print("\nTraining KNN...")
        knn_trainer = KNNTrainer()
        X_train, X_test, y_train, y_test = knn_trainer.preprocess_data(dataset)
        knn_model = knn_trainer.train(X_train, y_train, models_config['knn'])
        
        if output_config.get('save_models', True):
            knn_trainer.save_model(knn_model, 'models/knn_model.pkl')
        
        # Evaluate
        y_pred = knn_model.predict(X_test)
        knn_metrics = ModelEvaluator.calculate_metrics(y_test, y_pred)
        models['KNN'] = knn_metrics
        print("\nKNN Performance:")
        ModelEvaluator.print_metrics(knn_metrics)
    
    # Step 3: Create visualizations
    print("\n--- Step 3: Creating Visualizations ---")
    dashboard = Dashboard(output_config['visualizations_dir'])
    
    for model_name, metrics in models.items():
        dashboard.plot_performance_metrics(metrics, model_name)
    
    if len(models) >= 2:
        dashboard.plot_model_comparison(models)
    
    # Step 4: Save simulation run
    run_data = {
        'config': config,
        'results': {model: {k: v for k, v in metrics.items() if k != 'confusion_matrix'} 
                   for model, metrics in models.items()}
    }
    config_manager.save_simulation_run(run_data)
    
    print("\n" + "="*60)
    print("SIMULATION COMPLETE")
    print("="*60)
    print(f"✓ Traffic generated: {traffic_file}")
    print(f"✓ Models trained: {len(models)}")
    print(f"✓ Visualizations saved: {output_config['visualizations_dir']}")
    print("="*60 + "\n")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='AI-Driven Intrusion Detection System Simulation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate synthetic network traffic')
    generate_parser.add_argument('--samples', type=int, required=True, help='Number of samples to generate')
    generate_parser.add_argument('--attack-ratio', type=float, default=0.3, help='Ratio of attack traffic (0.0-1.0)')
    generate_parser.add_argument('--output', type=str, required=True, help='Output CSV file path')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train ML models')
    train_parser.add_argument('--data', type=str, required=True, help='Input training data CSV file')
    train_parser.add_argument('--model', type=str, required=True, choices=['dt', 'knn'], help='Model type (dt=Decision Tree, knn=K-Nearest Neighbors)')
    train_parser.add_argument('--output', type=str, required=True, help='Output model file path')
    train_parser.add_argument('--max-depth', type=int, default=10, help='Decision Tree: maximum depth')
    train_parser.add_argument('--k', type=int, default=5, help='KNN: number of neighbors')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Run intrusion detection')
    detect_parser.add_argument('--model', type=str, required=True, help='Trained model file path')
    detect_parser.add_argument('--data', type=str, required=True, help='Input test data CSV file')
    detect_parser.add_argument('--output', type=str, required=True, help='Output results directory')
    
    # Visualize command
    visualize_parser = subparsers.add_parser('visualize', help='Create visualizations')
    visualize_parser.add_argument('--results', type=str, required=True, help='Results directory')
    visualize_parser.add_argument('--output', type=str, required=True, help='Output visualizations directory')
    
    # Simulate command
    simulate_parser = subparsers.add_parser('simulate', help='Run full simulation pipeline')
    simulate_parser.add_argument('--config', type=str, required=True, help='Configuration YAML file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Route to appropriate command handler
    try:
        logger.info(f"Starting command: {args.command}")
        
        if args.command == 'generate':
            cmd_generate(args)
        elif args.command == 'train':
            cmd_train(args)
        elif args.command == 'detect':
            cmd_detect(args)
        elif args.command == 'visualize':
            cmd_visualize(args)
        elif args.command == 'simulate':
            cmd_simulate(args)
        
        logger.info(f"Command {args.command} completed successfully")
    except IDSSimulationError as e:
        logger.error(f"Simulation error: {e}")
        print(f"\nError: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"\nUnexpected error: {e}")
        print("Check the log file for more details")
        sys.exit(1)


if __name__ == '__main__':
    main()
