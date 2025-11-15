#!/usr/bin/env python3
"""
AI-IDS Simulation Tool - Main CLI Entry Point
"""

import argparse
import sys


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
    
    print(f"Command '{args.command}' not yet implemented")
    sys.exit(1)


if __name__ == '__main__':
    main()
