#!/usr/bin/env python3
"""
AI-IDS Simulation Tool - Web Dashboard
Interactive web interface for the IDS simulation tool
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import os
import json
from src.traffic_generator import TrafficGenerator
from src.model_trainer import DecisionTreeTrainer, KNNTrainer
from src.detection_engine import DetectionEngine, ModelEvaluator
from src.config_manager import ConfigManager

# Page configuration
st.set_page_config(
    page_title="AI-IDS Simulation Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'dataset' not in st.session_state:
    st.session_state.dataset = None
if 'models' not in st.session_state:
    st.session_state.models = {}
if 'results' not in st.session_state:
    st.session_state.results = {}

# Sidebar navigation
st.sidebar.title("🛡️ AI-IDS Simulation")
page = st.sidebar.radio(
    "Navigation",
    ["Home", "Generate Traffic", "Train Models", "Run Detection", "Compare Models", "About"]
)

# Home Page
if page == "Home":
    st.markdown('<div class="main-header">AI-Driven Intrusion Detection System</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Welcome to the AI-IDS Simulation Tool
    
    This interactive dashboard allows you to:
    - 🔄 Generate synthetic network traffic with configurable attack patterns
    - 🤖 Train machine learning models (Decision Tree & KNN)
    - 🔍 Detect intrusions in network traffic
    - 📊 Visualize performance metrics and compare models
    
    **Get Started:**
    1. Navigate to "Generate Traffic" to create a dataset
    2. Go to "Train Models" to train ML models
    3. Use "Run Detection" to test the models
    4. Compare results in "Compare Models"
    """)
    
    # Quick stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Dataset Samples", 
                 len(st.session_state.dataset) if st.session_state.dataset is not None else 0)
    
    with col2:
        st.metric("Trained Models", len(st.session_state.models))
    
    with col3:
        st.metric("Detection Runs", len(st.session_state.results))
    
    with col4:
        if st.session_state.results:
            avg_acc = np.mean([r['accuracy'] for r in st.session_state.results.values()])
            st.metric("Avg Accuracy", f"{avg_acc:.2%}")
        else:
            st.metric("Avg Accuracy", "N/A")

# Generate Traffic Page
elif page == "Generate Traffic":
    st.header("🔄 Generate Synthetic Network Traffic")
    
    col1, col2 = st.columns(2)
    
    with col1:
        num_samples = st.number_input("Number of Samples", min_value=100, max_value=100000, value=10000, step=1000)
        attack_ratio = st.slider("Attack Ratio", min_value=0.0, max_value=1.0, value=0.3, step=0.05)
    
    with col2:
        st.info(f"""
        **Configuration:**
        - Total Samples: {num_samples:,}
        - Benign Traffic: {int(num_samples * (1 - attack_ratio)):,}
        - Malicious Traffic: {int(num_samples * attack_ratio):,}
        """)
    
    if st.button("Generate Dataset", type="primary"):
        with st.spinner("Generating traffic data..."):
            generator = TrafficGenerator()
            dataset = generator.generate_dataset(num_samples, attack_ratio)
            st.session_state.dataset = dataset
            
            # Save to file
            os.makedirs('data', exist_ok=True)
            dataset.to_csv('data/web_traffic.csv', index=False)
            
            st.success(f"✅ Generated {len(dataset):,} samples successfully!")
    
    # Display dataset preview
    if st.session_state.dataset is not None:
        st.subheader("Dataset Preview")
        
        # Statistics
        col1, col2, col3 = st.columns(3)
        benign_count = len(st.session_state.dataset[st.session_state.dataset['label'] == 'benign'])
        malicious_count = len(st.session_state.dataset[st.session_state.dataset['label'] == 'malicious'])
        
        with col1:
            st.metric("Total Samples", len(st.session_state.dataset))
        with col2:
            st.metric("Benign", benign_count)
        with col3:
            st.metric("Malicious", malicious_count)
        
        # Distribution chart
        fig = go.Figure(data=[
            go.Bar(name='Count', x=['Benign', 'Malicious'], 
                   y=[benign_count, malicious_count],
                   marker_color=['#2ecc71', '#e74c3c'])
        ])
        fig.update_layout(title="Traffic Distribution", height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        # Data table
        st.dataframe(st.session_state.dataset.head(100), use_container_width=True)
        
        # Download button
        csv = st.session_state.dataset.to_csv(index=False)
        st.download_button(
            label="Download Dataset as CSV",
            data=csv,
            file_name="traffic_dataset.csv",
            mime="text/csv"
        )

# Train Models Page
elif page == "Train Models":
    st.header("🤖 Train Machine Learning Models")
    
    if st.session_state.dataset is None:
        st.warning("⚠️ Please generate a dataset first!")
    else:
        tab1, tab2 = st.tabs(["Decision Tree", "K-Nearest Neighbors"])
        
        # Decision Tree Tab
        with tab1:
            st.subheader("Decision Tree Classifier")
            
            col1, col2 = st.columns(2)
            with col1:
                dt_max_depth = st.slider("Max Depth", min_value=3, max_value=30, value=10)
                dt_min_samples = st.slider("Min Samples Split", min_value=2, max_value=20, value=5)
            
            with col2:
                dt_criterion = st.selectbox("Criterion", ["gini", "entropy"])
            
            if st.button("Train Decision Tree", type="primary", key="train_dt"):
                with st.spinner("Training Decision Tree..."):
                    trainer = DecisionTreeTrainer()
                    X_train, X_test, y_train, y_test = trainer.preprocess_data(st.session_state.dataset)
                    
                    hyperparameters = {
                        'max_depth': dt_max_depth,
                        'min_samples_split': dt_min_samples,
                        'criterion': dt_criterion
                    }
                    
                    model = trainer.train(X_train, y_train, hyperparameters)
                    
                    # Evaluate
                    y_pred = model.predict(X_test)
                    metrics = ModelEvaluator.calculate_metrics(y_test, y_pred)
                    
                    # Save model
                    os.makedirs('models', exist_ok=True)
                    trainer.save_model(model, 'models/web_dt_model.pkl')
                    
                    # Store in session
                    st.session_state.models['Decision Tree'] = {
                        'model': model,
                        'trainer': trainer,
                        'metrics': metrics,
                        'hyperparameters': hyperparameters
                    }
                    st.session_state.results['Decision Tree'] = metrics
                    
                    st.success("✅ Decision Tree trained successfully!")
                    
                    # Display metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Accuracy", f"{metrics['accuracy']:.2%}")
                    with col2:
                        st.metric("Precision", f"{metrics['precision']:.2%}")
                    with col3:
                        st.metric("Recall", f"{metrics['recall']:.2%}")
                    with col4:
                        st.metric("F1-Score", f"{metrics['f1_score']:.2%}")
        
        # KNN Tab
        with tab2:
            st.subheader("K-Nearest Neighbors Classifier")
            
            col1, col2 = st.columns(2)
            with col1:
                knn_neighbors = st.slider("Number of Neighbors (k)", min_value=1, max_value=20, value=5)
                knn_weights = st.selectbox("Weights", ["uniform", "distance"])
            
            with col2:
                knn_metric = st.selectbox("Distance Metric", ["euclidean", "manhattan", "minkowski"])
            
            if st.button("Train KNN", type="primary", key="train_knn"):
                with st.spinner("Training KNN..."):
                    trainer = KNNTrainer()
                    X_train, X_test, y_train, y_test = trainer.preprocess_data(st.session_state.dataset)
                    
                    hyperparameters = {
                        'n_neighbors': knn_neighbors,
                        'weights': knn_weights,
                        'metric': knn_metric
                    }
                    
                    model = trainer.train(X_train, y_train, hyperparameters)
                    
                    # Evaluate
                    y_pred = model.predict(X_test)
                    metrics = ModelEvaluator.calculate_metrics(y_test, y_pred)
                    
                    # Save model
                    os.makedirs('models', exist_ok=True)
                    trainer.save_model(model, 'models/web_knn_model.pkl')
                    
                    # Store in session
                    st.session_state.models['KNN'] = {
                        'model': model,
                        'trainer': trainer,
                        'metrics': metrics,
                        'hyperparameters': hyperparameters
                    }
                    st.session_state.results['KNN'] = metrics
                    
                    st.success("✅ KNN trained successfully!")
                    
                    # Display metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Accuracy", f"{metrics['accuracy']:.2%}")
                    with col2:
                        st.metric("Precision", f"{metrics['precision']:.2%}")
                    with col3:
                        st.metric("Recall", f"{metrics['recall']:.2%}")
                    with col4:
                        st.metric("F1-Score", f"{metrics['f1_score']:.2%}")

# Run Detection Page
elif page == "Run Detection":
    st.header("🔍 Run Intrusion Detection")
    
    if not st.session_state.models:
        st.warning("⚠️ Please train at least one model first!")
    else:
        model_choice = st.selectbox("Select Model", list(st.session_state.models.keys()))
        
        # File upload or use existing dataset
        data_source = st.radio("Data Source", ["Use Generated Dataset", "Upload CSV File"])
        
        test_data = None
        if data_source == "Use Generated Dataset":
            if st.session_state.dataset is not None:
                test_data = st.session_state.dataset
        else:
            uploaded_file = st.file_uploader("Upload CSV file", type=['csv'])
            if uploaded_file is not None:
                test_data = pd.read_csv(uploaded_file)
        
        if test_data is not None and st.button("Run Detection", type="primary"):
            with st.spinner("Running detection..."):
                model_info = st.session_state.models[model_choice]
                trainer = model_info['trainer']
                model = model_info['model']
                
                # Prepare data
                X = test_data[trainer.feature_columns].values
                
                if 'label' in test_data.columns:
                    y_true = trainer.label_encoder.transform(test_data['label'].values)
                    y_pred = model.predict(X)
                    
                    metrics = ModelEvaluator.calculate_metrics(y_true, y_pred)
                    
                    st.success("✅ Detection completed!")
                    
                    # Display metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Accuracy", f"{metrics['accuracy']:.2%}")
                    with col2:
                        st.metric("Precision", f"{metrics['precision']:.2%}")
                    with col3:
                        st.metric("Recall", f"{metrics['recall']:.2%}")
                    with col4:
                        st.metric("F1-Score", f"{metrics['f1_score']:.2%}")
                    
                    # Confusion Matrix
                    st.subheader("Confusion Matrix")
                    cm = metrics['confusion_matrix']
                    
                    fig = go.Figure(data=go.Heatmap(
                        z=cm,
                        x=['Benign', 'Malicious'],
                        y=['Benign', 'Malicious'],
                        colorscale='Blues',
                        text=cm,
                        texttemplate='%{text}',
                        textfont={"size": 20}
                    ))
                    fig.update_layout(
                        title="Confusion Matrix",
                        xaxis_title="Predicted",
                        yaxis_title="Actual",
                        height=500
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Detection distribution
                    predictions = trainer.label_encoder.inverse_transform(y_pred)
                    pred_counts = pd.Series(predictions).value_counts()
                    
                    fig = go.Figure(data=[
                        go.Bar(x=pred_counts.index, y=pred_counts.values,
                               marker_color=['#2ecc71' if x == 'benign' else '#e74c3c' for x in pred_counts.index])
                    ])
                    fig.update_layout(title="Detection Results Distribution", height=400)
                    st.plotly_chart(fig, use_container_width=True)

# Compare Models Page
elif page == "Compare Models":
    st.header("📊 Compare Model Performance")
    
    if len(st.session_state.results) < 2:
        st.warning("⚠️ Please train at least 2 models to compare!")
    else:
        # Metrics comparison
        metrics_to_compare = ['accuracy', 'precision', 'recall', 'f1_score']
        metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        
        # Create comparison dataframe
        comparison_data = []
        for model_name, metrics in st.session_state.results.items():
            comparison_data.append({
                'Model': model_name,
                'Accuracy': metrics['accuracy'],
                'Precision': metrics['precision'],
                'Recall': metrics['recall'],
                'F1-Score': metrics['f1_score'],
                'FPR': metrics['false_positive_rate'],
                'TPR': metrics['true_positive_rate']
            })
        
        df_comparison = pd.DataFrame(comparison_data)
        
        # Display table
        st.subheader("Performance Metrics")
        st.dataframe(df_comparison.style.format({
            'Accuracy': '{:.2%}',
            'Precision': '{:.2%}',
            'Recall': '{:.2%}',
            'F1-Score': '{:.2%}',
            'FPR': '{:.2%}',
            'TPR': '{:.2%}'
        }), use_container_width=True)
        
        # Bar chart comparison
        fig = go.Figure()
        for model_name in df_comparison['Model']:
            model_data = df_comparison[df_comparison['Model'] == model_name].iloc[0]
            fig.add_trace(go.Bar(
                name=model_name,
                x=metric_labels,
                y=[model_data['Accuracy'], model_data['Precision'], 
                   model_data['Recall'], model_data['F1-Score']]
            ))
        
        fig.update_layout(
            title="Model Performance Comparison",
            xaxis_title="Metrics",
            yaxis_title="Score",
            barmode='group',
            height=500
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Radar chart
        fig = go.Figure()
        for model_name in df_comparison['Model']:
            model_data = df_comparison[df_comparison['Model'] == model_name].iloc[0]
            fig.add_trace(go.Scatterpolar(
                r=[model_data['Accuracy'], model_data['Precision'], 
                   model_data['Recall'], model_data['F1-Score']],
                theta=metric_labels,
                fill='toself',
                name=model_name
            ))
        
        fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
            title="Model Performance Radar Chart",
            height=500
        )
        st.plotly_chart(fig, use_container_width=True)

# About Page
elif page == "About":
    st.header("ℹ️ About AI-IDS Simulation Tool")
    
    st.markdown("""
    ### Project Overview
    
    This AI-Driven Intrusion Detection System (IDS) Simulation Tool demonstrates how machine learning 
    techniques can enhance network security by detecting malicious traffic patterns.
    
    ### Features
    
    - **Traffic Generation**: Creates synthetic network traffic with realistic benign and malicious patterns
    - **ML Models**: Implements Decision Tree and K-Nearest Neighbors classifiers
    - **Attack Types**: Simulates DoS, Port Scanning, and Unauthorized Access attacks
    - **Performance Metrics**: Comprehensive evaluation with accuracy, precision, recall, F1-score, and confusion matrices
    - **Interactive Dashboard**: Web-based interface for easy experimentation
    
    ### Technology Stack
    
    - **Python 3.8+**
    - **scikit-learn**: Machine learning algorithms
    - **Pandas & NumPy**: Data processing
    - **Streamlit**: Web dashboard
    - **Plotly**: Interactive visualizations
    
    ### Research Context
    
    This tool supports academic research on AI-driven intrusion detection systems, demonstrating:
    - How ML models can adapt to evolving threats
    - Performance comparison between different algorithms
    - Real-time detection capabilities
    
    ### Usage
    
    1. Generate synthetic network traffic with configurable parameters
    2. Train Decision Tree and KNN models
    3. Run detection on test data
    4. Compare model performance
    5. Export results for research documentation
    
    ---
    
    **Version**: 1.0.0  
    **License**: Academic Research Use
    """)

# Footer
st.sidebar.markdown("---")
st.sidebar.info("AI-IDS Simulation Tool v1.0.0")
