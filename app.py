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
    page_icon="",
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
if 'noise_level' not in st.session_state:
    st.session_state.noise_level = 'Synthetic (Clean)'

# Sidebar navigation
st.sidebar.title("AI-IDS Simulation")
page = st.sidebar.radio(
    "Navigation",
    ["Home", "Generate Traffic", "Train Models", "Run Detection", "Attack Simulator", "Compare Models", "About"]
)

# Home Page
if page == "Home":
    st.markdown('<div class="main-header">AI-Driven Intrusion Detection System</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Welcome to the AI-IDS Simulation Tool
    
    This interactive dashboard allows you to:
    -  Generate synthetic network traffic with configurable attack patterns
    -  Train machine learning models (Decision Tree & KNN)
    -  Detect intrusions in network traffic
    -  Visualize performance metrics and compare models
    
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
    st.header(" Generate Synthetic Network Traffic")
    
    col1, col2 = st.columns(2)
    
    with col1:
        num_samples = st.number_input("Number of Samples", min_value=100, max_value=100000, value=10000, step=1000)
        attack_ratio = st.slider("Attack Ratio", min_value=0.0, max_value=1.0, value=0.3, step=0.05)
    
    with col2:
        noise_level = st.select_slider(
            "Data Realism Level",
            options=["Synthetic (Clean)", "Low Noise", "Medium Noise", "High Noise (Realistic)"],
            value="Synthetic (Clean)",
            help="Higher noise makes data more realistic but harder to classify perfectly"
        )
        
        st.info(f"""
        **Configuration:**
        - Total Samples: {num_samples:,}
        - Benign Traffic: {int(num_samples * (1 - attack_ratio)):,}
        - Malicious Traffic: {int(num_samples * attack_ratio):,}
        - Noise Level: {noise_level}
        """)
    
    if st.button("Generate Dataset", type="primary"):
        with st.spinner("Generating traffic data..."):
            # Map noise level to numeric value
            noise_map = {
                "Synthetic (Clean)": 0.0,
                "Low Noise": 0.1,
                "Medium Noise": 0.25,
                "High Noise (Realistic)": 0.5
            }
            noise_factor = noise_map[noise_level]
            
            generator = TrafficGenerator()
            dataset = generator.generate_dataset(num_samples, attack_ratio)
            
            # Add noise if requested
            if noise_factor > 0:
                st.info(f"Adding {noise_level} to make data more realistic...")
                
                # Add random noise to continuous features
                for col in ['packet_size', 'packet_rate', 'duration']:
                    if col in dataset.columns:
                        noise = np.random.normal(0, dataset[col].std() * noise_factor, len(dataset))
                        dataset[col] = dataset[col] + noise
                        dataset[col] = dataset[col].clip(lower=0)  # Keep values positive
                
                # Add noise to flag counts
                for col in ['syn_flag', 'ack_flag', 'fin_flag', 'failed_logins']:
                    if col in dataset.columns:
                        noise = np.random.randint(-int(2*noise_factor*10), int(2*noise_factor*10)+1, len(dataset))
                        dataset[col] = (dataset[col] + noise).clip(lower=0)
                
                # Randomly flip some labels (label noise)
                if noise_factor >= 0.25:
                    flip_ratio = noise_factor * 0.1  # Up to 5% label noise at highest setting
                    num_flips = int(len(dataset) * flip_ratio)
                    flip_indices = np.random.choice(len(dataset), num_flips, replace=False)
                    dataset.loc[flip_indices, 'label'] = dataset.loc[flip_indices, 'label'].apply(
                        lambda x: 'benign' if x == 'malicious' else 'malicious'
                    )
                    st.warning(f"Added {num_flips} mislabeled samples to simulate real-world noise")
            
            st.session_state.dataset = dataset
            st.session_state.noise_level = noise_level
            
            # Save to file
            os.makedirs('data', exist_ok=True)
            dataset.to_csv('data/web_traffic.csv', index=False)
            
            st.success(f" Generated {len(dataset):,} samples successfully!")
    
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
    st.header(" Train Machine Learning Models")
    
    if st.session_state.dataset is None:
        st.warning(" Please generate a dataset first!")
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
                    
                    st.success(" Decision Tree trained successfully!")
                    
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
                    
                    st.success(" KNN trained successfully!")
                    
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
    st.header(" Run Intrusion Detection")
    
    if not st.session_state.models:
        st.warning(" Please train at least one model first!")
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
                    
                    st.success(" Detection completed!")
                    
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

# Attack Simulator Page
elif page == "Attack Simulator":
    st.header(" Cyber Attack Simulator")
    
    st.markdown("""
    Simulate different types of cyber attacks and see how the AI-IDS detects them in real-time.
    This demonstrates the model's ability to identify various attack patterns.
    """)
    
    if not st.session_state.models:
        st.warning(" Please train at least one model first!")
    else:
        model_choice = st.selectbox("Select Detection Model", list(st.session_state.models.keys()))
        
        # Attack type selection
        st.subheader(" Select Attack Type")
        
        attack_type = st.radio(
            "Choose an attack to simulate:",
            ["Denial of Service (DoS)", "Port Scanning", "Unauthorized Access", "Mixed Attack Campaign", "Custom Attack"]
        )
        
        # Attack parameters based on type
        col1, col2 = st.columns(2)
        
        with col1:
            num_attack_packets = st.slider("Number of Attack Packets", 10, 500, 100)
            num_benign_packets = st.slider("Number of Benign Packets (Background)", 0, 200, 50)
        
        with col2:
            if attack_type == "Denial of Service (DoS)":
                st.info("""
                **DoS Attack Characteristics:**
                - High packet rate (500-2000 pkt/s)
                - Small packet sizes
                - Many SYN flags
                - Short connection durations
                - Targets web servers (ports 80, 443)
                """)
                intensity = st.select_slider("Attack Intensity", ["Low", "Medium", "High", "Extreme"], value="High")
            
            elif attack_type == "Port Scanning":
                st.info("""
                **Port Scan Characteristics:**
                - Sequential port access
                - Quick connection attempts
                - SYN packets without ACK
                - Probing multiple ports
                - Reconnaissance activity
                """)
                scan_range = st.slider("Port Range to Scan", 10, 1000, 100)
            
            elif attack_type == "Unauthorized Access":
                st.info("""
                **Unauthorized Access Characteristics:**
                - Multiple failed login attempts
                - Targets SSH, FTP, RDP ports
                - Brute force patterns
                - Repeated authentication failures
                """)
                failed_attempts = st.slider("Failed Login Attempts", 3, 50, 10)
            
            elif attack_type == "Mixed Attack Campaign":
                st.info("""
                **Mixed Campaign:**
                - Combination of multiple attack types
                - Simulates APT (Advanced Persistent Threat)
                - Tests model's versatility
                - More realistic attack scenario
                """)
                attack_mix = st.multiselect(
                    "Select attack types to include:",
                    ["DoS", "Port Scan", "Unauthorized Access"],
                    default=["DoS", "Port Scan", "Unauthorized Access"]
                )
            
            else:  # Custom Attack
                st.info("""
                **Custom Attack:**
                - Configure your own attack parameters
                - Experiment with different patterns
                """)
                custom_packet_rate = st.slider("Packet Rate", 1, 2000, 500)
                custom_syn_flags = st.slider("SYN Flags", 0, 20, 10)
        
        if st.button(" Launch Attack Simulation", type="primary"):
            with st.spinner("Simulating attack..."):
                model_info = st.session_state.models[model_choice]
                trainer = model_info['trainer']
                model = model_info['model']
                
                # Generate attack traffic based on type
                generator = TrafficGenerator()
                attack_packets = []
                
                if attack_type == "Denial of Service (DoS)":
                    intensity_map = {"Low": 0.5, "Medium": 1.0, "High": 1.5, "Extreme": 2.0}
                    multiplier = intensity_map[intensity]
                    
                    for i in range(num_attack_packets):
                        packet = generator._create_dos_packet(i * 0.001)
                        packet['packet_rate'] *= multiplier
                        attack_packets.append(packet)
                
                elif attack_type == "Port Scanning":
                    for i in range(num_attack_packets):
                        packet = generator._create_port_scan_packet(i * 0.01)
                        packet['dst_port'] = 1000 + (i % scan_range)
                        attack_packets.append(packet)
                
                elif attack_type == "Unauthorized Access":
                    for i in range(num_attack_packets):
                        packet = generator._create_unauthorized_access_packet(i * 0.1)
                        packet['failed_logins'] = np.random.randint(failed_attempts // 2, failed_attempts)
                        attack_packets.append(packet)
                
                elif attack_type == "Mixed Attack Campaign":
                    packets_per_type = num_attack_packets // len(attack_mix)
                    for attack in attack_mix:
                        for i in range(packets_per_type):
                            if attack == "DoS":
                                packet = generator._create_dos_packet(i * 0.001)
                            elif attack == "Port Scan":
                                packet = generator._create_port_scan_packet(i * 0.01)
                            else:
                                packet = generator._create_unauthorized_access_packet(i * 0.1)
                            attack_packets.append(packet)
                
                else:  # Custom Attack
                    for i in range(num_attack_packets):
                        packet = generator._create_dos_packet(i * 0.001)
                        packet['packet_rate'] = custom_packet_rate
                        packet['syn_flag'] = custom_syn_flags
                        attack_packets.append(packet)
                
                # Add benign background traffic
                benign_packets = []
                for i in range(num_benign_packets):
                    packet = generator._create_benign_packet(i * 0.5)
                    benign_packets.append(packet)
                
                # Combine and shuffle
                all_packets = attack_packets + benign_packets
                np.random.shuffle(all_packets)
                
                # Create dataframe
                attack_df = pd.DataFrame(all_packets)
                
                # Run detection
                X = attack_df[trainer.feature_columns].values
                y_pred = model.predict(X)
                
                if hasattr(model, 'predict_proba'):
                    probabilities = model.predict_proba(X)
                    confidences = np.max(probabilities, axis=1)
                else:
                    confidences = np.ones(len(y_pred))
                
                predictions = trainer.label_encoder.inverse_transform(y_pred)
                
                # Calculate detection metrics
                total_attacks = len(attack_packets)
                detected_attacks = sum(1 for i, p in enumerate(predictions) if p == 'malicious' and i < total_attacks)
                false_positives = sum(1 for i, p in enumerate(predictions) if p == 'malicious' and i >= total_attacks)
                
                detection_rate = detected_attacks / total_attacks if total_attacks > 0 else 0
                false_positive_rate = false_positives / num_benign_packets if num_benign_packets > 0 else 0
                
                # Display results
                st.success(" Attack simulation completed!")
                
                # Key metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Detection Rate", f"{detection_rate:.1%}", 
                             delta="Good" if detection_rate > 0.8 else "Needs Improvement")
                with col2:
                    st.metric("Attacks Detected", f"{detected_attacks}/{total_attacks}")
                with col3:
                    st.metric("False Positives", false_positives,
                             delta="Low" if false_positives < 5 else "High", delta_color="inverse")
                with col4:
                    avg_confidence = np.mean(confidences[:total_attacks])
                    st.metric("Avg Confidence", f"{avg_confidence:.1%}")
                
                # Visualization: Detection Timeline
                st.subheader(" Attack Detection Timeline")
                
                fig = go.Figure()
                
                # Mark attack packets
                attack_indices = list(range(total_attacks))
                attack_detected = [predictions[i] == 'malicious' for i in attack_indices]
                
                colors = ['#e74c3c' if detected else '#f39c12' for detected in attack_detected]
                
                fig.add_trace(go.Scatter(
                    x=attack_indices,
                    y=confidences[:total_attacks],
                    mode='markers',
                    name='Attack Packets',
                    marker=dict(
                        color=colors,
                        size=10,
                        line=dict(width=1, color='white')
                    ),
                    text=['Detected' if d else 'Missed' for d in attack_detected],
                    hovertemplate='<b>Attack Packet</b><br>Index: %{x}<br>Confidence: %{y:.2%}<br>Status: %{text}<extra></extra>'
                ))
                
                # Mark benign packets
                if num_benign_packets > 0:
                    benign_indices = list(range(total_attacks, len(predictions)))
                    benign_detected = [predictions[i] == 'malicious' for i in benign_indices]
                    
                    benign_colors = ['#e74c3c' if detected else '#2ecc71' for detected in benign_detected]
                    
                    fig.add_trace(go.Scatter(
                        x=benign_indices,
                        y=confidences[total_attacks:],
                        mode='markers',
                        name='Benign Packets',
                        marker=dict(
                            color=benign_colors,
                            size=8,
                            symbol='diamond'
                        ),
                        text=['False Positive' if d else 'Correct' for d in benign_detected],
                        hovertemplate='<b>Benign Packet</b><br>Index: %{x}<br>Confidence: %{y:.2%}<br>Status: %{text}<extra></extra>'
                    ))
                
                fig.update_layout(
                    title=f"{attack_type} Detection Results",
                    xaxis_title="Packet Index",
                    yaxis_title="Detection Confidence",
                    height=500,
                    hovermode='closest'
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Attack characteristics analysis
                st.subheader(" Attack Pattern Analysis")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Packet rate distribution
                    fig = go.Figure()
                    fig.add_trace(go.Histogram(
                        x=attack_df['packet_rate'][:total_attacks],
                        name='Attack Traffic',
                        marker_color='#e74c3c',
                        opacity=0.7
                    ))
                    if num_benign_packets > 0:
                        fig.add_trace(go.Histogram(
                            x=attack_df['packet_rate'][total_attacks:],
                            name='Benign Traffic',
                            marker_color='#2ecc71',
                            opacity=0.7
                        ))
                    fig.update_layout(
                        title="Packet Rate Distribution",
                        xaxis_title="Packets/Second",
                        yaxis_title="Count",
                        barmode='overlay',
                        height=300
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # Protocol distribution
                    protocol_map = {0: 'TCP', 1: 'UDP', 2: 'ICMP'}
                    attack_protocols = [protocol_map.get(p, 'Unknown') for p in attack_df['protocol'][:total_attacks]]
                    protocol_counts = pd.Series(attack_protocols).value_counts()
                    
                    fig = go.Figure(data=[go.Pie(
                        labels=protocol_counts.index,
                        values=protocol_counts.values,
                        hole=0.4
                    )])
                    fig.update_layout(title="Attack Protocol Distribution", height=300)
                    st.plotly_chart(fig, use_container_width=True)
                
                # Detailed attack breakdown
                st.subheader("📋 Detection Breakdown")
                
                breakdown_data = {
                    'Category': ['Total Attacks', 'Detected', 'Missed', 'Benign Traffic', 'False Positives'],
                    'Count': [
                        total_attacks,
                        detected_attacks,
                        total_attacks - detected_attacks,
                        num_benign_packets,
                        false_positives
                    ],
                    'Percentage': [
                        '100%',
                        f'{detection_rate:.1%}',
                        f'{(1-detection_rate):.1%}' if total_attacks > 0 else '0%',
                        '100%' if num_benign_packets > 0 else 'N/A',
                        f'{false_positive_rate:.1%}' if num_benign_packets > 0 else 'N/A'
                    ]
                }
                
                st.table(pd.DataFrame(breakdown_data))
                
                # Recommendations
                st.subheader(" Analysis & Recommendations")
                
                if detection_rate >= 0.95:
                    st.success(" **Excellent Detection!** The model successfully identified most attack packets.")
                elif detection_rate >= 0.80:
                    st.info(" **Good Detection.** The model caught most attacks but could be improved.")
                else:
                    st.warning(" **Detection Needs Improvement.** Consider retraining with more diverse attack samples.")
                
                if false_positive_rate > 0.1:
                    st.warning(f" **High False Positive Rate ({false_positive_rate:.1%}).** The model may be too sensitive.")
                elif false_positive_rate > 0:
                    st.info(f" **Low False Positive Rate ({false_positive_rate:.1%}).** Acceptable performance.")
                else:
                    st.success(" **No False Positives!** Perfect classification of benign traffic.")
                
                # Export results
                st.markdown("---")
                if st.button(" Export Attack Simulation Results"):
                    results_data = {
                        'attack_type': attack_type,
                        'total_packets': len(all_packets),
                        'attack_packets': total_attacks,
                        'detected': detected_attacks,
                        'detection_rate': detection_rate,
                        'false_positives': false_positives,
                        'model_used': model_choice
                    }
                    
                    st.json(results_data)
                    st.success("Results ready for export!")

elif page == "Compare Models":
    st.header(" Compare Model Performance")
    
    if len(st.session_state.results) < 2:
        st.warning(" Please train at least 2 models to compare!")
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
        
        # Overfitting Analysis
        st.markdown("---")
        st.subheader("Overfitting Analysis")
        
        st.markdown("""
        **Understanding Model Performance:**
        
        When comparing these models, consider the following insights:
        """)
        
        # Check if we have noise level info
        noise_level = st.session_state.get('noise_level', 'Unknown')
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **Decision Tree Characteristics:**
            - Creates hard decision boundaries
            - Can perfectly memorize training patterns
            - Prone to overfitting on clean data
            - May struggle with novel variations
            """)
            
            if 'Decision Tree' in df_comparison['Model'].values:
                dt_acc = df_comparison[df_comparison['Model'] == 'Decision Tree']['Accuracy'].values[0]
                if dt_acc >= 0.99:
                    st.warning("""
                    **Potential Overfitting Detected!**
                    
                    The Decision Tree achieved near-perfect accuracy, which may indicate:
                    - Memorization of training patterns
                    - May not generalize to real-world traffic
                    - Could fail on novel attack variations
                    """)
        
        with col2:
            st.markdown("""
            **K-Nearest Neighbors Characteristics:**
            - Distance-based classification
            - More robust to noise
            - Better generalization potential
            - Slower on large datasets
            """)
            
            if 'KNN' in df_comparison['Model'].values:
                knn_acc = df_comparison[df_comparison['Model'] == 'KNN']['Accuracy'].values[0]
                if knn_acc < 0.99:
                    st.info("""
                    **Better Generalization:**
                    
                    KNN's slightly lower accuracy may actually indicate:
                    - Less overfitting to training data
                    - Better performance on real-world traffic
                    - More robust to variations in attack patterns
                    """)
        
        st.markdown(f"""
        **Data Realism Level:** {noise_level}
        
        **Research Insight:** The performance gap between models reveals important trade-offs:
        - **Clean synthetic data** → Decision Trees can achieve perfect accuracy through memorization
        - **Realistic noisy data** → KNN may outperform due to better generalization
        - **Real-world deployment** → Models trained on realistic data are more reliable
        
        **Recommendation:** For production IDS systems, prefer models that maintain high accuracy 
        on noisy/realistic data rather than perfect accuracy on clean synthetic data.
        """)

# About Page
elif page == "About":
    st.header(" About AI-IDS Simulation Tool")
    
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
