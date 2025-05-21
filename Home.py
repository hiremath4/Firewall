import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime, timedelta
import random
import matplotlib.pyplot as plt
import pickle
import joblib
from sklearn.ensemble import RandomForestClassifier
import threading
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import Binarizer


# Set page configuration
st.set_page_config(
    page_title="AI Cyber Threat Intelligence System",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .threat-high {
        color: #ff4b4b;
        font-weight: bold;
    }
    .threat-medium {
        color: #ffa500;
        font-weight: bold;
    }
    .threat-low {
        color: #02b875;
        font-weight: bold;
    }
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1E90FF;
        margin-bottom: 1rem;
    }
    .subheader {
        font-size: 1.5rem;
        font-weight: bold;
        color: #4682B4;
        margin-bottom: 1rem;
    }
    .stButton button {
        background-color: #1E90FF;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state variables
if 'threat_data' not in st.session_state:
    st.session_state.threat_data = pd.DataFrame()

if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()

if 'ml_model' not in st.session_state:
    # Create a simple Random Forest model for demonstration
    # In a real app, you would load a pre-trained model
    st.session_state.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
    st.session_state.ml_model_trained = False

if 'predicted_threats' not in st.session_state:
    st.session_state.predicted_threats = []

if 'attack_simulation' not in st.session_state:
    st.session_state.attack_simulation = False

# Function to get features from threat data for ML model
def extract_features(df):
    # Extract time-based features
    df['hour'] = df['Timestamp'].dt.hour
    df['day_of_week'] = df['Timestamp'].dt.dayofweek
    
    # One-hot encode categorical features
    threat_dummies = pd.get_dummies(df['Threat Type'], prefix='threat')
    severity_dummies = pd.get_dummies(df['Severity'], prefix='severity')
    
    # Create numerical features from IP addresses (simplified)
    df['source_ip_first_octet'] = df['Source IP'].apply(lambda x: int(x.split('.')[0]))
    df['dest_ip_first_octet'] = df['Destination IP'].apply(lambda x: int(x.split('.')[0]))
    
    # Combine features
    features = pd.concat([
        df[['hour', 'day_of_week', 'source_ip_first_octet', 'dest_ip_first_octet', 'AI Confidence']],
        threat_dummies,
        severity_dummies
    ], axis=1)
    
    return features

# Function to train the ML model

def train_ml_model():
    if len(st.session_state.threat_data) > 0 and not st.session_state.ml_model_trained:
        # Create a target variable (for demonstration - in reality this would be based on actual outcomes)
        # Here we'll use a simple heuristic: high severity + high confidence = high risk
        df = st.session_state.threat_data.copy()
        df['is_high_risk'] = ((df['Severity'] == 'High') & (df['AI Confidence'] > 0.8)).astype(int)
        
        # Extract features
        features = extract_features(df)
        
        # Train the model
        st.session_state.ml_model.fit(features, df['is_high_risk'])
        st.session_state.ml_model_trained = True

# Function to predict threats
def predict_threats(df):
    if st.session_state.ml_model_trained:
        # Extract features
        features = extract_features(df)
        
        # Make predictions
        df['risk_score'] = st.session_state.ml_model.predict_proba(features)[:, 1]
        
        # Generate 7-day prediction
        dates = [(datetime.now() + timedelta(days=i)).strftime('%m/%d') for i in range(7)]
        base_prediction = int(df['risk_score'].mean() * 100)
        
        # Create a more realistic prediction with a trend
        predicted_threats = [
            max(5, base_prediction + random.randint(-5, 10) + i * random.randint(0, 3))
            for i in range(7)
        ]
        
        st.session_state.predicted_threats = list(zip(dates, predicted_threats))
        return df
    return df

# Generate some sample data for demonstration
def generate_threat_data(num_records=100, add_new=False):
    current_time = datetime.now()
    
    # If adding new data, generate fewer records
    if add_new:
        num_records = random.randint(1, 5)
    
    # Generate random times within the last hour
    times = [current_time - timedelta(minutes=random.randint(0, 60)) for _ in range(num_records)]
    times.sort(reverse=True)
    
    # IP addresses (source)
    source_ips = [f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(num_records)]
    
    # IP addresses (destination)
    dest_ips = [f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(num_records)]
    
    # Threat types - Added MITM to the threats
    threat_types = np.random.choice(
        ["Malware", "Phishing", "Network Intrusion", "DDoS", "Data Exfiltration", "Suspicious Login", "Man-in-the-Middle"], 
        num_records, 
        p=[0.2, 0.2, 0.15, 0.15, 0.1, 0.1, 0.1]  # Adjusted probabilities to include MITM
    )
    
    # Adjust probabilities if simulating an attack
    if st.session_state.attack_simulation:
        severity_probs = [0.6, 0.3, 0.1]  # Higher probability of high severity during attack
    else:
        severity_probs = [0.2, 0.3, 0.5]  # Normal probabilities
    
    # Severity
    severity = np.random.choice(["High", "Medium", "Low"], num_records, p=severity_probs)
    
    # AI confidence
    ai_confidence = [round(random.uniform(0.5, 0.99), 2) for _ in range(num_records)]
    
    # Status (resolved or not)
    status = np.random.choice(["Active", "Blocked", "Investigating"], num_records, p=[0.4, 0.4, 0.2])
    
    # Create DataFrame
    df = pd.DataFrame({
        "Timestamp": times,
        "Source IP": source_ips,
        "Destination IP": dest_ips,
        "Threat Type": threat_types,
        "Severity": severity,
        "AI Confidence": ai_confidence,
        "Status": status
    })
    
    # If adding to existing data, concatenate
    if add_new and not st.session_state.threat_data.empty:
        df = pd.concat([df, st.session_state.threat_data]).reset_index(drop=True)
    
    return df

# Function to filter data based on sidebar settings
def filter_data(df, malware_toggle, network_toggle, phishing_toggle, mitm_toggle):
    if df.empty:
        return df
        
    filtered_df = df.copy()
    
    # Apply filters based on toggles
    if not malware_toggle:
        filtered_df = filtered_df[filtered_df["Threat Type"] != "Malware"]
    if not network_toggle:
        filtered_df = filtered_df[filtered_df["Threat Type"] != "Network Intrusion"]
    if not phishing_toggle:
        filtered_df = filtered_df[filtered_df["Threat Type"] != "Phishing"]
    if not mitm_toggle:
        filtered_df = filtered_df[filtered_df["Threat Type"] != "Man-in-the-Middle"]
        
    return filtered_df

# Simulate attack function
def toggle_attack_simulation():
    st.session_state.attack_simulation = not st.session_state.attack_simulation
    
    # Update system status
    if st.session_state.attack_simulation:
        st.session_state.system_status = "⚠️ Attack Detected!"
        # Generate some high-severity threats immediately
        attack_data = generate_threat_data(num_records=5, add_new=False)
        attack_data["Severity"] = "High"
        attack_data["Status"] = "Active"
        attack_data["Threat Type"] = np.random.choice(
            ["Malware", "Network Intrusion", "DDoS", "Man-in-the-Middle"], 
            5, 
            p=[0.3, 0.3, 0.2, 0.2]  # Added MITM to attack simulation
        )
        st.session_state.threat_data = pd.concat([attack_data, st.session_state.threat_data]).reset_index(drop=True)
    else:
        st.session_state.system_status = "System Online"

# Get specific AI recommendations based on threat type
def get_ai_prevention_recommendations(threat_types):
    recommendations = {
        "Malware": [
            "Deploy advanced endpoint protection with AI-based malware detection",
            "Implement application whitelisting to prevent unauthorized software execution",
            "Schedule regular automated system scans during off-hours",
            "Deploy behavioral analytics to detect unusual file system activities"
        ],
        "Phishing": [
            "Enable AI-powered email filtering with URL and attachment scanning",
            "Implement DMARC, SPF, and DKIM email authentication",
            "Deploy an AI solution to analyze email content and sender reputation",
            "Set up automated phishing awareness training with simulated attacks"
        ],
        "Network Intrusion": [
            "Deploy an AI-enhanced IDS/IPS system that adapts to new attack patterns",
            "Implement zero-trust network architecture with continuous verification",
            "Use AI-based traffic analysis to identify anomalous patterns",
            "Set up automated network segmentation based on threat intelligence"
        ],
        "DDoS": [
            "Implement AI-based traffic monitoring to detect volumetric anomalies",
            "Configure automated rate limiting and traffic filtering",
            "Set up geographically distributed denial of service protection",
            "Deploy traffic pattern analysis to identify and block attack signatures"
        ],
        "Data Exfiltration": [
            "Deploy AI-powered data loss prevention (DLP) with content inspection",
            "Implement automated encryption for sensitive data transfers",
            "Set up ML-based user behavior analytics to detect unusual access patterns",
            "Configure automated alerts for large or unusual data transfers"
        ],
        "Suspicious Login": [
            "Implement AI-based authentication monitoring with risk scoring",
            "Configure adaptive MFA triggered by anomalous login patterns",
            "Deploy ML-powered geo-velocity analysis for login attempts",
            "Set up automated account lockdowns based on behavior analytics"
        ],
        "Man-in-the-Middle": [
            "Enforce certificate pinning for critical communications",
            "Implement AI monitoring for TLS/SSL session characteristics",
            "Deploy automated detection of unexpected certificate changes",
            "Set up real-time verification of connection integrity",
            "Enable automatic HTTPS enforcement with HSTS preloading"
        ]
    }
    
    # Get unique threat types in the data
    unique_threats = threat_types.unique()
    
    # Collect relevant recommendations
    relevant_recs = []
    for threat in unique_threats:
        if threat in recommendations:
            # Add one recommendation per threat type
            relevant_recs.append(random.choice(recommendations[threat]))
    
    # Add general recommendations if needed
    general_recs = [
        "Deploy an AI-powered SOC automation platform to coordinate security responses",
        "Implement machine learning for real-time threat correlation and pattern recognition",
        "Set up automated security posture assessment with continuous improvement"
    ]
    
    # Ensure we have at least 3-5 recommendations
    while len(relevant_recs) < 3:
        rec = random.choice(general_recs)
        if rec not in relevant_recs:
            relevant_recs.append(rec)
    
    return relevant_recs[:5]  # Return at most 5 recommendations

# Initialize threat data if empty
if st.session_state.threat_data.empty:
    st.session_state.threat_data = generate_threat_data()
    # Train the model with initial data
    train_ml_model()
    # Make initial predictions
    st.session_state.threat_data = predict_threats(st.session_state.threat_data)

# Sidebar
with st.sidebar:

    st.markdown("## Settings")
    
    refresh_rate = st.slider("Refresh Rate (seconds)", 1, 30, 5)
    show_raw_data = st.checkbox("Show Raw Data", True)
    ai_mode = st.selectbox("AI Analysis Mode", ["Basic", "Advanced"])
    
    st.markdown("## Threat Categories")
    
    malware_toggle = st.toggle("Malware Detection", True)
    network_toggle = st.toggle("Network Intrusion", True)
    phishing_toggle = st.toggle("Phishing Attempts", True)
    mitm_toggle = st.toggle("Man-in-the-Middle", True)  # Added MITM toggle
    
    st.markdown("---")
    st.markdown("### System Status")
    
    if 'system_status' not in st.session_state:
        st.session_state.system_status = "System Online"
    
    system_status = st.empty()
    if st.session_state.system_status == "System Online":
        system_status.success(st.session_state.system_status)
    else:
        system_status.error(st.session_state.system_status)
    
    if st.button("Simulate Attack" if not st.session_state.attack_simulation else "End Attack Simulation"):
        toggle_attack_simulation()

# Main content
col1, col2 = st.columns([2, 1])



with col1:
    
    
    # Stats cards
    stat1, stat2, stat3, stat4 = st.columns(4)
    
    # Compute stats from the data
    filtered_data = filter_data(st.session_state.threat_data, malware_toggle, network_toggle, phishing_toggle, mitm_toggle)
    
    if not filtered_data.empty:
        high_severity = len(filtered_data[filtered_data["Severity"] == "High"])
        active_threats = len(filtered_data[filtered_data["Status"] == "Active"])
        mitigated = len(filtered_data[filtered_data["Status"] == "Blocked"])
        avg_confidence = filtered_data["AI Confidence"].mean()
        
        # If we have previous values, calculate deltas
        if 'prev_high_severity' in st.session_state:
            high_severity_delta = high_severity - st.session_state.prev_high_severity
            active_threats_delta = active_threats - st.session_state.prev_active_threats
            mitigated_delta = mitigated - st.session_state.prev_mitigated
            avg_confidence_delta = avg_confidence - st.session_state.prev_avg_confidence
        else:
            high_severity_delta = None
            active_threats_delta = None
            mitigated_delta = None
            avg_confidence_delta = None
        
        # Store current values for next iteration
        st.session_state.prev_high_severity = high_severity
        st.session_state.prev_active_threats = active_threats
        st.session_state.prev_mitigated = mitigated
        st.session_state.prev_avg_confidence = avg_confidence
        
        with stat1:
            st.metric(
                label="Active Threats", 
                value=active_threats, 
                delta=active_threats_delta
            )
        
        with stat2:
            st.metric(
                label="High Severity", 
                value=high_severity, 
                delta=high_severity_delta,
                delta_color="inverse"
            )
        
        with stat3:
            st.metric(
                label="Blocked", 
                value=mitigated, 
                delta=mitigated_delta
            )
        
        with stat4:
            st.metric(
                label="AI Confidence", 
                value=f"{avg_confidence:.2f}", 
                delta=f"{avg_confidence_delta:.2f}" if avg_confidence_delta is not None else None
            )
    
        # Threat distribution chart
        st.markdown("### Threat Distribution")
        
        # Prepare data for charts
        threat_counts = filtered_data["Threat Type"].value_counts()
        severity_counts = filtered_data["Severity"].value_counts()
        
        chart1, chart2 = st.columns(2)
        
        with chart1:
            # Fix for pie chart - ensure there's data and handle data properly
            if not threat_counts.empty:
                fig, ax = plt.subplots(figsize=(5, 3))
                # Use custom colors and ensure proper display
                colors = plt.cm.Blues(np.linspace(0.4, 0.8, len(threat_counts)))
                wedges, texts, autotexts = ax.pie(
                    threat_counts.values, 
                    labels=threat_counts.index, 
                    autopct='%1.1f%%', 
                    startangle=90,
                    colors=colors
                )
                # Enhance readability
                for text in texts:
                    text.set_fontsize(8)
                for autotext in autotexts:
                    autotext.set_fontsize(8)
                    autotext.set_color('white')
                ax.axis('equal')
                ax.set_title('Threat Type Distribution')
                plt.tight_layout()
                st.pyplot(fig)
            else:
                st.info("No threat data to display")
        
        with chart2:
            fig, ax = plt.subplots(figsize=(5, 3))
            colors = ['#ff4b4b', '#ffa500', '#02b875']
            severity_order = ['High', 'Medium', 'Low']
            # Ensure all severities are represented
            for sev in severity_order:
                if sev not in severity_counts:
                    severity_counts[sev] = 0
            # Sort by severity order
            severity_counts = severity_counts.reindex(severity_order)
            ax.bar(severity_counts.index, severity_counts.values, color=colors)
            ax.set_ylabel('Count')
            ax.set_title('Threat Severity')
            plt.tight_layout()
            st.pyplot(fig)
    
    # Recent threats table
    st.markdown("### Recent Threats")
    
    # Function to apply color to severity
    def highlight_severity(val):
        if val == "High":
            return 'threat-high'
        elif val == "Medium":
            return 'threat-medium'
        elif val == "Low":
            return 'threat-low'
        return ''
    
    # Display recent threats
    if not filtered_data.empty:
        recent_threats = filtered_data.head(10).copy()
        recent_threats["Timestamp"] = recent_threats["Timestamp"].dt.strftime("%H:%M:%S")
        
        # Format the table with colored severity
        for i, row in recent_threats.iterrows():
            severity_class = highlight_severity(row["Severity"])
            st.markdown(
                f"""
                <div style="padding: 10px; margin-bottom: 10px; border-radius: 5px; background-color: rgba(0,0,0,0.05);">
                    <strong>{row["Timestamp"]}</strong> - {row["Source IP"]} → {row["Destination IP"]} - 
                    {row["Threat Type"]} (<span class="{severity_class}">{row["Severity"]}</span>) - 
                    Status: {row["Status"]} | AI Confidence: {row["AI Confidence"]}
                </div>
                """, 
                unsafe_allow_html=True
            )
    else:
        st.info("No threats detected based on current filters.")
    
    if show_raw_data and not filtered_data.empty:
        st.markdown("### Raw Data")
        st.dataframe(filtered_data, height=300)

with col2:
    st.markdown('<p class="subheader">AI Analysis</p>', unsafe_allow_html=True)
    
    # AI Insights
    insights_container = st.container()
    
    with insights_container:
        # Simulated AI analysis text based on the data
        if not filtered_data.empty:
            if ai_mode == "Advanced":
                st.markdown("#### Advanced AI Insights")
                
                # Generate more detailed insights based on the data
                high_threats = filtered_data[filtered_data["Severity"] == "High"]
                common_threat = filtered_data["Threat Type"].value_counts().idxmax() if not filtered_data.empty else "None"
                avg_confidence = filtered_data["AI Confidence"].mean() if not filtered_data.empty else 0
                
                # Check for MITM attacks specifically
                mitm_attacks = filtered_data[filtered_data["Threat Type"] == "Man-in-the-Middle"]
                mitm_insight = ""
                if len(mitm_attacks) > 0:
                    mitm_insight = f"""
                    **Man-in-the-Middle Detection:**
                    - {len(mitm_attacks)} potential MITM attacks detected
                    - Suspected certificate manipulation observed
                    - Unusual TLS handshake patterns detected
                    - Recommend immediate certificate verification
                    """
                
                # More sophisticated insights
                st.markdown(f"""
                **Pattern Recognition Results:**
                - {len(high_threats)} high severity threats detected
                - Most common threat type: {common_threat}
                - Detected coordinated scanning activity from multiple IPs
                - Potential APT signature matches with {avg_confidence*100:.1f}% confidence
                
                **Anomaly Detection:**
                - Network traffic spike detected at {datetime.now().strftime('%H:%M')}
                - Unusual login patterns from {len(filtered_data["Source IP"].unique())} unique source IPs
                - {len(filtered_data[filtered_data["Threat Type"] == "Data Exfiltration"])} potential data exfiltration attempts
                {mitm_insight}
                """)
                
                # Show risk scores from ML model if available
                if 'risk_score' in filtered_data.columns:
                    high_risk_ips = filtered_data[filtered_data['risk_score'] > 0.7]["Source IP"].unique()
                    if len(high_risk_ips) > 0:
                        st.markdown("**High Risk Sources:**")
                        for ip in high_risk_ips[:5]:  # Show top 5
                            st.markdown(f"- {ip} (Risk Score: {filtered_data[filtered_data['Source IP']==ip]['risk_score'].mean()*100:.1f}%)")
            else:
                st.markdown("#### Basic AI Insights")
                
                # Generate basic insights based on the data
                active_threats = len(filtered_data[filtered_data["Status"] == "Active"])
                high_threats = len(filtered_data[filtered_data["Severity"] == "High"])
                mitm_count = len(filtered_data[filtered_data["Threat Type"] == "Man-in-the-Middle"])
                
                mitm_note = f"- {mitm_count} possible Man-in-the-Middle attacks detected" if mitm_count > 0 else ""
                
                st.markdown(f"""
                **Summary:**
                - {active_threats} active threats detected
                - {high_threats} high severity issues requiring attention
                - Multiple login attempts detected from unusual locations
                - Suspicious activity detected from {len(filtered_data["Source IP"].unique())} unique IPs
                {mitm_note}
                """)
        else:
            st.info("No data available for AI analysis based on current filters.")
    
    # Threat prediction using ML model
    st.markdown("#### Predictive Analysis")
    
    if st.session_state.predicted_threats:
        dates, predictions = zip(*st.session_state.predicted_threats)
        
        fig, ax = plt.subplots(figsize=(5, 3))
        ax.plot(dates, predictions, marker='o', linestyle='-', color='#1E90FF')
        ax.set_title('7-Day Threat Prediction (ML Model)')
        ax.set_ylabel('Predicted Threats')
        ax.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        st.pyplot(fig)
    else:
        st.info("ML model needs more data for predictions.")
    
    # AI Prevention Recommendations based on actual data
    st.markdown("#### AI Prevention Recommendations")
    
    if not filtered_data.empty:
        # Generate AI-specific prevention recommendations based on threat types
        ai_recommendations = get_ai_prevention_recommendations(filtered_data["Threat Type"])
        
        # Display the AI recommendations with a more professional look
        for i, rec in enumerate(ai_recommendations):
            st.markdown(
                f"""
                <div style="padding: 8px; margin-bottom: 8px; border-radius: 5px; background-color: rgba(30,144,255,0.1); border-left: 4px solid #1E90FF;">
                    <strong>{i+1}.</strong> {rec}
                </div>
                """, 
                unsafe_allow_html=True
            )
    else:
        st.info("No recommendations available based on current filters.")
    
    # Additional recommendations section
    st.markdown("#### Standard Recommendations")
    
    if not filtered_data.empty:
        # Generate dynamic recommendations based on actual data
        recommendations = []
        
        # Check for high severity threats
        if len(filtered_data[filtered_data["Severity"] == "High"]) > 0:
            recommendations.append("Immediate investigation of high severity threats required")
        
        # Check for malware
        if len(filtered_data[filtered_data["Threat Type"] == "Malware"]) > 0:
            recommendations.append("Update antivirus definitions and scan affected systems")
        
        # Check for phishing
        if len(filtered_data[filtered_data["Threat Type"] == "Phishing"]) > 0:
            recommendations.append("Send phishing awareness reminder to all employees")
        
        # Check for network intrusion
        if len(filtered_data[filtered_data["Threat Type"] == "Network Intrusion"]) > 0:
            recommendations.append("Review firewall rules and update IDS signatures")
            
        # Check for MITM attacks
        if len(filtered_data[filtered_data["Threat Type"] == "Man-in-the-Middle"]) > 0:
            recommendations.append("Verify all SSL/TLS certificates and implement certificate pinning")
        
        # Add some general recommendations
        general_recs = [
            "Implement additional authentication for sensitive areas",
            "Review user access permissions for affected resources"
        ]
        
        # Add general recommendations if we need more
        while len(recommendations) < 3 and general_recs:
            recommendations.append(general_recs.pop(0))
        
        for i, rec in enumerate(recommendations):
            st.markdown(f"{i+1}. {rec}")
    else:
        st.info("No recommendations available based on current filters.")
    
    
  
# Auto-refresh logic
st.markdown("---")
status_container = st.empty()
refresh_container = st.empty()

# Check if it's time to refresh
time_since_last_update = (datetime.now() - st.session_state.last_update).total_seconds()
if time_since_last_update >= refresh_rate:
    # Update the last update time
    st.session_state.last_update = datetime.now()
    
    # Add new threat events
    if st.session_state.attack_simulation:
        # More threats during attack simulation
        n_new_threats = random.randint(2, 5)
    else:
        n_new_threats = random.randint(0, 2)
    
    if n_new_threats > 0:
        new_data = generate_threat_data(num_records=n_new_threats, add_new=False)
        st.session_state.threat_data = pd.concat([new_data, st.session_state.threat_data]).reset_index(drop=True)
        
        # Update ML model and predictions
        if len(st.session_state.threat_data) > 10:  # Only if we have enough data
            train_ml_model()
            st.session_state.threat_data = predict_threats(st.session_state.threat_data)
        
        # Alert about new threats
        n_high = len(new_data[new_data["Severity"] == "High"])
        if n_high > 0:
            status_container.error(f"⚠️ {n_high} new high severity threats detected!")
        else:
            status_container.info(f"ℹ️ {len(new_data)} new threats analyzed")
    else:
        status_container.info("Monitoring for threats...")

# Display last update time
refresh_container.text(f"Last updated: {datetime.now().strftime('%H:%M:%S')} (Refreshes every {refresh_rate} seconds)")

# Add a rerun button for manual refresh

if st.button("Refresh Now"):
    st.rerun()
    


# Add JavaScript for automatic page refresh
st.markdown(f"""
<script>
    setTimeout(function(){{
        window.location.reload();
    }}, {refresh_rate * 1000});
</script>
""", unsafe_allow_html=True)

if st.checkbox("📥 Download Raw Data"):
    csv = st.session_state.threat_data.to_csv(index=False)
    st.download_button("Download CSV", data=csv, file_name="raw_threat_data.csv", mime="text/csv")

