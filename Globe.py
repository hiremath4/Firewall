import streamlit as st
import folium
from folium.plugins import HeatMap
from streamlit.components.v1 import html
import random

# Set Streamlit page configuration
st.set_page_config(layout="wide")
st.title("🌎 Real-Time Threat Heatmap (Simulation)")
st.markdown("""
 **🔴**: High Threat
 **🟡**: Medium Threat
 **🟢**: Low Threat
""")

# Function to generate sample threat points with severity
def generate_sample_threat_points():
    # Predefined threat locations (latitude, longitude, severity)
    threat_points = [
        (28.6139, 77.2090, "High"),    # Delhi, India
        (19.0760, 72.8777, "Medium"),  # Mumbai, India
        (12.9716, 77.5946, "Low"),     # Bangalore, India
        (37.7749, -122.4194, "High"),  # San Francisco, USA
        (51.5074, -0.1278, "Medium"),  # London, UK
        (35.6895, 139.6917, "High"),   # Tokyo, Japan
        (55.7558, 37.6173, "Low"),     # Moscow, Russia
        (-33.8688, 151.2093, "Medium"),# Sydney, Australia
        (48.8566, 2.3522, "Low"),      # Paris, France
        (34.0522, -118.2437, "High"),  # Los Angeles, USA
        (1.3521, 103.8198, "Medium"),  # Singapore
        (31.2304, 121.4737, "Low"),    # Shanghai, China
    ]
    return threat_points

# Function to map severity to intensity
def severity_to_intensity(severity):
    return {"High": 1.0, "Medium": 0.6, "Low": 0.3}.get(severity, 0.3)

# Main function to generate and display the map
def generate_map():
    # Initialize Folium map
    m = folium.Map(location=[20.0, 0.0], zoom_start=2, tiles="cartodb dark_matter")

    # Generate sample threat data
    threat_points = generate_sample_threat_points()
    heat_data = []
    
    # Add circles and heat data based on predefined threat points
    for lat, lon, severity in threat_points:
        intensity = severity_to_intensity(severity)
        heat_data.append([lat, lon, intensity])
        # Add circle marker with tooltip
        folium.CircleMarker(
            location=[lat, lon],
            radius=8,
            color="white",
            fill=True,
            fill_color={"High": "red", "Medium": "yellow", "Low": "green"}.get(severity, "green"),
            fill_opacity=0.7,
            tooltip=f"Severity: {severity}\nLocation: ({lat}, {lon})"
        ).add_to(m)

    # Add heatmap layer
    HeatMap(heat_data, radius=25, blur=15, max_zoom=1).add_to(m)

    # Render map in Streamlit
    map_html = m._repr_html_()
    html(map_html, height=400)

# Display the map
generate_map()
