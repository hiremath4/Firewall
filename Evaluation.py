import streamlit as st
from model import train_and_evaluate

import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


st.set_page_config(page_title="Evaluation Metrics", page_icon="📊", layout="wide")


st.title("📊 Model Evaluation Metrics")

try:
    st.success("Model trained and evaluated successfully!")
    metrics = train_and_evaluate("raw_threat_data.csv")

except Exception as e:
    st.error(f"Error: {e}")



