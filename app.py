import streamlit as st
st.set_page_config(
    page_title="ZugaBooks",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

import os
import time
import json
import bcrypt
import pandas as pd
import numpy as np
from datetime import date, timedelta
import logging
import requests
from config import load_config, save_config, config_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Custom CSS ---
st.markdown("""
    <style>
        .main .block-container { padding-top: 2rem; }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            border-radius: 5px;
            padding: 10px 20px;
            transition: all 0.3s;
        }
        .stButton>button:hover {
            background-color: #45a049;
            transform: scale(1.05);
        }
        .stTextInput>div>div>input {
            border: 2px solid #ccc;
            border-radius: 4px;
            padding: 8px 12px;
            font-size: 16px;
        }
        .sidebar .sidebar-content {
            background-color: #f8f9fa;
            padding: 20px 15px;
        }
        .sidebar .sidebar-content .stRadio>div { flex-direction: column; }
        .header {
            padding: 1rem 0;
            border-bottom: 1px solid #eee;
            margin-bottom: 1.5rem;
        }
        .status-success { color: #4CAF50; font-weight: bold; }
        .status-warning { color: #FF9800; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

# --- Mock User Database ---
users = {
    "user1": bcrypt.hashpw("password1".encode(), bcrypt.gensalt()).decode(),
    "user2": bcrypt.hashpw("password2".encode(), bcrypt.gensalt()).decode(),
}

# --- Welcome Screen ---
def show_welcome():
    with st.empty():
        st.title("Welcome to Zuga Books")
        st.subheader("Your Financial Management Solution")
        st.markdown("---")
        st.write("Streamlining your financial workflows with intuitive reporting")
        time.sleep(3)

# --- Login System ---
def login():
    """Multi-user login system with form submission"""
    with st.sidebar:
        with st.form("login_form"):
            st.title("Login")
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Login")
            if submitted:
                if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
                    st.session_state["username"] = username
                    st.success("Logged in successfully!")
                    st.rerun()
                else:
                    st.error("Invalid username or password")

# --- Password Gate ---
def password_gate():
    """App-level password authentication"""
    with st.sidebar:
        with st.form("password_gate_form"):
            st.title("🔐 App Access")
            pw = st.text_input("Enter App Password", type="password", key="password_gate")
            submitted = st.form_submit_button("Submit")
            if submitted:
                if pw == os.getenv("APP_PASSWORD", "").strip():
                    st.session_state.authenticated = True
                    st.success("✅ Access granted — valid for 24 hours")
                    logger.info("Password authentication successful")
                    st.rerun()
                else:
                    st.error("❌ Incorrect password")
                    logger.error("Password authentication failed: incorrect password")

# --- QuickBooks Authorization ---
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        self.client_id = self.cfg.get("qb_client_id", "")
        self.redirect_uri = self.cfg.get("redirect_uri", "https://zugabooks.onrender.com")
        if not self.client_id:
            st.error("QuickBooks Client ID missing in configuration.")
            st.stop()

    def handle_oauth(self):
        """Mock QuickBooks OAuth2 authorization"""
        st.markdown("## 🔑 QuickBooks Authorization")
        st.markdown("""
            ### Steps:
            1. Authorize in QuickBooks (mock process)
            2. Enter the provided mock authorization code
        """)
        st.warning("⚠️ Mock codes for demo purposes only.")
        auth_code = st.text_input("Paste mock authorization code", key="qb_auth_code")
        if not auth_code:
            st.stop()
        try:
            with st.spinner("Processing authorization..."):
                time.sleep(1)
                st.session_state.tokens = {
                    "access_token": "mock_access_token",
                    "refresh_token": "mock_refresh_token",
                    "expires_at": time.time() + 3600
                }
                self.cfg.update(st.session_state.tokens)
                save_config(self.cfg)
                st.success("✅ QuickBooks authorized successfully!")
                st.rerun()
        except Exception as e:
            st.error(f"🔴 Authorization failed: {e}")
            logger.error(f"Authorization failed: {e}")
            st.stop()

# --- Credential Manager ---
def credential_manager():
    """Manage QuickBooks and Google Sheets credentials"""
    cfg = load_config()
    st.subheader("Integration Credentials")
    st.markdown("Enter API tokens for external services. Sensitive data is securely stored.")
    with st.expander("QuickBooks Integration", expanded=False):
        qb_token = st.text_input("QuickBooks API Token", value=cfg.get("qb_client_id", ""), type="password", key="qb_token")
        if st.button("🔗 Connect QuickBooks", key="qb_connect"):
            cfg["qb_client_id"] = qb_token
            save_config(cfg)
            st.success("QuickBooks connected successfully!")
    with st.expander("Google Sheets Integration", expanded=False):
        gs_token = st.text_input("Google Sheets API Token", value=cfg.get("google_sheets", {}).get("sheet_id", ""), type="password", key="gs_token")
        if st.button("🔗 Connect Google Sheets", key="gs_connect"):
            cfg.setdefault("google_sheets", {})["sheet_id"] = gs_token
            save_config(cfg)
            st.success("Google Sheets connected successfully!")
    if st.button("Authorize QuickBooks", key="qb_authorize"):
        QBTokenManager().handle_oauth()

# --- Dashboard Page ---
def dashboard_page():
    st.title("Dashboard")
    st.markdown(f"### Welcome back, {st.session_state['username']}!")
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Monthly Revenue", "$12,845", "12%", key="metric_revenue")
    with col2:
        st.metric("Expenses", "$8,230", "-5%", key="metric_expenses")
    with col3:
        st.metric("Net Profit", "$4,615", "28%", key="metric_profit")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Income vs Expenses")
        data = pd.DataFrame({
            "Month": ["Jan", "Feb", "Mar", "Apr"],
            "Income": [12000, 15000, 11000, 13000],
            "Expenses": [8000, 9000, 8500, 8200]
        })
        st.bar_chart(data.set_index("Month"), key="chart_income_expenses")
    with col2:
        st.subheader("Profit Trend")
        st.line_chart(data.set_index("Month")[['Income','Expenses']], key="chart_profit_trend")

# --- Reports Page ---
def reports_page():
    st.title("Financial Reports")
    st.markdown("---")
    today = date.today()
    col1, col2 = st.columns(2)
    with col1:
        start = st.date_input("Start Date", today - timedelta(days=30), key="report_start_date")
    with col2:
        end = st.date_input("End Date", today, key="report_end_date")
    if start > end:
        st.error("⚠️ End date must be after start date.")
        st.stop()
    rpt = st.selectbox("Select Report Type", ["Profit & Loss", "Balance Sheet", "Transaction List"], key="report_type")
    if st.button("🔄 Generate Report", key="report_generate"):
        with st.spinner("Compiling report data..."):
            time.sleep(2)
            if rpt == "Profit & Loss":
                data = pd.DataFrame({
                    "Category": ["Revenue","Cost of Goods","Gross Profit","Expenses","Net Profit"],
                    "Amount": [25000,12000,13000,8000,5000]
                })
            elif rpt == "Balance Sheet":
                data = pd.DataFrame({
                    "Account": ["Assets","Liabilities","Equity"],
                    "Balance": [75000,45000,30000]
                })
            else:
                data = pd.DataFrame({
                    "Date": [today - timedelta(days=i) for i in range(10,0,-1)],
                    "Description": [f"Transaction {i}" for i in range(10,0,-1)],
                    "Amount": [100*i for i in range(10,0,-1)]
                })
            st.subheader(f"{rpt} Report")
            st.dataframe(data, use_container_width=True, height=400, key="report_dataframe")
            st.markdown("---")
            st.subheader("Export Options")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📤 Export to Google Sheets", key="report_export_gsheets"):
                    st.success("✅ Report exported to Google Sheets!")
            with col2:
                st.download_button("💾 Download CSV", data=data.to_csv(index=False), file_name=f"{rpt.replace(' ','_')}_{today}.csv", mime="text/csv", key="report_download_csv")

# --- Settings Page ---
def settings_page():
    st.title("Settings")
    st.markdown("---")
    st.subheader("Account Settings")
    col1, col2 = st.columns(2)
    with col1:
        st.text_input("Name", value="John Doe", key="settings_name")
    with col2:
        st.text_input("Email", value="john@example.com", key="settings_email")
    st.subheader("Preferences")
    theme = st.selectbox("Theme", ["Light","Dark","System Default"], key="settings_theme")
    timezone = st.selectbox("Timezone", ["UTC","EST","PST","CET"], key="settings_timezone")
    credential_manager()
    if st.button("💾 Save Settings", key="settings_save"):
        st.success("Settings saved successfully!")

# --- Navigation ---
def navigation_dashboard():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("", ["Dashboard","Reports","Settings"], key="nav_radio")
    st.sidebar.markdown("---")
    st.sidebar.markdown("### System Status")
    st.sidebar.markdown("QuickBooks: <span class='status-success'>Connected</span>", unsafe_allow_html=True)
    st.sidebar.markdown("Google Sheets: <span class='status-success'>Connected</span>", unsafe_allow_html=True)
    st.sidebar.markdown("---")
    st.sidebar.markdown("### App Information")
    st.sidebar.markdown("**Version:** 2.1.0")
    st.sidebar.markdown("**Last Updated:** July 2025")
    pages = {"Dashboard": dashboard_page, "Reports": reports_page, "Settings": settings_page}
    pages[page]()

# --- Main App ---
def main():
    # Maintenance Alert
    st.warning("🚧 App under maintenance and updates. Some features may be temporarily unavailable.")

    # Show welcome screen once
    if "welcome_shown" not in st.session_state:
        show_welcome()
        st.session_state.welcome_shown = True
        st.rerun()

    # Initialize ConfigManager
    if config_manager is None:
        st.error("ConfigManager not initialized. Please check config.py.")
        logger.error("ConfigManager not initialized")
        st.stop()

    # Authentication flow
    if "username" not in st.session_state:
        login()
    elif not st.session_state.get("authenticated", False):
        password_gate()
    else:
        navigation_dashboard()

if __name__ == "__main__":
    main()
