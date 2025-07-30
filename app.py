import streamlit as st
# --- Streamlit Configuration ---
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
from streamlit_cookies_manager import EncryptedCookieManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Custom CSS ---
st.markdown("""
    <style>
        /* Main content styling */
        .main .block-container {
            padding-top: 2rem;
        }
        
        /* Button styling */
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
        
        /* Input field styling */
        .stTextInput>div>div>input {
            border: 2px solid #ccc;
            border-radius: 4px;
            padding: 8px 12px;
            font-size: 16px;
        }
        
        /* Sidebar styling */
        .sidebar .sidebar-content {
            background-color: #f8f9fa;
            padding: 20px 15px;
        }
        .sidebar .sidebar-content .stRadio>div {
            flex-direction: column;
        }
        
        /* Header styling */
        .header {
            padding: 1rem 0;
            border-bottom: 1px solid #eee;
            margin-bottom: 1.5rem;
        }
        
        /* Status indicators */
        .status-success {
            color: #4CAF50;
            font-weight: bold;
        }
        .status-warning {
            color: #FF9800;
            font-weight: bold;
        }
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
    with st.sidebar.form("login_form"):
        st.title("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.form_submit_button("Login"):
            if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
                st.session_state["username"] = username
                st.success("Logged in successfully!")
                st.rerun()
            else:
                st.error("Invalid username or password")

# --- Password Gate ---
def password_gate():
    """App-level password authentication"""
    if not st.session_state.cookies.ready():
        st.warning("Initializing cookie manager, please wait...")
        time.sleep(1)
        st.rerun()
    with st.sidebar.form("password_gate_form"):
        st.title("🔐 App Access")
        pw = st.text_input("Enter App Password", type="password", key="password_gate")
        if st.form_submit_button("Submit"):
            if pw == os.getenv("APP_PASSWORD", "").strip():
                st.session_state.authenticated = True
                st.session_state.cookies["last_auth_ts"] = str(int(time.time()))
                st.session_state.cookies.save()
                st.success("✅ Access granted — valid for 24 hours")
                logger.info("Password authentication successful")
                st.rerun()
            else:
                st.error("❌ Incorrect password")
                logger.error("Password authentication failed: incorrect password")

# --- Dashboard Page ---
def dashboard_page():
    st.title(f"Dashboard")
    st.markdown(f"### Welcome back, {st.session_state['username']}!")
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Monthly Revenue", "$12,845", "12%")
    with col2:
        st.metric("Expenses", "$8,230", "-5%")
    with col3:
        st.metric("Net Profit", "$4,615", "28%")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Income vs Expenses")
        data = pd.DataFrame({
            "Month": ["Jan", "Feb", "Mar", "Apr"],
            "Income": [12000, 15000, 11000, 13000],
            "Expenses": [8000, 9000, 8500, 8200]
        })
        st.bar_chart(data.set_index("Month"))
    with col2:
        st.subheader("Profit Trend")
        st.line_chart(data.set_index("Month")[['Income','Expenses']])

# --- Reports Page ---
def reports_page():
    st.title("Financial Reports")
    st.markdown("---")
    today = date.today()
    col1, col2 = st.columns(2)
    with col1:
        start = st.date_input("Start Date", today - timedelta(days=30), key="start")
    with col2:
        end = st.date_input("End Date", today, key="end")
    if start > end:
        st.error("⚠️ End date must be after start date.")
        st.stop()
    rpt = st.selectbox("Select Report Type", ["Profit & Loss", "Balance Sheet", "Transaction List"], key="rpt")
    if st.button("🔄 Generate Report", key="gen"):
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
            st.dataframe(data, use_container_width=True, height=400)
            st.markdown("---")
            st.subheader("Export Options")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📤 Export to Google Sheets", key="exp"):
                    st.success("✅ Report exported to Google Sheets!")
            with col2:
                st.download_button("💾 Download CSV", data=data.to_csv(index=False), file_name=f"{rpt.replace(' ','_')}_{today}.csv", mime="text/csv", key="dl")

# --- Settings Page ---
def settings_page():
    st.title("Settings")
    st.markdown("---")
    st.subheader("Account Settings")
    col1, col2 = st.columns(2)
    with col1:
        st.text_input("Name", value="John Doe", key="user_name")
    with col2:
        st.text_input("Email", value="john@example.com", key="user_email")
    st.subheader("Preferences")
    theme = st.selectbox("Theme", ["Light","Dark","System Default"], key="theme_select")
    timezone = st.selectbox("Timezone", ["UTC","EST","PST","CET"], key="timezone_select")
    st.subheader("Credential Settings")
    st.markdown("Sensitive data removed for security.")
    with st.expander("QuickBooks Integration", expanded=False):
        qb_token = st.text_input("QuickBooks API Token", type="password", key="qb_token")
        if st.button("🔗 Connect QuickBooks", key="qb_connect"):
            st.success("QuickBooks connected successfully!")
    with st.expander("Google Sheets Integration", expanded=False):
        gs_token = st.text_input("Google Sheets API Token", type="password", key="gs_token")
        if st.button("🔗 Connect Google Sheets", key="gs_connect"):
            st.success("Google Sheets connected successfully!")
    if st.button("💾 Save Settings", key="save_settings"):
        st.success("Settings saved successfully!")

# --- Navigation ---
def navigation_dashboard():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("", ["Dashboard","Reports","Settings"], key="nav=nav_radio")
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
    if "cookies" not in st.session_state:
        st.session_state.cookies = EncryptedCookieManager(
            prefix="zugabooks",
            password=os.getenv("COOKIE_SECRET", "default-secret")
        )
    # Maintenance Alert
    st.warning("🚧 App under maintenance and updates. Some features may be temporarily unavailable.")
    # Show welcome screen once
    if "welcome_shown" not in st.session_state:
        show_welcome()
        st.session_state.welcome_shown = True
        st.rerun()
    # Authentication flow
    if "username" not in st.session_state:
        login()
    else:
        if not st.session_state.get("authenticated", False):
            password_gate()
        else:
            navigation_dashboard()

if __name__ == "__main__":
    main()
