import streamlit as st
import pandas as pd
import numpy as np
from datetime import date, timedelta
import time
import bcrypt
import logging

# Local imports
from config import config_manager
from utils import get_mock_data

# --- Page Configuration ---
st.set_page_config(
    page_title="ZugaBooks Demo",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Logging ---
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
            border: none;
            transition: all 0.3s ease;
            width: 100%;
        }
        .stButton>button:hover {
            background-color: #45a049;
            transform: scale(1.02);
        }
        .sidebar .sidebar-content { background-color: #f8f9fa; }
        .header {
            font-size: 2.5rem;
            font-weight: bold;
            padding: 1rem 0;
            border-bottom: 1px solid #eee;
            margin-bottom: 1.5rem;
        }
        .status-success { color: #4CAF50; font-weight: bold; }
        .status-warning { color: #FF9800; font-weight: bold; }
        .status-disconnected { color: #F44336; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

# --- Mock User Database ---
# In a real app, this would be a secure database
users = {
    "demo": bcrypt.hashpw("demo".encode(), bcrypt.gensalt()).decode(),
    "recruiter": bcrypt.hashpw("welcome".encode(), bcrypt.gensalt()).decode(),
}

# --- State Initialization ---
def initialize_state():
    """Initialize session state variables."""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "qb_connected" not in st.session_state:
        st.session_state.qb_connected = False
    if "gs_connected" not in st.session_state:
        st.session_state.gs_connected = False
    if "welcome_shown" not in st.session_state:
        st.session_state.welcome_shown = False
    if "username" not in st.session_state:
        st.session_state.username = ""

# --- UI Components ---
def show_welcome_screen():
    """A temporary splash screen."""
    with st.empty():
        st.title("Welcome to the ZugaBooks Demo")
        st.subheader("A Financial Reporting & Management Solution")
        st.markdown("---")
        st.info("This is an interactive, production-ready demonstration.")
        st.balloons()
        time.sleep(2.5)

def login_page():
    """Displays the login form in the sidebar."""
    with st.sidebar:
        st.title("🔐 ZugaBooks Login")
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Try 'demo'")
            password = st.text_input("Password", type="password", placeholder="Try 'demo'")
            submitted = st.form_submit_button("Login")

            if submitted:
                if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    logger.info(f"User '{username}' logged in successfully.")
                    st.success("Logged in successfully!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
                    logger.warning(f"Failed login attempt for username: '{username}'")

def credential_manager():
    """Mock credential manager in the Settings page."""
    st.subheader("Integration Credentials")
    st.markdown("Manage API tokens for external services. In this demo, connections are simulated.")

    with st.expander("QuickBooks Integration", expanded=True):
        st.text_input("QuickBooks Client ID", value="**************" if st.session_state.qb_connected else "", type="password")
        if not st.session_state.qb_connected:
            if st.button("🔗 Connect QuickBooks"):
                with st.spinner("Simulating OAuth2 connection..."):
                    time.sleep(2)
                    st.session_state.qb_connected = True
                    st.success("QuickBooks connected successfully!")
                    st.rerun()
        else:
            st.success("QuickBooks is connected.")

    with st.expander("Google Sheets Integration", expanded=True):
        st.text_input("Google Sheets API Key", value="**************" if st.session_state.gs_connected else "", type="password")
        if not st.session_state.gs_connected:
            if st.button("🔗 Connect Google Sheets"):
                with st.spinner("Verifying Google Sheets API access..."):
                    time.sleep(2)
                    st.session_state.gs_connected = True
                    st.success("Google Sheets connected successfully!")
                    st.rerun()
        else:
            st.success("Google Sheets is connected.")

# --- App Pages ---
def dashboard_page():
    st.title("📊 Dashboard")
    st.markdown(f"### Welcome back, {st.session_state['username'].capitalize()}!")
    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    col1.metric("Quarterly Revenue", "$45,845", "12%")
    col2.metric("Operating Expenses", "$28,230", "-5% (YoY)")
    col3.metric("Net Profit", "$17,615", "28%")

    st.markdown("---")
    col1, col2 = st.columns([0.6, 0.4])
    with col1:
        st.subheader("Income vs Expenses (Last 6 Months)")
        chart_data = pd.DataFrame({
            "Month": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
            "Income": [12500, 15500, 11000, 13000, 16200, 17100],
            "Expenses": [8000, 9200, 8500, 8800, 9500, 10100]
        }).set_index("Month")
        st.bar_chart(chart_data)

    with col2:
        st.subheader("Expense Breakdown")
        pie_data = pd.DataFrame({
            'Category': ['Salaries', 'Marketing', 'Software', 'Rent', 'Utilities'],
            'Amount': [45, 25, 15, 10, 5]
        }).set_index('Category')
        st.bar_chart(pie_data)


def reports_page():
    st.title("📄 Financial Reports")
    st.markdown("Generate and export key financial statements.")
    st.markdown("---")

    if not st.session_state.qb_connected:
        st.warning("Please connect to QuickBooks in the Settings page to generate reports.")
        st.stop()

    today = date.today()
    col1, col2 = st.columns(2)
    start_date = col1.date_input("Start Date", today - timedelta(days=365))
    end_date = col2.date_input("End Date", today)

    if start_date > end_date:
        st.error("Error: Start date must be before end date.")
        st.stop()

    report_type = st.selectbox(
        "Select Report Type",
        ["Profit & Loss", "Balance Sheet", "Transaction List"]
    )

    if st.button("🔄 Generate Report"):
        with st.spinner(f"Fetching {report_type} data from QuickBooks..."):
            time.sleep(1.5)
            # Fetch mock data instead of calling a real API
            report_df = get_mock_data(report_type)

        st.subheader(f"Generated Report: {report_type}")
        st.dataframe(report_df, use_container_width=True, height=350)

        # Download and export options
        csv_data = report_df.to_csv(index=False).encode('utf-8')
        col1, col2 = st.columns(2)
        col1.download_button(
            label="💾 Download as CSV",
            data=csv_data,
            file_name=f"{report_type.replace(' ', '_')}_{today}.csv",
            mime="text/csv",
        )
        with col2:
            if st.button("📤 Export to Google Sheets"):
                if st.session_state.gs_connected:
                    with st.spinner("Exporting data..."):
                        time.sleep(2)
                        st.success("✅ Report exported to Google Sheets!")
                else:
                    st.error("⚠️ Google Sheets is not connected. Go to Settings.")

def settings_page():
    st.title("⚙️ Settings")
    st.markdown("---")

    st.subheader("User Profile")
    col1, col2 = st.columns(2)
    col1.text_input("Name", value=st.session_state.username.capitalize())
    col2.text_input("Email", value=f"{st.session_state.username}@zugabooks.demo")

    st.selectbox("Theme", ["Light", "Dark", "System Default"], help="Theme selection is for display purposes.")
    st.selectbox("Timezone", ["UTC", "EST", "PST", "CET"])

    st.markdown("---")
    credential_manager()

    st.markdown("---")
    if st.button("💾 Save Settings"):
        st.success("Settings saved successfully!")


# --- Main Application Flow ---
def main():
    initialize_state()

    # Show a one-time welcome splash screen
    if not st.session_state.welcome_shown:
        show_welcome_screen()
        st.session_state.welcome_shown = True
        st.rerun()
        
    st.sidebar.image("https://raw.githubusercontent.com/zugatech/ZugaBooks/main/assets/zuga_logo_sidebar.png", width=200)

    if not st.session_state.authenticated:
        login_page()
    else:
        st.sidebar.title(f"Welcome, {st.session_state.username.capitalize()}!")
        st.sidebar.markdown("---")

        page_map = {
            "Dashboard": dashboard_page,
            "Reports": reports_page,
            "Settings": settings_page,
        }
        
        page = st.sidebar.radio("Navigation", options=list(page_map.keys()))
        
        st.sidebar.markdown("---")
        st.sidebar.markdown("### System Status")
        
        qb_status = "<span class='status-success'>Connected</span>" if st.session_state.qb_connected else "<span class='status-disconnected'>Disconnected</span>"
        gs_status = "<span class='status-success'>Connected</span>" if st.session_state.gs_connected else "<span class='status-warning'>Not Connected</span>"
        
        st.sidebar.markdown(f"QuickBooks: {qb_status}", unsafe_allow_html=True)
        st.sidebar.markdown(f"Google Sheets: {gs_status}", unsafe_allow_html=True)
        
        st.sidebar.markdown("---")
        if st.sidebar.button("Logout"):
            st.session_state.authenticated = False
            st.session_state.username = ""
            st.rerun()

        # Display the selected page
        page_map[page]()

if __name__ == "__main__":
    st.info("✨ **Demo Mode Active**: All data is randomly generated for demonstration purposes and does not reflect real financial information.", icon="💡")
    main()
