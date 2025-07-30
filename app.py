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
import requests
import bcrypt
import pandas as pd
import numpy as np
from datetime import date, timedelta
from pathlib import Path
import logging
from intuitlib.client import AuthClient
from quickbooks import QuickBooks
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from intuitlib.enums import Scopes
from intuitlib.exceptions import AuthClientError
from utils import get_report_dataframe, apply_custom_categories
from config import load_config, save_config, config_manager
from streamlit_cookies_manager import EncryptedCookieManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mock user database for multi-user login
users = {
    "user1": bcrypt.hashpw("password1".encode(), bcrypt.gensalt()).decode(),
    "user2": bcrypt.hashpw("password2".encode(), bcrypt.gensalt()).decode(),
}

# Custom CSS for professional styling
def add_custom_css():
    st.markdown("""
        <style>
            .stButton > button {
                background-color: #4CAF50;
                color: white;
                border-radius: 5px;
                padding: 10px 20px;
            }
            .stTextInput > div > div > input {
                border: 2px solid #ccc;
                border-radius: 4px;
                padding: 5px;
            }
            .sidebar .sidebar-content {
                background-color: #f8f9fa;
            }
        </style>
    """, unsafe_allow_html=True)

# Welcome message
def show_welcome():
    placeholder = st.empty()
    with placeholder:
        st.title("Welcome to Zuga Books")
        st.write("Your personalized financial management app")
        time.sleep(3)
    placeholder.empty()

# Multi-user login system
def login():
    st.sidebar.title("Login")
    username = st.sidebar.text_input("Username", key="login_username")
    password = st.sidebar.text_input("Password", type="password", key="login_password")
    if st.sidebar.button("Login", key="login_button"):
        if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
            st.session_state["username"] = username
            st.sidebar.success("Logged in successfully!")
            st.rerun()
        else:
            st.sidebar.error("Invalid username or password")

# Cookie setup
COOKIE_SECRET = os.getenv("COOKIE_SECRET")
if not COOKIE_SECRET:
    st.error("🔒 Missing COOKIE_SECRET in environment variables")
    logger.error("COOKIE_SECRET not set in environment variables")
    st.stop()

cookies = EncryptedCookieManager(prefix="zugabooks", password=COOKIE_SECRET)
if not cookies.ready():
    st.stop()

# Initialize ConfigManager
import config
if config.config_manager is None:
    config.config_manager = config.ConfigManager(cookies)
    logger.info("ConfigManager initialized")
else:
    logger.info("ConfigManager already initialized")

# Password gate
APP_PASSWORD = os.getenv("APP_PASSWORD")
if not APP_PASSWORD:
    st.error("🔒 Missing APP_PASSWORD in environment variables")
    logger.error("APP_PASSWORD not set in environment variables")
    st.stop()

def password_gate():
    last_ts = cookies.get("last_auth_ts")
    now = int(time.time())
    if last_ts:
        try:
            last_ts = int(last_ts)
            if now - last_ts < 24 * 3600:
                st.session_state.authenticated = True
                logger.info("Authenticated via valid cookie timestamp")
                return
        except ValueError:
            logger.warning("Invalid last_auth_ts cookie value")

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        logger.info("Already authenticated, proceeding")
        return

    st.sidebar.title("🔐 App Access")
    pw = st.sidebar.text_input("Enter App Password", type="password", key="password_gate").strip()
    if pw:
        if pw == APP_PASSWORD.strip():
            st.session_state.authenticated = True
            cookies["last_auth_ts"] = str(now)
            cookies.save()
            st.sidebar.success("✅ Access granted — valid for 24 h")
            logger.info("Password authentication successful")
            st.rerun()
        else:
            st.sidebar.error("❌ Incorrect password")
            logger.error("Password authentication failed: incorrect password")
            st.stop()
    else:
        logger.info("No password entered, stopping execution")
        st.stop()

# Credential and Token Manager
def credential_manager():
    cfg = load_config()
    st.sidebar.markdown("### 🔧 Credentials & Settings")
    new_cid = st.sidebar.text_input("QuickBooks Client ID", value=cfg.get("qb_client_id", ""), type="password", key="cred_qb_client_id")
    new_secret = st.sidebar.text_input("QuickBooks Client Secret", value=cfg.get("qb_client_secret", ""), type="password", key="cred_qb_client_secret")
    new_redirect = st.sidebar.text_input("QuickBooks Redirect URI", value=cfg.get("redirect_uri", "https://zugabooks.onrender.com"), key="cred_qb_client_redirect")
    new_realm = st.sidebar.text_input("QuickBooks Realm ID", value=cfg.get("realm_id", "9341454953961084"), type="password", key="cred_qb_realm_id")
    new_sheet = st.sidebar.text_input("Google Sheet ID", value=cfg.get("google_sheets", {}).get("sheet_id", "1ZVOs-WWFtfUfwrBwyMa18IFvrB_4YWZlACmFJ3ZGMV8"), key="cred_google_sheet_id")
    sa_file = st.sidebar.file_uploader("Service Account JSON", type=["json"], key="cred_sa_file_uploader")
    
    if st.sidebar.button("💾 Save All Credentials", key="cred_save_button"):
        updated = False
        for k, v in [("qb_client_id", new_cid), ("qb_client_secret", new_secret), ("redirect_uri", new_redirect), ("realm_id", new_realm)]:
            if v and v != cfg.get(k):
                cfg[k] = v
                updated = True
        if new_sheet and new_sheet != cfg.get("google_sheets", {}).get("sheet_id", ""):
            cfg.setdefault("google_sheets", {})["sheet_id"] = new_sheet
            updated = True
        if sa_file:
            try:
                sa_content = json.load(sa_file)
                cfg["service_account_json"] = sa_content
                updated = True
            except Exception as e:
                st.error(f"Failed to parse service account JSON: {e}")
                logger.error(f"Failed to parse service account JSON: {e}")
        if updated:
            save_config(cfg)
            st.success("✅ Configuration saved successfully!")
            st.balloons()
            st.rerun()
        else:
            st.warning("⚠️ No changes detected")

# QBTokenManager
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        self._verify_credentials()
        self.auth_client = AuthClient(
            client_id=self.cfg.get("qb_client_id", ""),
            client_secret=self.cfg.get("qb_client_secret", ""),
            environment="production",
            redirect_uri=self.cfg.get("redirect_uri", "https://zugabooks.onrender.com")
        )
        self._init_token_state()

    def _verify_credentials(self):
        required = {
            "qb_client_id": "Client ID from Intuit Developer Portal",
            "qb_client_secret": "Client Secret from Intuit",
            "redirect_uri": "Redirect URI (must match exactly)"
        }
        missing = [f"{field} ({desc})" for field, desc in required.items() if not self.cfg.get(field)]
        if missing:
            st.error(f"Missing required config:\n" + "\n".join(f"• {item}" for item in missing))
            st.stop()

    def _init_token_state(self):
        if "tokens" not in st.session_state:
            st.session_state.tokens = {
                "access_token": self.cfg.get("access_token"),
                "refresh_token": self.cfg.get("refresh_token"),
                "expires_at": self.cfg.get("expires_at", 0)
            }

    def handle_oauth(self):
        tokens = st.session_state.tokens
        if tokens.get("access_token") and time.time() < tokens.get("expires_at", 0):
            return True

        st.markdown("## 🔑 QuickBooks Authorization")
        auth_url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        logger.info(f"Generated auth URL: {auth_url}")
        st.markdown(f"""
            ### Steps:
            1. [Authorize in QuickBooks]({auth_url})
            2. Copy the **code** parameter from the URL
            3. Paste below
        """)
        st.warning("⚠️ Codes expire in 5 minutes!")

        code = st.text_input("Paste authorization code:", key="qb_auth_code")
        if not code:
            st.stop()

        try:
            clean_code = code.strip()
            if "code=" in clean_code:
                clean_code = clean_code.split("code=")[-1].split("&")[0]
            logger.debug(f"Cleaned auth code: {clean_code}")
            st.code(f"🔍 Clean Code Used: {clean_code}")

            with st.spinner("Exchanging code for tokens…"):
                # Try intuitlib first
                try:
                    self.auth_client.environment = "production"
                    resp = self.auth_client.get_bearer_token(clean_code, realm_id=self.cfg.get("realm_id"))
                    logger.debug(f"Intuitlib token response: {resp}")
                except Exception as intuit_error:
                    logger.warning(f"Intuitlib failed: {intuit_error}")
                    # Fallback to direct HTTP request
                    token_url = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
                    headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    data = {
                        "grant_type": "authorization_code",
                        "code": clean_code,
                        "redirect_uri": self.cfg.get("redirect_uri", "https://zugabooks.onrender.com"),
                        "client_id": self.cfg.get("qb_client_id"),
                        "client_secret": self.cfg.get("qb_client_secret")
                    }
                    auth = (self.cfg.get("qb_client_id"), self.cfg.get("qb_client_secret"))
                    resp = requests.post(token_url, data=data, headers=headers, auth=auth)
                    logger.debug(f"HTTP token response: {resp.status_code}, {resp.text}")
                    if resp.status_code != 200:
                        st.error(f"🔴 Token request failed: HTTP {resp.status_code}, {resp.text}")
                        logger.error(f"Token request failed: HTTP {resp.status_code}, {resp.text}")
                        st.stop()
                    resp = resp.json()

            at = resp.get("access_token")
            rt = resp.get("refresh_token")
            ei = resp.get("expires_in")

            if not at or not rt:
                st.error(f"🔴 No access_token or refresh_token returned.\nFull response: `{resp}`")
                logger.error(f"No access_token or refresh_token returned: {resp}")
                st.stop()

            st.session_state.tokens = {
                "access_token": at,
                "refresh_token": rt,
                "expires_at": time.time() + (ei or 3600)
            }
            self.cfg.update(st.session_state.tokens)
            realm = resp.get("realmId") or getattr(self.auth_client, "realm_id", None)
            if realm:
                self.cfg["realm_id"] = realm
            save_config(self.cfg)
            logger.info(f"Token saved to config: {st.session_state.tokens}")
            st.success("✅ Authorization successful! Copy tokens from 'Show Current Tokens'.")
            st.rerun()
            return True
        except AuthClientError as e:
            st.error(f"🔴 QuickBooks API Error {e.status_code}:\n{e.content}")
            logger.error(f"QuickBooks API Error {e.status_code}: {e.content}")
            st.stop()
        except Exception as e:
            st.error(f"🔴 Authorization failed: {e}")
            logger.error(f"Authorization failed: {e}")
            st.stop()

    def _refresh_token(self):
        try:
            refresh_token = st.session_state.tokens.get("refresh_token")
            if not refresh_token:
                return False
            self.auth_client.refresh_token = refresh_token
            new_tokens = self.auth_client.refresh()
            if not new_tokens or not hasattr(new_tokens, "access_token"):
                return False
            st.session_state.tokens = {
                "access_token": new_tokens.access_token,
                "refresh_token": new_tokens.refresh_token,
                "expires_at": time.time() + new_tokens.expires_in
            }
            self.cfg.update(st.session_state.tokens)
            save_config(self.cfg)
            logger.info(f"Token refreshed: {st.session_state.tokens}")
            return True
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return False

# Dashboard page
def dashboard_page():
    st.title(f"Dashboard - Welcome, {st.session_state['username']}")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Financial Overview")
        data = pd.DataFrame({
            "Category": ["Income", "Expenses", "Profit"],
            "Amount": [np.random.randint(1000, 5000), np.random.randint(500, 2000), np.random.randint(500, 3000)]
        })
        st.bar_chart(data.set_index("Category"))
    with col2:
        st.subheader("Recent Activity")
        st.write("Generated 3 reports this week")

# Reports page (QuickBooks integration)
def reports_page():
    st.title("Reports")
    today = date.today()
    col1, col2 = st.columns(2)
    with col1:
        start = st.date_input("Start Date", today - timedelta(days=30), key="start")
    with col2:
        end = st.date_input("End Date", today, key="end")
    
    if start > end:
        st.error("⚠️ End date must be after start date.")
        st.stop()

    rpt = st.selectbox("Select Report Type", ["ProfitAndLoss", "BalanceSheet", "TransactionList"], key="rpt")
    if st.button("🔄 Generate Report", key="gen"):
        with st.spinner("Fetching report…"):
            try:
                if not st.session_state.tokens.get("access_token"):
                    st.error("No access token found. Please authorize or enter tokens manually.")
                    return
                if time.time() > st.session_state.tokens.get("expires_at", 0):
                    if not token_manager._refresh_token():
                        st.error("Token refresh failed. Please re-authorize or enter tokens manually.")
                        return
                qb = QuickBooks(
                    auth_client=token_manager.auth_client,
                    access_token=st.session_state.tokens["access_token"],
                    refresh_token=st.session_state.tokens["refresh_token"],
                    company_id=token_manager.cfg.get("realm_id", "")
                )
                params = {"start_date": start.strftime("%Y-%m-%d"), "end_date": end.strftime("%Y-%m-%d")}
                rep = qb.get_report(report_name=rpt, params=params)
                df = get_report_dataframe(rep.get("Rows", {}).get("Row", []), rpt)
                st.subheader(f"{rpt} Report")
                st.dataframe(df, use_container_width=True)
            except Exception as e:
                st.error(f"Report generation failed: {e}")
                logger.error(f"Report generation failed: {e}")

# Settings page
def settings_page():
    st.title("Settings")
    credential_manager()
    st.write("Adjust additional preferences here.")
    theme = st.selectbox("Theme", ["Light", "Dark"])
    st.write(f"Selected theme: {theme}")

# Navigation dashboard
def navigation_dashboard():
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox("Select a page", ["Dashboard", "Reports", "Settings"])
    st.info("Note: This app is under development, and some features may not be fully functional.")
    pages = {
        "Dashboard": dashboard_page,
        "Reports": reports_page,
        "Settings": settings_page,
    }
    pages[page]()

# Main app function
def main():
    global token_manager
    add_custom_css()
    token_manager = QBTokenManager()
    if "username" not in st.session_state:
        show_welcome()
        login()
    else:
        password_gate()
        navigation_dashboard()

if __name__ == "__main__":
    main()
