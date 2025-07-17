import streamlit as st
# ————————————————————————————————————————————————
# MUST be the very first call
st.set_page_config(
    page_title="ZugaBooks",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

import os
import time
import json
from datetime import date, timedelta
from pathlib import Path
import logging
from intuitlib.client import AuthClient
from quickbooks import QuickBooks
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pandas as pd
from intuitlib.enums import Scopes
from intuitlib.exceptions import AuthClientError
from utils import get_report_dataframe, apply_custom_categories
from config import load_config, save_config, initialize
from streamlit_cookies_manager import EncryptedCookieManager

# ————————————————————————————————————————————————

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
config.initialize(cookies)
logger.info("ConfigManager initialization called")

# Password gate
APP_PASSWORD = os.getenv("APP_PASSWORD")
if not APP_PASSWORD:
    st.error("🔒 Missing APP_PASSWORD in environment variables")
    logger.error("APP_PASSWORD not set in environment variables")
    st.stop()

def password_gate():
    last_ts = cookies.get("last_auth_ts")
    now = int(time.time())
    if last_ts and now - int(last_ts) < 24 * 3600:
        return
    
    st.sidebar.title("🔐 Login Required")
    pw = st.sidebar.text_input("Enter Access Password", type="password", key="password_gate")
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    
    if pw == APP_PASSWORD:
        st.session_state.authenticated = True
        cookies["last_auth_ts"] = str(now)
        cookies.save()
        st.sidebar.success("✅ Access granted — valid for 24 h")
        return
    elif pw:
        st.sidebar.error("❌ Incorrect password")
        st.stop()

password_gate()

# Credential and Token Manager (no caching)
def credential_manager():
    logger.info("Entering credential_manager")
    cfg = load_config()
    with st.sidebar:
        st.markdown("### ZugaBooks")
        st.markdown("**App Version: 1.3.5**")
        st.markdown("---")
        st.markdown("### 🔧 Credentials & Settings")
        
        new_cid = st.text_input("QuickBooks Client ID", value=cfg.get("qb_client_id", ""), type="password", key="cred_qb_client_id")
        new_secret = st.text_input("QuickBooks Client Secret", value=cfg.get("qb_client_secret", ""), type="password", key="cred_qb_client_secret")
        new_redirect = st.text_input("QuickBooks Redirect URI", value=cfg.get("redirect_uri", "https://zugabooks.onrender.com/"), key="cred_qb_redirect_uri")
        new_realm = st.text_input("QuickBooks Realm ID", value=cfg.get("realm_id", "9341454953961084"), type="password", key="cred_qb_realm_id")
        
        new_sheet = st.text_input("Google Sheet ID", value=cfg.get("google_sheets", {}).get("sheet_id", "1ZVOs-WWFtfUfwrBwyMa18IFvrB_4YWZlACmFJ3ZGMV8"), key="cred_google_sheet_id")
        sa_file = st.file_uploader("Service Account JSON", type=["json"], key="cred_sa_file_uploader")
        
        if st.button("💾 Save All Credentials", key="cred_save_button"):
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
                st.cache_data.clear()
                st.rerun()
            else:
                st.warning("⚠️ No changes detected")
        
        st.markdown("---")
        st.markdown("### 🔑 Token Management")
        manual_access_token = st.text_input("QuickBooks Access Token", type="password", key="manual_access_token")
        manual_refresh_token = st.text_input("QuickBooks Refresh Token", type="password", key="manual_refresh_token")
        if st.button("💾 Save Tokens", key="save_tokens"):
            if manual_access_token and manual_refresh_token:
                cfg.update({
                    "access_token": manual_access_token,
                    "refresh_token": manual_refresh_token,
                    "expires_at": time.time() + 3600
                })
                st.session_state.tokens = {
                    "access_token": manual_access_token,
                    "refresh_token": manual_refresh_token,
                    "expires_at": time.time() + 3600
                }
                save_config(cfg)
                logger.info(f"Manually saved tokens: {st.session_state.tokens}")
                st.success("Tokens saved successfully! Please generate a report.")
                st.rerun()
            else:
                st.error("Please provide both access and refresh tokens")
                logger.warning("Manual token save failed: Missing tokens")
        
        if "tokens" in st.session_state:
            if st.button("👁️ Show Current Tokens", key="show_tokens"):
                st.text_area("Current Access Token", st.session_state.tokens.get("access_token", "None"), height=50)
                st.text_area("Current Refresh Token", st.session_state.tokens.get("refresh_token", "None"), height=50)
                logger.info("Displayed current tokens")
        
        if st.checkbox("🔍 Show Config Debug", False):
            st.write("### Config Status")
            st.json({
                "source": "🍪 Cookie-based",
                "quickbooks_configured": bool(cfg.get("qb_client_id")),
                "google_sheets_configured": bool(cfg.get("google_sheets", {}).get("sheet_id")),
                "service_account_json_set": bool(cfg.get("service_account_json")),
                "tokens_set": bool(cfg.get("access_token")),
                "version": cfg.get("version", "Unknown")
            })

# QBTokenManager (unchanged for brevity, assumed correct)
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        self._verify_credentials()
        self.auth_client = AuthClient(
            client_id=self.cfg.get("qb_client_id", ""),
            client_secret=self.cfg.get("qb_client_secret", ""),
            environment="production",
            redirect_uri=self.cfg.get("redirect_uri", "https://zugabooks.onrender.com/")
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
        # ... (rest unchanged)

    def _refresh_token(self):
        # ... (rest unchanged)
        pass

# Main Dashboard (unchanged for brevity, assumed correct)
def main_dashboard():
    st.title("📊 Financial Dashboard")
    # ... (rest unchanged)

# Main Execution
if __name__ == "__main__":
    credential_manager()
    token_manager = QBTokenManager()
    if st.sidebar.button("🔄 Reset QuickBooks Authorization", key="reset_qb_auth"):
        st.session_state.pop("tokens", None)
        cfg3 = load_config()
        for k in ("access_token", "refresh_token", "expires_at"):
            cfg3.pop(k, None)
        save_config(cfg3)
        st.success("Auth reset—please reauthorize")
        time.sleep(1)
        st.rerun()

    if st.session_state.tokens.get("access_token"):
        st.sidebar.success("✅ Connected to QuickBooks")
    else:
        st.sidebar.warning("🔴 Not connected to QuickBooks")

    if token_manager.handle_oauth():
        main_dashboard()
