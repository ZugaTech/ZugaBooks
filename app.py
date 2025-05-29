import streamlit as st
import os
import time
import json
from datetime import date, timedelta
from intuitlib.client import AuthClient
from quickbooks import QuickBooks
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pandas as pd
from intuitlib.enums import Scopes
from cryptography.fernet import Fernet
from utils import get_report_dataframe, apply_custom_categories
from config import load_config, save_config
from typing import Dict, Any
from intuitlib.exceptions import AuthClientError  # For specific error handling


# --- Streamlit App Config ---
st.set_page_config(
    page_title="ZugaBooks",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Load APP_PASSWORD securely ---
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
if not APP_PASSWORD:
    try:
        APP_PASSWORD = st.secrets["APP_PASSWORD"]
    except Exception:
        APP_PASSWORD = ""

# --- PASSWORD PROTECTION ---
def password_gate():
    st.sidebar.title("🔐 Login Required")
    pw = st.sidebar.text_input("Enter Access Password", type="password", key="password_gate")
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if pw and APP_PASSWORD and pw == APP_PASSWORD:
        st.session_state.authenticated = True
        st.sidebar.success("✅ Access granted")
    elif pw:
        st.sidebar.error("❌ Incorrect password")

    if not st.session_state.authenticated:
        st.stop()

password_gate()

# --- Credential Manager Sidebar ---
def credential_manager():
    with st.sidebar.expander("🔐 Credential Configuration", expanded=False):
        st.markdown("### 🔑 API & OAuth Credentials")
        cfg = load_config()

        # QuickBooks fields - FIXED KEYS
        new_client_id = st.text_input(
            "QuickBooks Client ID",
            type="password",
            value=cfg.get("qb_client_id",""),
            help="From Intuit Developer Portal",
            key="qb_client_id_input"  # FIXED: Unique key
        )
        new_client_secret = st.text_input(
            "QuickBooks Client Secret",
            type="password",
            value=cfg.get("qb_client_secret",""),
            key="qb_client_secret_input"  # FIXED: Unique key
        )
        new_redirect_uri = st.text_input(
            "QuickBooks Redirect URI",
            value=cfg.get("redirect_uri",""),
            help="Must exactly match Intuit app settings",
            key="qb_redirect_uri_input"  # FIXED: Unique key
        )
        new_realm_id = st.text_input(
            "QuickBooks Realm ID",
            type="password",
            value=cfg.get("realm_id",""),
            help="Your QuickBooks Company ID",
            key="qb_realm_id_input"  # FIXED: Unique key
        )

        # Google Sheets
        new_sheet_id = st.text_input(
            "Google Sheet ID",
            type="password",
            value=cfg.get("sheet_id",""),
            help="From your Google Sheets URL",
            key="sheet_id_input"  # FIXED: Unique key
        )

        # Service account JSON
        sa_file = st.file_uploader(
            "Google Service Account JSON",
            type=["json"],
            help="Download from Google Cloud Console",
            key="sa_file_uploader"  # FIXED: Unique key
        )

        if st.button("💾 Save All Credentials", key="save_credentials"):
            updated = False
            if new_client_id and new_client_id != cfg.get("qb_client_id"):
                cfg["qb_client_id"] = new_client_id; updated = True
            if new_client_secret and new_client_secret != cfg.get("qb_client_secret"):
                cfg["qb_client_secret"] = new_client_secret; updated = True
            if new_redirect_uri and new_redirect_uri != cfg.get("redirect_uri"):
                cfg["redirect_uri"] = new_redirect_uri; updated = True
            if new_realm_id and new_realm_id != cfg.get("realm_id"):
                cfg["realm_id"] = new_realm_id; updated = True
            if new_sheet_id and new_sheet_id != cfg.get("sheet_id"):
                cfg["sheet_id"] = new_sheet_id; updated = True
            if sa_file:
                with open("service_account.json","wb") as f:
                    f.write(sa_file.getbuffer())
                updated = True
            if updated:
                save_config(cfg)
                st.success("Credentials saved securely!")
            else:
                st.warning("No changes detected")

# --- QuickBooks Token Manager ---
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        # Validate minimum required config
        if not all([self.cfg.get("qb_client_id"), self.cfg.get("qb_client_secret"), self.cfg.get("redirect_uri")]):
            st.error("❌ Missing required QuickBooks credentials in config")
            st.stop()
            
        self.auth_client = AuthClient(
            client_id=self.cfg.get("qb_client_id"),
            client_secret=self.cfg.get("qb_client_secret"),
            environment="production",
            redirect_uri=self.cfg.get("redirect_uri")
        )

    def handle_oauth(self) -> bool:
        # Initialize tokens from config if they exist
        if "tokens" not in st.session_state:
            st.session_state.tokens = {
                "access_token": self.cfg.get("access_token"),
                "refresh_token": self.cfg.get("refresh_token"),
                "expires_at": self.cfg.get("expires_at", 0)
            } if self.cfg.get("access_token") else {}

        # 1. Check for existing valid tokens
        if st.session_state.tokens.get("access_token"):
            # Check if token needs refresh
            if time.time() > st.session_state.tokens.get("expires_at", 0):
                try:
                    self.auth_client.realm_id = self.cfg.get("realm_id")
                    self.auth_client.refresh_token = st.session_state.tokens["refresh_token"]
                    new_tokens = self.auth_client.refresh()
                    
                    if not new_tokens or not hasattr(new_tokens, 'access_token'):
                        raise ValueError("Invalid token response from QuickBooks")
                    
                    # Update tokens
                    st.session_state.tokens = {
                        "access_token": new_tokens.access_token,
                        "refresh_token": new_tokens.refresh_token,
                        "expires_at": time.time() + new_tokens.expires_in
                    }
                    # Persist to config
                    self.cfg.update({
                        "access_token": new_tokens.access_token,
                        "refresh_token": new_tokens.refresh_token,
                        "expires_at": st.session_state.tokens["expires_at"]
                    })
                    save_config(self.cfg)
                    st.rerun()
                except Exception as e:
                    st.error(f"🔴 Token refresh failed: {str(e)}")
                    st.session_state.pop("tokens", None)
                    return False
            return True

        # 2. No valid tokens - start OAuth flow
        st.markdown("## QuickBooks Authorization Required")
        auth_url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        st.markdown(f"[Click here to authorize with QuickBooks]({auth_url})")

        code = st.text_input("After authorizing, paste the authorization code here:", key="qb_auth_code")
        if not code:
            st.warning("Please complete the OAuth flow to continue")
            st.stop()

        # 3. Exchange authorization code for tokens
        try:
            # Clean the code (remove URL parameters if pasted from redirect)
            clean_code = code.split("code=")[-1].split("&")[0].strip()
            
            # Get bearer token
            token_response = self.auth_client.get_bearer_token(clean_code)
            
            # Validate token response
            if not token_response or not hasattr(token_response, 'access_token'):
                raise ValueError("Invalid token response from QuickBooks API")
            
            # Store tokens
            st.session_state.tokens = {
                "access_token": token_response.access_token,
                "refresh_token": token_response.refresh_token,
                "expires_at": time.time() + token_response.expires_in
            }
            
            # Update realm ID if not set
            if not self.cfg.get("realm_id") and hasattr(self.auth_client, 'realm_id'):
                self.cfg["realm_id"] = self.auth_client.realm_id
                
            # Persist tokens
            self.cfg.update({
                "access_token": token_response.access_token,
                "refresh_token": token_response.refresh_token,
                "expires_at": st.session_state.tokens["expires_at"]
            })
            save_config(self.cfg)
            
            st.success("✅ Successfully connected to QuickBooks!")
            time.sleep(1.5)
            st.rerun()
            
        except AuthClientError as e:
            st.error(f"🔴 QuickBooks API Error: {e.status_code} - {e.content}")
            st.stop()
        except Exception as e:
            st.error(f"🔴 Authorization failed: {str(e)}")
            st.stop()
# --- Main Dashboard ---
def main_dashboard():
    st.title("📊 Financial Dashboard")
    today = date.today()
    c1, c2 = st.columns(2)
    with c1:
        start = st.date_input("Start Date", today - timedelta(days=30), key="start_date")
    with c2:
        end = st.date_input("End Date", today, key="end_date")
    if start > end:
        st.error("End date must be after start date"); st.stop()

    report_type = st.selectbox(
        "Select Report Type",
        ["ProfitAndLoss","BalanceSheet","TransactionList"],
        key="report_type_select"
    )

    # CSV custom categories
    mapping_file = st.sidebar.file_uploader(
        "Upload CSV mapping: Vendor → Category", type=["csv"], key="mapping_file_uploader"
    )
    cat_map = {}
    if mapping_file:
        df_map = pd.read_csv(mapping_file)
        if {'Vendor','Category'}.issubset(df_map.columns):
            cat_map = dict(zip(df_map['Vendor'], df_map['Category']))
        else:
            st.sidebar.warning("CSV needs 'Vendor' & 'Category' columns.")

    if st.button("🔄 Generate Report", key="generate_report_btn"):
        with st.spinner("📡 Fetching report..."):
            try:
                qb = QuickBooks(
                    auth_client=token_manager.auth_client,
                    company_id=token_manager.cfg.get("realm_id",""),
                    refresh_token=st.session_state.tokens["refresh_token"]
                )
                params = {
                    "start_date": start.strftime("%Y-%m-%d"),
                    "end_date": end.strftime("%Y-%m-%d")
                }
                report = qb.get_report(report_name=report_type, params=params)
                df = get_report_dataframe(report.get('Rows',{}).get('Row',[]), report_type)
                if cat_map:
                    df = apply_custom_categories(df, mapping_file)
                st.subheader(f"{report_type} Report")
                st.dataframe(df, use_container_width=True)

                # Export to Google Sheets
                if st.button("📤 Export to Google Sheets", key="export_sheets_btn"):
                    scope = [
                        "https://spreadsheets.google.com/feeds",
                        "https://www.googleapis.com/auth/drive"
                    ]
                    creds = ServiceAccountCredentials.from_json_keyfile_name(
                        "service_account.json", scope
                    )
                    gc = gspread.authorize(creds)
                    sheet = gc.open_by_key(load_config().get("sheet_id",""))
                    try:
                        ws = sheet.worksheet(report_type)
                    except gspread.exceptions.WorksheetNotFound:
                        ws = sheet.add_worksheet(
                            title=report_type,
                            rows=len(df)+1,
                            cols=len(df.columns)
                        )
                    ws.clear()
                    ws.update('A1',
                              [df.columns.tolist()] + df.values.tolist(),
                              value_input_option='USER_ENTERED')
                    st.success("✅ Exported to Google Sheets")

                # Download CSV
                st.download_button(
                    "💾 Download CSV",
                    data=df.to_csv(index=False),
                    file_name=f"{report_type}_{date.today()}.csv",
                    mime="text/csv",
                    key="download_csv_btn"
                )

            except Exception as e:
                st.error(f"Failed to fetch or export report: {e}")

# --- Run App ---
if __name__ == "__main__":
    credential_manager()
    token_manager = QBTokenManager()
    if token_manager.handle_oauth():
        main_dashboard()