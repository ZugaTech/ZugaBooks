import streamlit as st
import json
import os
import time
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
from typing import Dict, Any, Optional

.
# --- Streamlit App Configuration ---
st.set_page_config(
    page_title="ZugaBooks",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Credential Management UI ---
def credential_manager() -> None:
    """Sidebar UI for managing credentials"""
    with st.sidebar.expander("🔐 Credential Configuration", expanded=False):
        st.markdown("### 🔑 API Credentials")
        
        cfg = load_config()
        
        # QuickBooks Credentials
        new_client_id = st.text_input(
            "QuickBooks Client ID",
            type="password",
            value=cfg.get("qb_client_id", ""),
            help="From Intuit Developer Portal"
        )
        new_client_secret = st.text_input(
            "QuickBooks Client Secret", 
            type="password",
            value=cfg.get("qb_client_secret", ""),
        )
        new_realm_id = st.text_input(
            "QuickBooks Realm ID",
            type="password",
            value=cfg.get("realm_id", ""),
            help="Company ID from QuickBooks"
        )
        
        # Google Sheets Credentials
        new_sheet_id = st.text_input(
            "Google Sheet ID",
            type="password",
            value=cfg.get("sheet_id", ""),
            help="From your Google Sheet URL"
        )
        
        # Service Account JSON
        sa_file = st.file_uploader(
            "Google Service Account JSON",
            type=["json"],
            help="Download from Google Cloud Console"
        )
        
        if st.button("💾 Save All Credentials"):
            updated = False
            if new_client_id:
                cfg["qb_client_id"] = new_client_id
                updated = True
            if new_client_secret:
                cfg["qb_client_secret"] = new_client_secret
                updated = True
            if new_realm_id:
                cfg["realm_id"] = new_realm_id
                updated = True
            if new_sheet_id:
                cfg["sheet_id"] = new_sheet_id
                updated = True
            if sa_file:
                with open("service_account.json", "wb") as f:
                    f.write(sa_file.getbuffer())
                updated = True
            
            if updated:
                save_config(cfg)
                st.success("Credentials securely stored!")
            else:
                st.warning("No changes detected")

# --- QuickBooks OAuth Flow ---
class QBTokenManager:
    """Manage QuickBooks token lifecycle"""
    def __init__(self):
        self.cfg = load_config()
        self.auth_client = AuthClient(
            client_id=self.cfg.get("qb_client_id", ""),
            client_secret=self.cfg.get("qb_client_secret", ""),
            environment="production",
            redirect_uri="https://ZugaBooks.streamlit.app/callback",
            realm_id=self.cfg.get("realm_id", "")
        )
        
    def handle_oauth(self) -> bool:
        """Handle complete OAuth flow"""
        query_params = st.query_params
        if "code" in query_params:
            return self._exchange_code(query_params["code"])
        
        if "tokens" not in st.session_state:
            self._start_oauth_flow()
            return False
        return True
    
    def _start_oauth_flow(self) -> None:
        """Initiate authorization"""
        auth_url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        st.markdown(f"""
            <div style="text-align: center; margin: 20px;">
                <a href="{auth_url}" target="_blank">
                    <button style="
                        background: #2C8CFF;
                        color: white;
                        padding: 12px 24px;
                        border: none;
                        border-radius: 8px;
                        font-size: 16px;
                        cursor: pointer;
                    ">
                        🔗 Connect QuickBooks Account
                    </button>
                </a>
            </div>
        """, unsafe_allow_html=True)
    
    def _exchange_code(self, code: str) -> bool:
        """Exchange authorization code for tokens"""
        try:
            clean_code = code.split("&")[0].split("=")[-1]
            tokens = self.auth_client.get_bearer_token(clean_code)
            
            if not tokens:
                st.error("Authorization failed: Empty token response")
                return False
            
            st.session_state.tokens = {
                "access_token": tokens["accessToken"],
                "refresh_token": tokens["refreshToken"],
                "expires_at": time.time() + 3600
            }
            self.cfg["realm_id"] = tokens.get("realmId", self.cfg.get("realm_id", ""))
            save_config(self.cfg)
            st.rerun()
            return True
            
        except Exception as e:
            st.error(f"Authorization failed: {str(e)}")
            return False

# --- Main Application Interface ---
def main_dashboard() -> None:
    """Main reporting interface"""
    st.title("📊 Financial Dashboard")
    
    # Date selection
    today = date.today()
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", today - timedelta(days=30))
    with col2:
        end_date = st.date_input("End Date", today)
    
    if start_date > end_date:
        st.error("⚠️ End date must be after start date")
        st.stop()
    
    # Report selection
    report_type = st.selectbox(
        "Select Report Type",
        ["ProfitAndLoss", "BalanceSheet", "TransactionList"]
    )
    
    # Data fetching
    if st.button("🔄 Generate Report"):
        with st.spinner("📡 Connecting to QuickBooks..."):
            try:
                qb_client = QuickBooks(
                    auth_client=token_manager.auth_client,
                    company_id=token_manager.cfg.get("realm_id", ""),
                    refresh_token=st.session_state.tokens["refresh_token"]
                )
                
                # Fetch report data
                params = {
                    "start_date": start_date.strftime("%Y-%m-%d"),
                    "end_date": end_date.strftime("%Y-%m-%d")
                }
                report = qb_client.get_report(report_name=report_type, params=params)
                
                # Process and display data
                df = process_report_data(report, report_type)
                display_report(df)
                export_interface(df, report_type)
                
            except Exception as e:
                st.error(f"""
                    ❌ Report generation failed: {str(e)}
                    **Troubleshooting Tips:**
                    1. Verify QuickBooks connection
                    2. Check date range contains data
                    3. Ensure proper user permissions
                """)

def process_report_data(report: Dict, report_type: str) -> pd.DataFrame:
    """Process QuickBooks API response"""
    # Add your data processing logic here
    return pd.DataFrame()  # Placeholder

def display_report(df: pd.DataFrame) -> None:
    """Interactive data display"""
    with st.expander("📈 View Full Report Data", expanded=True):
        st.dataframe(
            df.style.highlight_max(axis=0, color="#90EE90"),
            use_container_width=True,
            height=600
        )

def export_interface(df: pd.DataFrame, report_type: str) -> None:
    """Data export controls"""
    st.subheader("🚀 Export Options")
    
    # Google Sheets Export
    if st.button("📤 Update Google Sheets"):
        with st.spinner("Syncing with Google Sheets..."):
            try:
                scope = [
                    "https://spreadsheets.google.com/feeds",
                    "https://www.googleapis.com/auth/drive"
                ]
                creds = ServiceAccountCredentials.from_json_keyfile_name(
                    "service_account.json", scope
                )
                gc = gspread.authorize(creds)
                
                sheet = gc.open_by_key(load_config().get("sheet_id", ""))
                worksheet = sheet.worksheet(report_type)
                worksheet.update([df.columns.values.tolist()] + df.values.tolist())
                
                st.success("✅ Google Sheets updated successfully!")
            except Exception as e:
                st.error(f"Google Sheets error: {str(e)}")
    
    # CSV Download
    st.download_button(
        label="💾 Download CSV",
        data=df.to_csv(index=False),
        file_name=f"{report_type}_{date.today()}.csv",
        mime="text/csv"
    )

# --- Main Execution Flow ---
if __name__ == "__main__":
    credential_manager()
    token_manager = QBTokenManager()
    if token_manager.handle_oauth():
        main_dashboard()