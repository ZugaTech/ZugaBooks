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

        # QuickBooks fields
        new_client_id = st.text_input(
            "QuickBooks Client ID",
            type="password",
            value=cfg.get("qb_client_id",""),
            help="From Intuit Developer Portal",
            key="qb_client_id"
        )
        new_client_secret = st.text_input(
            "QuickBooks Client Secret",
            type="password",
            value=cfg.get("qb_client_secret",""),
            key="qb_client_secret"
        )
        new_redirect_uri = st.text_input(
            "QuickBooks Redirect URI",
            value=cfg.get("redirect_uri",""),
            help="Must exactly match Intuit app settings",
            key="qb_redirect_uri"
        )
        new_realm_id = st.text_input(
            "QuickBooks Realm ID",
            type="password",
            value=cfg.get("realm_id",""),
            help="Your QuickBooks Company ID",
            key="qb_realm_id"
        )

        # Google Sheets
        new_sheet_id = st.text_input(
            "Google Sheet ID",
            type="password",
            value=cfg.get("sheet_id",""),
            help="From your Google Sheets URL",
            key="sheet_id"
        )

        # Service account JSON
        sa_file = st.file_uploader(
            "Google Service Account JSON",
            type=["json"],
            help="Download from Google Cloud Console",
            key="sa_file"
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

credential_manager()

# --- QuickBooks Token Manager ---
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        # Must have redirect_uri set
        self.auth_client = AuthClient(
            client_id=self.cfg.get("qb_client_id",""),
            client_secret=self.cfg.get("qb_client_secret",""),
            environment="production",
            redirect_uri=self.cfg.get("redirect_uri",""),
            realm_id=self.cfg.get("realm_id","")
        )

    def handle_oauth(self) -> bool:
        tokens = st.session_state.get("tokens", {})

        # 1) Auto-refresh if expired
        if tokens:
            if time.time() > tokens.get("expires_at",0):
                try:
                    new_tokens = self.auth_client.refresh(tokens["refresh_token"])
                    st.session_state.tokens = {
                        "access_token": new_tokens["accessToken"],
                        "refresh_token": new_tokens["refreshToken"],
                        "expires_at": time.time() + new_tokens.get("expires_in",3600)
                    }
                    # Save updated tokens
                    self.cfg.update({
                        "access_token": new_tokens["accessToken"],
                        "refresh_token": new_tokens["refreshToken"]
                    })
                    save_config(self.cfg)
                    return True
                except Exception:
                    st.session_state.pop("tokens")
                    st.warning("🔄 Session expired. Please re-authorize.")
            else:
                return True

        # 2) No valid tokens → Prompt OAuth
        url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        st.markdown("### 🔗 Connect to QuickBooks")
        st.markdown(f"[Authorize QuickBooks]({url})", unsafe_allow_html=True)

        code = st.text_input("Paste the 'code' from QuickBooks URL here", key="oauth_code")
        if not code:
            st.stop()

        # 3) Exchange code for tokens
        try:
            clean = code.strip().split("&")[0].split("=")[-1]
            new_tokens = self.auth_client.get_bearer_token(clean)
            st.session_state.tokens = {
                "access_token": new_tokens["accessToken"],
                "refresh_token": new_tokens["refreshToken"],
                "expires_at": time.time() + new_tokens.get("expires_in",3600)
            }
            self.cfg.update({
                "realm_id": new_tokens.get("realmId", self.cfg.get("realm_id","")),
                "access_token": new_tokens["accessToken"],
                "refresh_token": new_tokens["refreshToken"]
            })
            save_config(self.cfg)
            st.success("✅ QuickBooks connected!")
            st.rerun()
        except Exception as e:
            st.error(f"Authorization failed: {e}")
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
        key="report_type"
    )

    # CSV custom categories
    mapping_file = st.sidebar.file_uploader(
        "Upload CSV mapping: Vendor → Category", type=["csv"], key="mapping_file"
    )
    cat_map = {}
    if mapping_file:
        df_map = pd.read_csv(mapping_file)
        if {'Vendor','Category'}.issubset(df_map.columns):
            cat_map = dict(zip(df_map['Vendor'], df_map['Category']))
        else:
            st.sidebar.warning("CSV needs 'Vendor' & 'Category' columns.")

    if st.button("🔄 Generate Report", key="generate_report"):
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
                if st.button("📤 Export to Google Sheets", key="export_sheets"):
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
                    key="download_csv"
                )

            except Exception as e:
                st.error(f"Failed to fetch or export report: {e}")

# --- Run App ---
if __name__ == "__main__":
    credential_manager()
    token_manager = QBTokenManager()
    if token_manager.handle_oauth():
        main_dashboard()
